package icewarp

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

// Per-operation timeouts. Bind is generous because bad credentials are tarpitted
// ~25-30s server-side (see docs/icewarp-api.md).
const (
	repoBindTimeout = 90 * time.Second
	repoOpTimeout   = 30 * time.Second
)

// accountAPI is the slice of the IceWarp client the repository depends on. The
// repository takes it (satisfied by *Client) rather than the concrete type, so
// tests can inject a mock and verify how the client is driven.
type accountAPI interface {
	GetAuthToken(ctx context.Context, email, password string) (*AuthToken, error)
	GetAccountProperties(ctx context.Context, email string, props ...string) (Properties, error)
	GetAccountCard(ctx context.Context, email string) (AccountCard, error)
	ListAccounts(ctx context.Context, domain, nameMask string, offset, count int) ([]Account, int, error)
	CreateAccount(ctx context.Context, domain string, props ...WriteProperty) error
	SetAccountPassword(ctx context.Context, email, password string, ignorePolicy bool) error
	SetAccountProperties(ctx context.Context, email string, props ...WriteProperty) error
	SetAccountCard(ctx context.Context, email string, card AccountCard) error
	DeleteAccounts(ctx context.Context, domain string, emails ...string) error
}

var _ accountAPI = (*Client)(nil)

// Repository is a users.Repository backed by the IceWarp admin RPC API. It maps
// a username to the account "<username>@<domain>" and keeps no LDAP knowledge.
type Repository struct {
	client accountAPI
	domain string
	logger *slog.Logger
}

var _ users.Repository = (*Repository)(nil)

// NewRepository returns an IceWarp-backed user repository for a mail domain.
func NewRepository(client *Client, domain string, logger *slog.Logger) *Repository {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Repository{client: client, domain: domain, logger: logger}
}

// email qualifies a mailbox local part with the domain. It is idempotent: a
// value that is already a full address (contains "@") is returned unchanged, so
// a domain-qualified username never gets the domain appended twice.
func (r *Repository) email(username string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + "@" + r.domain
}

func (r *Repository) Authenticate(ctx context.Context, username, password string) error {
	ctx, cancel := context.WithTimeout(ctx, repoBindTimeout)
	defer cancel()

	if _, err := r.client.GetAuthToken(ctx, r.email(username), password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountDisabled) {
			return users.ErrInvalidCredentials
		}
		return err
	}
	return nil
}

func (r *Repository) Get(ctx context.Context, username string) (users.User, error) {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()
	return r.fetch(ctx, username)
}

// List returns lightweight candidate users — identity and the cheap fields from
// getaccountsinfolist (display name, disabled), but NOT the structured name,
// which lives in each account's a_vcard card. The caller enriches only the
// entries it actually returns (via Get), so a single-user lookup doesn't read
// every account's card. See users.Query: the result is a hint, not exact.
func (r *Repository) List(ctx context.Context, q users.Query) ([]users.User, error) {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()

	// A targeted username needs no enumeration: return the single candidate
	// without a round-trip and let the caller's Get resolve existence + names.
	if q.Username != "" {
		return []users.User{{Username: q.Username, Email: r.email(q.Username)}}, nil
	}

	mask := "*"
	if q.UsernamePrefix != "" {
		mask = q.UsernamePrefix + "*"
	}
	accounts, err := r.listAll(ctx, mask)
	if err != nil {
		return nil, err
	}

	out := make([]users.User, 0, len(accounts))
	for _, a := range accounts {
		if a.AccountType != 0 { // users only
			continue
		}
		out = append(out, users.User{
			Username: localPart(a.Email),
			Fileas:   a.Name, // u_name display name; the card's fileas wins after enrichment
			Email:    a.Email,
			Disabled: a.Disabled(),
		})
	}
	return out, nil
}

func (r *Repository) Create(ctx context.Context, u users.User) error {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()

	props := []WriteProperty{
		StringProperty("u_mailbox", u.Username),
		StringProperty("u_type", "0"),
	}
	if u.Fileas != "" {
		props = append(props, StringProperty("u_name", u.Fileas))
	}
	if err := r.client.CreateAccount(ctx, r.domain, props...); err != nil {
		return mapRepoError(err)
	}
	// The structured name lives in the a_vcard card; set it after the account
	// exists (read-modify-write so we don't clobber server-initialised fields).
	if hasCardName(u) {
		card, err := r.client.GetAccountCard(ctx, r.email(u.Username))
		if err != nil {
			return mapRepoError(err)
		}
		setIfNonEmpty(&card, cardFirstname, u.Firstname)
		setIfNonEmpty(&card, cardLastname, u.Lastname)
		setIfNonEmpty(&card, cardMiddlename, u.Middlename)
		setIfNonEmpty(&card, cardNickname, u.Nickname)
		setIfNonEmpty(&card, cardSuffix, u.Suffix)
		setIfNonEmpty(&card, cardTitle, u.Title)
		setIfNonEmpty(&card, cardFileas, u.Fileas)
		if err := r.client.SetAccountCard(ctx, r.email(u.Username), card); err != nil {
			return mapRepoError(err)
		}
	}
	if u.Password != "" {
		if err := r.client.SetAccountPassword(ctx, r.email(u.Username), u.Password, true); err != nil {
			return mapRepoError(err)
		}
	}
	if u.Disabled {
		if err := r.client.SetAccountProperties(ctx, r.email(u.Username), StringProperty("u_accountdisabled", "1")); err != nil {
			return mapRepoError(err)
		}
	}
	return nil
}

func (r *Repository) Update(ctx context.Context, u users.User) error {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()

	email := r.email(u.Username)

	// Names live in the a_vcard card. Read it, change only the fields we map,
	// and write the whole card back so unmanaged fields (nickname, addresses,
	// …) survive — IceWarp's own UI does the same.
	card, err := r.client.GetAccountCard(ctx, email)
	if err != nil {
		return mapRepoError(err)
	}
	cardChanged := false
	set := func(key, val string) {
		if val != card.Get(key) {
			card.Set(key, val)
			cardChanged = true
		}
	}
	set(cardFirstname, u.Firstname)
	set(cardLastname, u.Lastname)
	set(cardMiddlename, u.Middlename)
	set(cardNickname, u.Nickname)
	set(cardSuffix, u.Suffix)
	set(cardTitle, u.Title)
	// fileas is only written when non-empty so it isn't blanked when the caller
	// doesn't carry a display name.
	fileasChanged := false
	if u.Fileas != "" && u.Fileas != card.Get(cardFileas) {
		fileasChanged = true
		set(cardFileas, u.Fileas)
	}
	if cardChanged {
		if err := r.client.SetAccountCard(ctx, email, card); err != nil {
			return mapRepoError(err)
		}
	}

	// The card's fileas is the bridge's display name, but IceWarp shows u_name as
	// the account "Display name" (the <name> in account listings and the admin
	// UI). Create writes both; keep them in sync on update too, otherwise a
	// display-name change lands in the card but is invisible in IceWarp.
	if fileasChanged {
		if err := r.client.SetAccountProperties(ctx, email, StringProperty("u_name", u.Fileas)); err != nil {
			return mapRepoError(err)
		}
	}

	// The disabled flag is a plain account property, independent of the card.
	props, err := r.client.GetAccountProperties(ctx, email, "u_accountdisabled")
	if err != nil {
		return mapRepoError(err)
	}
	if (props["u_accountdisabled"].Val == "1") != u.Disabled {
		disabled := "0"
		if u.Disabled {
			disabled = "1"
		}
		if err := r.client.SetAccountProperties(ctx, email, StringProperty("u_accountdisabled", disabled)); err != nil {
			return mapRepoError(err)
		}
	}
	return nil
}

func (r *Repository) SetPassword(ctx context.Context, username, password string) error {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()
	if err := r.client.SetAccountPassword(ctx, r.email(username), password, true); err != nil {
		return mapRepoError(err)
	}
	return nil
}

func (r *Repository) Delete(ctx context.Context, username string) error {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()
	if err := r.client.DeleteAccounts(ctx, r.domain, r.email(username)); err != nil {
		return mapRepoError(err)
	}
	return nil
}

// fetch reads a user's properties without applying its own timeout (the caller
// sets one). The structured name lives in the a_vcard card (what the IceWarp
// admin UI edits); u_name is only a fallback display name.
func (r *Repository) fetch(ctx context.Context, username string) (users.User, error) {
	email := r.email(username)
	// One round-trip for the card (structured name) plus the scalar props.
	props, err := r.client.GetAccountProperties(ctx, email, "a_vcard", "u_name", "u_accountdisabled")
	if err != nil {
		return users.User{}, mapRepoError(err)
	}
	card := props["a_vcard"].Card
	u := users.User{
		Username: username,
		Fileas:   cardDisplayName(card, props["u_name"].Val),
		Email:    email,
		Disabled: props["u_accountdisabled"].Val == "1",
	}
	cardToUser(&u, card)
	return u, nil
}

// maxListAccounts caps how many accounts listAll will accumulate, bounding
// memory and guarding against a server that misreports a huge total or ignores
// the offset (which would otherwise loop forever). It is well above any
// realistic single-domain user count; hitting it is logged and truncates.
const maxListAccounts = 100_000

func (r *Repository) listAll(ctx context.Context, mask string) ([]Account, error) {
	const pageSize = 250
	var all []Account
	for offset := 0; ; {
		page, total, err := r.client.ListAccounts(ctx, r.domain, mask, offset, pageSize)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		offset += len(page)
		if len(page) == 0 || offset >= total {
			return all, nil
		}
		if len(all) >= maxListAccounts {
			r.logger.Warn("listAll: account cap reached, truncating result",
				"cap", maxListAccounts, "domain", r.domain, "mask", mask, "total", total)
			return all, nil
		}
	}
}

func localPart(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return local
}

// a_vcard (TAccountCard) field names the bridge maps onto LDAP attributes:
// firstname -> givenName, lastname -> sn, middlename -> initials,
// nickname -> displayName, suffix -> generationQualifier,
// title -> personalTitle, fileas ("Display as") -> cn.
const (
	cardFirstname  = "firstname"
	cardLastname   = "lastname"
	cardMiddlename = "middlename"
	cardNickname   = "nickname"
	cardSuffix     = "suffix"
	cardTitle      = "title"
	cardFileas     = "fileas"
)

// cardToUser copies the card's structured-name fields onto u. Fileas is
// handled separately by the caller (fileas, with a fallback).
func cardToUser(u *users.User, card AccountCard) {
	u.Firstname = card.Get(cardFirstname)
	u.Lastname = card.Get(cardLastname)
	u.Middlename = card.Get(cardMiddlename)
	u.Nickname = card.Get(cardNickname)
	u.Suffix = card.Get(cardSuffix)
	u.Title = card.Get(cardTitle)
}

// hasCardName reports whether u carries any name field that lives in the card.
func hasCardName(u users.User) bool {
	return u.Firstname != "" || u.Lastname != "" || u.Middlename != "" ||
		u.Nickname != "" || u.Suffix != "" || u.Title != "" || u.Fileas != ""
}

// setIfNonEmpty sets a card field only when val is non-empty, so a create never
// blanks a server-initialised field the caller didn't provide.
func setIfNonEmpty(card *AccountCard, key, val string) {
	if val != "" {
		card.Set(key, val)
	}
}

// cardDisplayName picks the account's display name: the card's "Display as"
// (fileas) field, falling back to u_name when it is empty.
func cardDisplayName(card AccountCard, uName string) string {
	if fa := card.Get(cardFileas); fa != "" {
		return fa
	}
	return uName
}

// mapRepoError translates IceWarp API errors into users sentinel errors.
func mapRepoError(err error) error {
	var ae *APIError
	if errors.As(err, &ae) && ae.UID == "account_invalid" {
		return users.ErrNotFound
	}
	return err
}
