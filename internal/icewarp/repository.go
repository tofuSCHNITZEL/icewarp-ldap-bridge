package icewarp

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
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

func (r *Repository) email(username string) string { return username + "@" + r.domain }

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

func (r *Repository) List(ctx context.Context, q users.Query) ([]users.User, error) {
	ctx, cancel := context.WithTimeout(ctx, repoOpTimeout)
	defer cancel()

	// Exact-username lookup is a single read.
	if q.Username != "" {
		u, err := r.fetch(ctx, q.Username)
		if errors.Is(err, users.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return []users.User{u}, nil
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
			Fileas:   a.Name, // u_name; overridden by the card's fileas below
			Email:    a.Email,
			Disabled: a.Disabled(),
		})
	}

	// The list response omits the structured name, so it must be read from each
	// account's a_vcard card — one call per user (an N+1). "Sync all users"
	// needs these names, so we can't skip them; fetch the cards concurrently
	// (bounded) instead to keep a large sync from serializing N round-trips.
	r.fillNames(ctx, out)
	return out, nil
}

// listCardConcurrency bounds how many per-user card reads run at once in List.
const listCardConcurrency = 8

// fillNames populates the structured-name fields on each user from its a_vcard
// card, concurrently. A per-user read error leaves that user's name fields
// empty (same lenient behaviour as a single failed lookup).
func (r *Repository) fillNames(ctx context.Context, list []users.User) {
	sem := make(chan struct{}, listCardConcurrency)
	var wg sync.WaitGroup
	for i := range list {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(u *users.User) {
			defer wg.Done()
			defer func() { <-sem }()
			card, err := r.client.GetAccountCard(ctx, u.Email)
			if err != nil {
				r.logger.Warn("fillNames: card read failed, name fields will be empty", "email", u.Email, "err", err)
				return
			}
			cardToUser(u, card)
			u.Fileas = cardDisplayName(card, u.Fileas)
		}(&list[i])
	}
	wg.Wait()
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
	if u.Fileas != "" {
		set(cardFileas, u.Fileas)
	}
	if cardChanged {
		if err := r.client.SetAccountCard(ctx, email, card); err != nil {
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
