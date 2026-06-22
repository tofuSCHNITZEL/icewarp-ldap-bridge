package icewarp

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

// These tests verify the repository's mapping logic by injecting a mock client
// and asserting how it is driven — not by going over HTTP (that is the client's
// own concern, covered by its e2e test).

// mockClient records the calls the repository makes and returns canned results.
type mockClient struct {
	authEmail, authPassword string
	authResult              *AuthToken
	authErr                 error

	getProps Properties
	getErr   error

	listMask     string
	listAccounts []Account
	listTotal    int

	createDomain string
	createProps  []WriteProperty

	pwEmail, pwPassword string
	pwIgnore            bool

	setEmail string
	setProps []WriteProperty

	getCard    AccountCard
	getCardErr error

	setCardEmail string
	setCard      AccountCard

	deleteDomain string
	deleteEmails []string
}

func (m *mockClient) GetAuthToken(_ context.Context, email, password string) (*AuthToken, error) {
	m.authEmail, m.authPassword = email, password
	if m.authErr != nil {
		return nil, m.authErr
	}
	if m.authResult != nil {
		return m.authResult, nil
	}
	return &AuthToken{Token: "ok"}, nil
}

func (m *mockClient) GetAccountProperties(_ context.Context, _ string, _ ...string) (Properties, error) {
	return m.getProps, m.getErr
}

func (m *mockClient) ListAccounts(_ context.Context, _, nameMask string, _, _ int) ([]Account, int, error) {
	m.listMask = nameMask
	return m.listAccounts, m.listTotal, nil
}

func (m *mockClient) CreateAccount(_ context.Context, domain string, props ...WriteProperty) error {
	m.createDomain, m.createProps = domain, props
	return nil
}

func (m *mockClient) SetAccountPassword(_ context.Context, email, password string, ignorePolicy bool) error {
	m.pwEmail, m.pwPassword, m.pwIgnore = email, password, ignorePolicy
	return nil
}

func (m *mockClient) SetAccountProperties(_ context.Context, email string, props ...WriteProperty) error {
	m.setEmail, m.setProps = email, props
	return nil
}

func (m *mockClient) GetAccountCard(_ context.Context, _ string) (AccountCard, error) {
	return m.getCard, m.getCardErr
}

func (m *mockClient) SetAccountCard(_ context.Context, email string, card AccountCard) error {
	m.setCardEmail, m.setCard = email, card
	return nil
}

func (m *mockClient) DeleteAccounts(_ context.Context, domain string, emails ...string) error {
	m.deleteDomain, m.deleteEmails = domain, emails
	return nil
}

func newRepo(client accountAPI) *Repository {
	return &Repository{client: client, domain: "icewarp.local", logger: slog.New(slog.DiscardHandler)}
}

func TestRepositoryCreate(t *testing.T) {
	mock := &mockClient{}
	err := newRepo(mock).Create(context.Background(), users.User{
		Username:  "jdoe",
		Fileas:    "John Doe",
		Firstname: "John",
		Lastname:  "Doe",
		Password:  "pw",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if mock.createDomain != "icewarp.local" {
		t.Errorf("create domain: got %q", mock.createDomain)
	}
	assertStringProp(t, mock.createProps, "u_mailbox", "jdoe")
	assertStringProp(t, mock.createProps, "u_type", "0")
	assertStringProp(t, mock.createProps, "u_name", "John Doe")

	// The structured name is written to the a_vcard card, not a_name.
	if mock.setCardEmail != "jdoe@icewarp.local" {
		t.Errorf("card write email: got %q", mock.setCardEmail)
	}
	if g, s, f := mock.setCard.Get("firstname"), mock.setCard.Get("lastname"), mock.setCard.Get("fileas"); g != "John" || s != "Doe" || f != "John Doe" {
		t.Errorf("card name: firstname=%q lastname=%q fileas=%q", g, s, f)
	}

	// Password goes through the dedicated command, with policy bypassed.
	if mock.pwEmail != "jdoe@icewarp.local" || mock.pwPassword != "pw" || !mock.pwIgnore {
		t.Errorf("setpassword: got %q %q ignore=%v", mock.pwEmail, mock.pwPassword, mock.pwIgnore)
	}
}

func TestRepositoryCreateWithoutPassword(t *testing.T) {
	mock := &mockClient{}
	if err := newRepo(mock).Create(context.Background(), users.User{Username: "jdoe"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if mock.pwEmail != "" {
		t.Errorf("setpassword should not be called without a password, got %q", mock.pwEmail)
	}
}

func TestRepositoryGet(t *testing.T) {
	// fetch reads the card and the scalar props in one getaccountproperties
	// call; fileas ("Display as") is the display name, falling back to u_name.
	mock := &mockClient{
		getProps: Properties{
			"a_vcard": {Card: makeCard(
				"firstname", "John", "lastname", "Doe", "fileas", "Johnny D",
				"middlename", "Bob", "nickname", "JD", "suffix", "II", "title", "Herr")},
			"u_name":            {Val: "John Doe"},
			"u_accountdisabled": {Val: "0"},
		},
	}

	u, err := newRepo(mock).Get(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Username != "jdoe" || u.Fileas != "Johnny D" || u.Firstname != "John" ||
		u.Lastname != "Doe" || u.Email != "jdoe@icewarp.local" || u.Disabled {
		t.Fatalf("get: unexpected user %+v", u)
	}
	if u.Middlename != "Bob" || u.Nickname != "JD" || u.Suffix != "II" || u.Title != "Herr" {
		t.Fatalf("get: extra name fields not read: %+v", u)
	}
	if u.Password != "" {
		t.Error("get must not return a password")
	}
}

func TestRepositoryGetDisplayNameFallsBackToUName(t *testing.T) {
	mock := &mockClient{
		getProps: Properties{
			"a_vcard": {Card: makeCard("firstname", "John", "lastname", "Doe")}, // no fileas
			"u_name":  {Val: "John Doe"},
		},
	}
	u, err := newRepo(mock).Get(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Fileas != "John Doe" {
		t.Errorf("display name fallback: got %q, want u_name %q", u.Fileas, "John Doe")
	}
}

func TestRepositoryGetNotFound(t *testing.T) {
	mock := &mockClient{getErr: &APIError{UID: "account_invalid"}}
	if _, err := newRepo(mock).Get(context.Background(), "ghost"); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("get missing: got %v, want ErrNotFound", err)
	}
}

func TestRepositoryListPrefix(t *testing.T) {
	mock := &mockClient{
		listAccounts: []Account{
			{Name: "John Doe", Email: "jdoe@icewarp.local", AccountType: 0},
			{Name: "Front Desk", Email: "desk@icewarp.local", AccountType: 7}, // not a user
		},
		listTotal: 2,
		getCard:   makeCard("firstname", "John", "lastname", "Doe"),
	}

	list, err := newRepo(mock).List(context.Background(), users.Query{UsernamePrefix: "j"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if mock.listMask != "j*" {
		t.Errorf("namemask pushdown: got %q, want %q", mock.listMask, "j*")
	}
	if len(list) != 1 || list[0].Username != "jdoe" || list[0].Firstname != "John" || list[0].Lastname != "Doe" {
		t.Fatalf("list: unexpected %+v", list)
	}
}

func TestRepositoryListFillsNamesForAllUsers(t *testing.T) {
	mock := &mockClient{
		listAccounts: []Account{
			{Name: "A", Email: "a@icewarp.local", AccountType: 0},
			{Name: "B", Email: "b@icewarp.local", AccountType: 0},
			{Name: "C", Email: "c@icewarp.local", AccountType: 0},
		},
		listTotal: 3,
		getCard:   makeCard("firstname", "John", "lastname", "Doe", "fileas", "John Doe"),
	}

	list, err := newRepo(mock).List(context.Background(), users.Query{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d users, want 3", len(list))
	}
	// Every user must have its name filled from the card (concurrent fan-out).
	for _, u := range list {
		if u.Firstname != "John" || u.Lastname != "Doe" || u.Fileas != "John Doe" {
			t.Errorf("user %s: names not filled: %+v", u.Username, u)
		}
	}
}

func TestRepositoryListExactUsesGet(t *testing.T) {
	mock := &mockClient{
		getProps: Properties{
			"a_vcard": {Card: makeCard("firstname", "John", "lastname", "Doe")},
			"u_name":  {Val: "John Doe"},
		},
	}
	list, err := newRepo(mock).List(context.Background(), users.Query{Username: "jdoe"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if mock.listMask != "" {
		t.Errorf("exact lookup should not call ListAccounts (mask=%q)", mock.listMask)
	}
	if len(list) != 1 || list[0].Username != "jdoe" {
		t.Fatalf("list exact: unexpected %+v", list)
	}
}

func TestRepositoryAuthenticate(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"valid", nil, nil},
		{"wrong-password", ErrInvalidCredentials, users.ErrInvalidCredentials},
		{"disabled", ErrAccountDisabled, users.ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockClient{authErr: tc.err}
			err := newRepo(mock).Authenticate(context.Background(), "jdoe", "pw")
			if !errors.Is(err, tc.want) {
				t.Fatalf("authenticate: got %v, want %v", err, tc.want)
			}
			if mock.authEmail != "jdoe@icewarp.local" {
				t.Errorf("authenticate email: got %q", mock.authEmail)
			}
		})
	}
}

// TestRepositoryUpdateSurnameOnly is the regression for the Keycloak lastName
// edit: only the surname changes. The card is read-modify-written, so the new
// surname sticks and card fields the bridge doesn't manage (here companyname)
// are preserved.
func TestRepositoryUpdateSurnameOnly(t *testing.T) {
	mock := &mockClient{
		getCard: makeCard("firstname", "John", "lastname", "Doe2", "fileas", "Foo Bar", "companyname", "Acme"),
		getProps: Properties{
			"u_accountdisabled": {Val: "0"},
		},
	}

	err := newRepo(mock).Update(context.Background(), users.User{
		Username:  "jdoe",
		Fileas:    "Foo Bar", // unchanged, as Keycloak resends it
		Firstname: "John",
		Lastname:  "Doe3", // the only real change
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if mock.setCardEmail != "jdoe@icewarp.local" {
		t.Fatalf("card not written (email=%q)", mock.setCardEmail)
	}
	if got := mock.setCard.Get("lastname"); got != "Doe3" {
		t.Errorf("lastname: got %q, want Doe3", got)
	}
	if got := mock.setCard.Get("firstname"); got != "John" {
		t.Errorf("firstname clobbered: got %q, want John", got)
	}
	if got := mock.setCard.Get("companyname"); got != "Acme" {
		t.Errorf("unmanaged field dropped: companyname=%q, want Acme", got)
	}
}

// TestRepositoryUpdateExtraNameFields covers the optional name parts
// (middlename/nickname/suffix/title) being written to the card.
func TestRepositoryUpdateExtraNameFields(t *testing.T) {
	mock := &mockClient{
		getCard:  makeCard("firstname", "John", "lastname", "Doe"),
		getProps: Properties{"u_accountdisabled": {Val: "0"}},
	}

	err := newRepo(mock).Update(context.Background(), users.User{
		Username:   "jdoe",
		Firstname:  "John",
		Lastname:   "Doe",
		Middlename: "Bob",
		Nickname:   "Johnny",
		Suffix:     "II",
		Title:      "Herr",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, tc := range []struct{ field, want string }{
		{"middlename", "Bob"}, {"nickname", "Johnny"}, {"suffix", "II"}, {"title", "Herr"},
	} {
		if got := mock.setCard.Get(tc.field); got != tc.want {
			t.Errorf("card %s: got %q, want %q", tc.field, got, tc.want)
		}
	}
}

// TestRepositoryUpdateDisplayNameOnly: a genuine display-name change writes the
// card's fileas; the structured name is untouched.
func TestRepositoryUpdateDisplayNameOnly(t *testing.T) {
	mock := &mockClient{
		getCard:  makeCard("firstname", "John", "lastname", "Doe", "fileas", "Old Name"),
		getProps: Properties{"u_accountdisabled": {Val: "0"}},
	}

	err := newRepo(mock).Update(context.Background(), users.User{
		Username:  "jdoe",
		Fileas:    "New Name",
		Firstname: "John",
		Lastname:  "Doe",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if got := mock.setCard.Get("fileas"); got != "New Name" {
		t.Errorf("fileas: got %q, want New Name", got)
	}
	if g, s := mock.setCard.Get("firstname"), mock.setCard.Get("lastname"); g != "John" || s != "Doe" {
		t.Errorf("structured name changed: firstname=%q lastname=%q", g, s)
	}
}

// TestRepositoryUpdateNoChange writes nothing when nothing changed.
func TestRepositoryUpdateNoChange(t *testing.T) {
	mock := &mockClient{
		getCard:  makeCard("firstname", "John", "lastname", "Doe", "fileas", "John Doe"),
		getProps: Properties{"u_accountdisabled": {Val: "0"}},
	}

	err := newRepo(mock).Update(context.Background(), users.User{
		Username:  "jdoe",
		Fileas:    "John Doe",
		Firstname: "John",
		Lastname:  "Doe",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if mock.setCardEmail != "" {
		t.Errorf("no-op update must not write the card, got email %q", mock.setCardEmail)
	}
	if mock.setProps != nil {
		t.Errorf("no-op update must not write properties, got %+v", mock.setProps)
	}
}

func TestRepositorySetPassword(t *testing.T) {
	mock := &mockClient{}
	if err := newRepo(mock).SetPassword(context.Background(), "jdoe", "new"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if mock.pwEmail != "jdoe@icewarp.local" || mock.pwPassword != "new" || !mock.pwIgnore {
		t.Errorf("setpassword: got %q %q ignore=%v", mock.pwEmail, mock.pwPassword, mock.pwIgnore)
	}
}

// listLoopClient simulates a server that ignores the offset and always returns a
// full page with a total far above the cap — without listAll's cap this loops
// forever. calls is bounded so a regression fails fast instead of hanging.
type listLoopClient struct {
	*mockClient
	page  []Account
	calls int
}

func (c *listLoopClient) ListAccounts(_ context.Context, _, _ string, _, _ int) ([]Account, int, error) {
	c.calls++
	if c.calls > maxListAccounts { // far beyond the pages the cap can need
		return nil, 0, errors.New("listAll did not terminate")
	}
	return c.page, maxListAccounts * 10, nil // total never reached by offset
}

// TestListAllCap: a runaway server can't drive unbounded accumulation; listAll
// stops at maxListAccounts and returns.
func TestListAllCap(t *testing.T) {
	page := make([]Account, 1000)
	client := &listLoopClient{mockClient: &mockClient{}, page: page}

	all, err := newRepo(client).listAll(context.Background(), "*")
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if len(all) < maxListAccounts || len(all) >= maxListAccounts+len(page) {
		t.Fatalf("listAll returned %d accounts, want it capped at ~%d", len(all), maxListAccounts)
	}
}

// TestRepositoryEmailIdempotent: a username that is already a full address is
// not re-qualified (the double-domain regression: johndoe@icewarp.local must not
// become johndoe@icewarp.local@icewarp.local).
func TestRepositoryEmailIdempotent(t *testing.T) {
	r := newRepo(&mockClient{})
	if got := r.email("jdoe"); got != "jdoe@icewarp.local" {
		t.Errorf("bare local part: got %q", got)
	}
	if got := r.email("jdoe@icewarp.local"); got != "jdoe@icewarp.local" {
		t.Errorf("already-qualified: got %q, want it unchanged", got)
	}
}

func TestRepositoryDelete(t *testing.T) {
	mock := &mockClient{}
	if err := newRepo(mock).Delete(context.Background(), "jdoe"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if mock.deleteDomain != "icewarp.local" || len(mock.deleteEmails) != 1 || mock.deleteEmails[0] != "jdoe@icewarp.local" {
		t.Errorf("delete: domain %q emails %v", mock.deleteDomain, mock.deleteEmails)
	}
}

// --- helpers (internal test: can read WriteProperty internals) ---

// makeCard builds an AccountCard from name/value pairs.
func makeCard(kv ...string) AccountCard {
	var c AccountCard
	for i := 0; i+1 < len(kv); i += 2 {
		c.Set(kv[i], kv[i+1])
	}
	return c
}

func propByName(props []WriteProperty, name string) (propertyValue, bool) {
	for _, p := range props {
		if p.propName == name {
			return p.value, true
		}
	}
	return propertyValue{}, false
}

func assertStringProp(t *testing.T, props []WriteProperty, name, want string) {
	t.Helper()
	v, ok := propByName(props, name)
	if !ok || v.class != "TPropertyString" || v.val != want {
		t.Errorf("prop %s: got %+v (present=%v), want TPropertyString=%q", name, v, ok, want)
	}
}
