//go:build e2e_icewarp

package icewarp_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/verdigado/icewarp-ldap-bridge/internal/icewarp"
)

// End-to-end test for the IceWarp client, run against the live dev instance:
//
//	go test -tags e2e_icewarp ./internal/icewarp/...
//
// Connection details default to the dev stack (reachable as icewarp:80 from the
// devcontainer) and are overridable via ICEWARP_* env vars.
//
// The bad-credentials bind path is intentionally NOT exercised: it is tarpitted
// ~25-30s server-side. The disabled-account path (immediate) is used instead to
// cover a bind failure.

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func newClient(t *testing.T) (*icewarp.Client, string) {
	t.Helper()
	endpoint := env("ICEWARP_URL", "http://icewarp:80/icewarpapi/")
	email := env("ICEWARP_ADMIN_EMAIL", "admin@icewarp.local")
	domain := env("ICEWARP_DOMAIN", "icewarp.local")
	// The admin password has no default — it's the same credential the bridge
	// uses, so fall back to ICEWARP_ADMIN_PASSWORD (loaded from .env).
	password := env("ICEWARP_ADMIN_PASSWORD", os.Getenv("ICEWARP_ADMIN_PASSWORD"))
	if password == "" {
		t.Skip("set ICEWARP_ADMIN_PASSWORD (e.g. `set -a; source .env; set +a`) to run the IceWarp client e2e")
	}
	return icewarp.NewClient(endpoint, email, password), domain
}

// withTimeout returns a context for the fast admin commands.
func withTimeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestClientE2E(t *testing.T) {
	client, domain := newClient(t)

	if err := client.Authenticate(withTimeout(t, 60*time.Second)); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	const mailbox = "e2eclient"
	email := mailbox + "@" + domain
	const password = "Bridge#9Probe!" // policy: mixed case + digit + special, no account name

	// Start clean and guarantee teardown.
	_ = client.DeleteAccounts(withTimeout(t, 30*time.Second), domain, email)
	t.Cleanup(func() {
		_ = client.DeleteAccounts(withTimeout(t, 30*time.Second), domain, email)
	})

	// createaccount
	err := client.CreateAccount(withTimeout(t, 30*time.Second), domain,
		icewarp.StringProperty("u_mailbox", mailbox),
		icewarp.StringProperty("u_type", "0"),
		icewarp.StringProperty("u_name", "E2E Client"),
	)
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	// getaccountsinfolist: the new account is found and enabled.
	accounts, total, err := client.ListAccounts(withTimeout(t, 30*time.Second), domain, mailbox+"*", 0, 0)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	got := findAccount(accounts, email)
	if got == nil {
		t.Fatalf("list accounts: %s not found (total=%d, got %v)", email, total, emails(accounts))
	}
	if got.Disabled() {
		t.Fatalf("freshly created account %s is disabled", email)
	}

	// getaccountproperties: read back what we set.
	props, err := client.GetAccountProperties(withTimeout(t, 30*time.Second), email, "u_mailbox", "u_name")
	if err != nil {
		t.Fatalf("get properties: %v", err)
	}
	if props["u_mailbox"].Val != mailbox {
		t.Fatalf("u_mailbox: got %q, want %q", props["u_mailbox"].Val, mailbox)
	}

	// a_vcard (TAccountCard): the structured name lives here, not in a_name. Read
	// the card, update the name fields, write the whole card back, and re-read to
	// confirm each field persisted (and that the read-modify-write preserved the
	// fields we didn't touch).
	card, err := client.GetAccountCard(withTimeout(t, 30*time.Second), email)
	if err != nil {
		t.Fatalf("get card: %v", err)
	}
	card.Set("firstname", "E2E")
	card.Set("lastname", "Renamed")
	card.Set("fileas", "E2E Renamed Display")
	card.Set("nickname", "e2enick")
	card.Set("middlename", "Mid")
	card.Set("suffix", "Jr")
	card.Set("title", "Dr")
	if err := client.SetAccountCard(withTimeout(t, 30*time.Second), email, card); err != nil {
		t.Fatalf("set card: %v", err)
	}

	card, err = client.GetAccountCard(withTimeout(t, 30*time.Second), email)
	if err != nil {
		t.Fatalf("re-read card: %v", err)
	}
	for _, tc := range []struct{ field, want string }{
		{"firstname", "E2E"},
		{"lastname", "Renamed"},
		{"fileas", "E2E Renamed Display"},
		{"nickname", "e2enick"},
		{"middlename", "Mid"},
		{"suffix", "Jr"},
		{"title", "Dr"},
	} {
		if got := card.Get(tc.field); got != tc.want {
			t.Errorf("card %s after write: got %q, want %q", tc.field, got, tc.want)
		}
	}

	// setaccountpassword + getauthtoken: bind succeeds with the new password.
	if err := client.SetAccountPassword(withTimeout(t, 30*time.Second), email, password, false); err != nil {
		t.Fatalf("set password: %v", err)
	}
	tok, err := client.GetAuthToken(withTimeout(t, 90*time.Second), email, password)
	if err != nil {
		t.Fatalf("auth token (valid password): %v", err)
	}
	if tok.Token == "" {
		t.Fatal("auth token (valid password): empty token")
	}

	// Disable the account → bind now fails fast with ErrAccountDisabled.
	if err := client.SetAccountProperties(withTimeout(t, 30*time.Second), email,
		icewarp.StringProperty("u_accountdisabled", "1"),
	); err != nil {
		t.Fatalf("disable account: %v", err)
	}
	if _, err := client.GetAuthToken(withTimeout(t, 30*time.Second), email, password); !errors.Is(err, icewarp.ErrAccountDisabled) {
		t.Fatalf("auth token (disabled): got %v, want ErrAccountDisabled", err)
	}
}

// TestClientE2EGroups proves the user→groups reverse lookup: create a user and a
// group, add the user to the group, and read it back via the u_groups property.
func TestClientE2EGroups(t *testing.T) {
	client, domain := newClient(t)
	if err := client.Authenticate(withTimeout(t, 60*time.Second)); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	const userMbx, groupMbx = "e2egmember", "e2egroup"
	userEmail := userMbx + "@" + domain
	groupEmail := groupMbx + "@" + domain

	// Start clean and guarantee teardown (deleting the group purges membership).
	cleanup := func() {
		_ = client.DeleteAccounts(withTimeout(t, 30*time.Second), domain, userEmail, groupEmail)
	}
	cleanup()
	t.Cleanup(cleanup)

	if err := client.CreateAccount(withTimeout(t, 30*time.Second), domain,
		icewarp.StringProperty("u_mailbox", userMbx), icewarp.StringProperty("u_type", "0")); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := client.CreateAccount(withTimeout(t, 30*time.Second), domain,
		icewarp.StringProperty("u_mailbox", groupMbx), icewarp.StringProperty("u_type", "7"),
		icewarp.StringProperty("u_name", "E2E Group")); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if err := client.AddGroupMembers(withTimeout(t, 30*time.Second), groupEmail, userEmail); err != nil {
		t.Fatalf("add group member: %v", err)
	}

	// u_groups on the user now lists the group address.
	props, err := client.GetAccountProperties(withTimeout(t, 30*time.Second), userEmail, "u_groups")
	if err != nil {
		t.Fatalf("get u_groups: %v", err)
	}
	if !strings.Contains(props["u_groups"].Val, groupEmail) {
		t.Fatalf("u_groups = %q, want it to contain %q", props["u_groups"].Val, groupEmail)
	}

	// And the repository maps it to the group's local part on the user.
	u, err := icewarp.NewRepository(client, domain, nil).Get(withTimeout(t, 30*time.Second), userMbx)
	if err != nil {
		t.Fatalf("repo get: %v", err)
	}
	if !contains(u.Groups, groupMbx) {
		t.Fatalf("user groups = %v, want it to contain %q", u.Groups, groupMbx)
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func findAccount(accounts []icewarp.Account, email string) *icewarp.Account {
	for i := range accounts {
		if accounts[i].Email == email {
			return &accounts[i]
		}
	}
	return nil
}

func emails(accounts []icewarp.Account) []string {
	out := make([]string, len(accounts))
	for i, a := range accounts {
		out[i] = a.Email
	}
	return out
}
