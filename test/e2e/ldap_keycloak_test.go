//go:build e2e_ldap

package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// These tests cover the core LDAP operations Keycloak's LDAP User Federation
// performs against a directory (derived from Keycloak's LDAPOperationManager /
// LDAPIdentityStore): Root DSE capability discovery, user authentication via
// bind, filtered + paged searches, and password updates. Conditional/rare
// operations Keycloak only uses in narrow cases (ModifyDN/rename, StartTLS, the
// RFC 3062 password-modify extended op) are intentionally left out.

// addUser creates an inetOrgPerson under baseDN and registers cleanup. It
// returns the new entry's DN.
func addUser(t *testing.T, conn *ldap.Conn, baseDN, uid, mail, password string) string {
	t.Helper()
	dn := fmt.Sprintf("uid=%s,%s", uid, baseDN)
	_ = conn.Del(ldap.NewDelRequest(dn, nil)) // clear any leftover from a prior run

	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{uid})
	add.Attribute("cn", []string{uid})
	add.Attribute("sn", []string{uid})
	if mail != "" {
		add.Attribute("mail", []string{mail})
	}
	if password != "" {
		add.Attribute("userPassword", []string{password})
	}
	if err := conn.Add(add); err != nil {
		t.Fatalf("add %s: %v", dn, err)
	}
	t.Cleanup(func() { _ = conn.Del(ldap.NewDelRequest(dn, nil)) })
	return dn
}

// tryBind dials a fresh connection and attempts a simple bind, returning the
// bind error (nil on success). Keycloak verifies a user's password by binding
// as that user's DN on a separate connection.
func tryBind(t *testing.T, cfg Config, dn, password string) error {
	t.Helper()
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		t.Fatalf("dial %s: %v", cfg.URL, err)
	}
	defer conn.Close()
	return conn.Bind(dn, password)
}

// TestRootDSE mirrors LDAPIdentityStore.queryServerCapabilities: a base-scoped
// search with an empty base DN must return exactly one entry advertising the
// server's supported controls.
func TestRootDSE(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	req := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"supportedControl", "supportedLDAPVersion", "namingContexts"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("root DSE search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("root DSE: got %d entries, want 1", len(res.Entries))
	}

	const pagingOID = "1.2.840.113556.1.4.319"
	controls := res.Entries[0].GetAttributeValues("supportedControl")
	if !contains(controls, pagingOID) {
		t.Fatalf("root DSE supportedControl %v does not advertise paged results (%s)", controls, pagingOID)
	}

	// Interactive LDAP clients (Apache Directory Studio, JXplorer, etc.) refuse
	// to browse without at least one advertised naming context.
	if contexts := res.Entries[0].GetAttributeValues("namingContexts"); len(contexts) == 0 {
		t.Fatal("root DSE namingContexts is empty, clients cannot discover a search base")
	}
}

// TestAuthenticateUser covers user authentication by bind and password updates
// (LDAPIdentityStore.updatePassword's REPLACE on userPassword): a user can bind
// with their password, a wrong password is rejected, and after a password
// change the new password works while the old one no longer does.
func TestAuthenticateUser(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	const oldPassword, newPassword = "Secret123!", "Changed456!"
	dn := addUser(t, conn, cfg.UserBaseDN, "e2e-auth", "e2e-auth@icewarp.local", oldPassword)

	if err := tryBind(t, cfg, dn, oldPassword); err != nil {
		t.Fatalf("bind with correct password: %v", err)
	}
	if err := tryBind(t, cfg, dn, "wrong-password"); err == nil {
		t.Fatal("bind with wrong password: expected error, got nil")
	}

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("userPassword", []string{newPassword})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("change password: %v", err)
	}

	if err := tryBind(t, cfg, dn, newPassword); err != nil {
		t.Fatalf("bind with new password: %v", err)
	}
	if err := tryBind(t, cfg, dn, oldPassword); err == nil {
		t.Fatal("bind with old password after change: expected error, got nil")
	}
}

// TestSearchUsers covers the filtered searches Keycloak issues to look up and
// list users: a compound equality filter for a single user and a substring
// filter to enumerate a set.
func TestSearchUsers(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	dn1 := addUser(t, conn, cfg.UserBaseDN, "e2e-find-1", "find1@icewarp.local", "")
	addUser(t, conn, cfg.UserBaseDN, "e2e-find-2", "find2@icewarp.local", "")

	// Lookup by username: (&(objectClass=inetOrgPerson)(uid=e2e-find-1)).
	lookup := ldap.NewSearchRequest(
		cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", ldap.EscapeFilter("e2e-find-1")),
		[]string{"uid"}, nil,
	)
	res, err := conn.Search(lookup)
	if err != nil {
		t.Fatalf("lookup search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].DN != dn1 {
		t.Fatalf("lookup: got %d entries %v, want 1 (%s)", len(res.Entries), dns(res), dn1)
	}

	// Enumerate by substring: (uid=e2e-find-*) should return both users.
	list := ldap.NewSearchRequest(
		cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(uid=e2e-find-*)",
		[]string{"uid"}, nil,
	)
	res, err = conn.Search(list)
	if err != nil {
		t.Fatalf("list search: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("list: got %d entries %v, want 2", len(res.Entries), dns(res))
	}
}

// TestSearchKeycloakUserLookup reproduces the filter the Keycloak admin console
// builds when searching users: an OR over the mapped attributes (uid/mail/cn/sn)
// ANDed with objectClass assertions. The nested compound followed by sibling
// leaves is the shape that must parse correctly.
func TestSearchKeycloakUserLookup(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	dn := addUser(t, conn, cfg.UserBaseDN, "e2e-kc", "e2e-kc@icewarp.local", "")

	const filter = "(&(|(uid=e2e-kc*)(mail=e2e-kc*)(cn=e2e-kc*)(sn=e2e-kc*))" +
		"(objectClass=inetOrgPerson)(objectClass=organizationalPerson))"
	req := ldap.NewSearchRequest(
		cfg.UserBaseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"uid"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].DN != dn {
		t.Fatalf("keycloak-style lookup: got %d entries %v, want 1 (%s)", len(res.Entries), dns(res), dn)
	}
}

// TestSearchReturnsPagingControl checks that a search carrying the paged-results
// control gets a paging control back in the response. Keycloak logs a warning
// ("Did not receive response controls for paginated query") otherwise.
func TestSearchReturnsPagingControl(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	req := ldap.NewSearchRequest(
		cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(uid=*)", []string{"uid"},
		[]ldap.Control{ldap.NewControlPaging(100)},
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("paged search: %v", err)
	}
	if ldap.FindControl(res.Controls, ldap.ControlTypePaging) == nil {
		t.Fatal("response is missing the paged-results control")
	}
}

// TestEntryHasStableUUID checks that entries carry a non-empty entryUUID that is
// stable across reads — Keycloak uses it as the federation link id.
func TestEntryHasStableUUID(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	addUser(t, conn, cfg.UserBaseDN, "e2e-uuid", "e2e-uuid@icewarp.local", "")

	read := func() string {
		req := ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false, "(uid=e2e-uuid)", []string{"entryUUID"}, nil)
		res, err := conn.Search(req)
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("search: %d entries, err %v", len(res.Entries), err)
		}
		return attrCI(res.Entries[0], "entryUUID")
	}

	first := read()
	if first == "" {
		t.Fatal("entry has no entryUUID")
	}
	if second := read(); second != first {
		t.Fatalf("entryUUID changed between reads: %q vs %q", first, second)
	}
}

// TestPagedSearch covers LDAPOperationManager.searchPaginated: a paged search
// (PagedResultsControl) must return the full result set across pages.
func TestPagedSearch(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	const total = 5
	for i := 0; i < total; i++ {
		addUser(t, conn, cfg.UserBaseDN, fmt.Sprintf("e2e-page-%d", i), "", "")
	}

	req := ldap.NewSearchRequest(
		cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(uid=e2e-page-*)",
		[]string{"uid"}, nil,
	)
	res, err := conn.SearchWithPaging(req, 2)
	if err != nil {
		t.Fatalf("paged search: %v", err)
	}
	if len(res.Entries) != total {
		t.Fatalf("paged search: got %d entries, want %d", len(res.Entries), total)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// attrCI reads an attribute case-insensitively (LDAP attribute names are
// case-insensitive, but go-ldap's GetAttributeValue is not).
func attrCI(e *ldap.Entry, name string) string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) && len(a.Values) > 0 {
			return a.Values[0]
		}
	}
	return ""
}

func dns(res *ldap.SearchResult) []string {
	out := make([]string, len(res.Entries))
	for i, e := range res.Entries {
		out[i] = e.DN
	}
	return out
}
