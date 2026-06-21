//go:build e2e_ldap

package e2e

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// dialAndBind opens a connection to the directory and binds as the admin user.
// CRUD operations require an authenticated (write-capable) connection.
func dialAndBind(t *testing.T, cfg Config) *ldap.Conn {
	t.Helper()

	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		t.Fatalf("dial %s: %v", cfg.URL, err)
	}
	if err := conn.Bind(cfg.AdminDN, cfg.AdminPassword); err != nil {
		conn.Close()
		t.Fatalf("bind as %s: %v", cfg.AdminDN, err)
	}
	return conn
}

// TestUserCRUD exercises the four basic directory operations against the user
// base DN: Add (create), Search (read), Modify (update) and Delete. They run
// in sequence on a single throwaway entry — each step depends on the previous.
//
// The user base DN is configurable via LDAP_USER_BASE_DN and defaults to the
// dev stack's people OU.
func TestUserCRUD(t *testing.T) {
	cfg := loadConfig()
	conn := dialAndBind(t, cfg)
	defer conn.Close()

	baseDN := cfg.UserBaseDN
	const uid = "e2e-crud"
	dn := fmt.Sprintf("uid=%s,%s", uid, baseDN)

	// Ensure a clean slate in case a previous run left the entry behind.
	_ = conn.Del(ldap.NewDelRequest(dn, nil))
	// And guarantee cleanup even if a later step fails.
	defer func() { _ = conn.Del(ldap.NewDelRequest(dn, nil)) }()

	// Create.
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{uid})
	add.Attribute("cn", []string{"E2E CRUD"})
	add.Attribute("sn", []string{"CRUD"})
	add.Attribute("mail", []string{"e2e-crud@icewarp.local"})
	add.Attribute("userPassword", []string{"password"})
	if err := conn.Add(add); err != nil {
		t.Fatalf("create %s: %v", dn, err)
	}

	// Read: look the entry up by uid under the base DN and verify an attribute.
	if mail := readAttr(t, conn, baseDN, uid, "mail"); mail != "e2e-crud@icewarp.local" {
		t.Fatalf("read after create: got mail %q, want %q", mail, "e2e-crud@icewarp.local")
	}

	// Update: replace the display name (cn). mail is identity-bound on some
	// backends, so cn is the portable attribute to modify.
	const newCN = "E2E Renamed"
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("cn", []string{newCN})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("update %s: %v", dn, err)
	}
	if cn := readAttr(t, conn, baseDN, uid, "cn"); cn != newCN {
		t.Fatalf("read after update: got cn %q, want %q", cn, newCN)
	}

	// Delete.
	if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		t.Fatalf("delete %s: %v", dn, err)
	}
	// Confirm it's gone: the search should return zero entries.
	res, err := conn.Search(searchByUID(baseDN, uid))
	if err != nil {
		t.Fatalf("search after delete: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("entry %s still present after delete", dn)
	}
}

// readAttr searches for the entry by uid under baseDN and returns the named
// attribute, failing the test if exactly one entry isn't found.
func readAttr(t *testing.T, conn *ldap.Conn, baseDN, uid, attr string) string {
	t.Helper()

	res, err := conn.Search(searchByUID(baseDN, uid))
	if err != nil {
		t.Fatalf("search uid=%s: %v", uid, err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("search uid=%s: got %d entries, want 1", uid, len(res.Entries))
	}
	return res.Entries[0].GetAttributeValue(attr)
}

func searchByUID(baseDN, uid string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid)),
		[]string{"mail", "cn"},
		nil,
	)
}
