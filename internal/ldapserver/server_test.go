package ldapserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users/memory"
)

const testBaseDN = "ou=people,dc=icewarp,dc=local"

// startServer runs a Server backed by repo on a free local port and returns its
// address. The server is stopped on test cleanup.
func startServer(t *testing.T, repo users.Repository) string {
	return startServerSchema(t, repo, Schema{BaseUserDN: testBaseDN})
}

// startServerSchema is startServer with an explicit Schema (e.g. EmailAsUID).
func startServerSchema(t *testing.T, repo users.Repository, schema Schema) string {
	t.Helper()
	srv, err := New(repo, schema, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	addr := freePort(t)
	go func() { _ = srv.Run(addr) }()
	t.Cleanup(func() { _ = srv.Stop() })

	deadline := time.Now().Add(5 * time.Second)
	for !srv.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("server did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return addr
}

// freePort reserves an ephemeral port and releases it, returning the address for
// the server to listen on.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func dial(t *testing.T, addr string) *ldap.Conn {
	t.Helper()
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// emptyPasswordBind sends a simple bind with an empty password (an
// unauthenticated bind). go-ldap's Conn.Bind refuses to send an empty password,
// so the request is built explicitly with AllowEmptyPassword to reach the server.
func emptyPasswordBind(conn *ldap.Conn, dn string) error {
	_, err := conn.SimpleBind(&ldap.SimpleBindRequest{Username: dn, AllowEmptyPassword: true})
	return err
}

// TestBindEmptyPasswordRejected: an empty-password (unauthenticated) bind for a
// real account must fail.
func TestBindEmptyPasswordRejected(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "admin", Password: "secret"})
	addr := startServer(t, repo)

	if err := emptyPasswordBind(dial(t, addr), "uid=admin,"+testBaseDN); err == nil {
		t.Fatal("empty-password bind succeeded, want rejection")
	}
}

// TestBindEmptyPasswordRejectedEvenWhenAccountHasNoPassword pins the server-side
// guard specifically: even if the backend would accept the empty password (the
// seeded account itself has an empty password), the bind must still be rejected
// before reaching the backend.
func TestBindEmptyPasswordRejectedEvenWhenAccountHasNoPassword(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "admin", Password: ""})
	addr := startServer(t, repo)

	if err := emptyPasswordBind(dial(t, addr), "uid=admin,"+testBaseDN); err == nil {
		t.Fatal("empty-password bind succeeded against empty-password account, want rejection by the server guard")
	}
}

// TestBindValidSucceeds is the positive control: a correct password binds, so a
// rejection in the empty-password tests is the guard, not a broken harness.
func TestBindValidSucceeds(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "admin", Password: "secret"})
	addr := startServer(t, repo)

	if err := dial(t, addr).Bind("uid=admin,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("valid bind failed: %v", err)
	}
}

// TestBindWrongPasswordRejected: a non-empty but wrong password is rejected.
func TestBindWrongPasswordRejected(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "admin", Password: "secret"})
	addr := startServer(t, repo)

	if err := dial(t, addr).Bind("uid=admin,"+testBaseDN, "wrong"); err == nil {
		t.Fatal("bind with wrong password succeeded, want rejection")
	}
}

// TestBindEmailAsUID: with EmailAsUID the bind DN carries the full email, which
// the server maps back to the mailbox local part before authenticating.
func TestBindEmailAsUID(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "johndoe", Email: "johndoe@icewarp.local", Password: "secret"})
	addr := startServerSchema(t, repo, Schema{BaseUserDN: testBaseDN, Domain: "icewarp.local", EmailAsUID: true})

	if err := dial(t, addr).Bind("uid=johndoe@icewarp.local,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("email-as-uid bind failed: %v", err)
	}
}

// TestModifyCNUpdatesFileas proves a cn (display name) modify is mapped to the
// user's Fileas and persisted — so if IceWarp stays unchanged, the bridge did
// not receive a changed cn value.
func TestModifyCNUpdatesFileas(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "johndoe", Email: "johndoe@icewarp.local", Fileas: "John Doe", Password: "secret"})
	addr := startServer(t, repo)

	conn := dial(t, addr)
	if err := conn.Bind("uid=johndoe,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := ldap.NewModifyRequest("uid=johndoe,"+testBaseDN, nil)
	req.Replace("cn", []string{"Johnny D"})
	if err := conn.Modify(req); err != nil {
		t.Fatalf("modify cn: %v", err)
	}

	u, err := repo.Get(context.Background(), "johndoe")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Fileas != "Johnny D" {
		t.Fatalf("cn change not persisted: Fileas=%q, want %q", u.Fileas, "Johnny D")
	}
}

const testGroupBaseDN = "ou=groups,dc=icewarp,dc=local"

// groupSchema enables both subtrees for the wire group tests.
func groupSchema() Schema {
	return Schema{BaseUserDN: testBaseDN, Domain: "icewarp.local", GroupBaseDN: testGroupBaseDN}
}

// TestSearchServesGroupEntries: a subtree search under the groups base returns
// group entries with objectClass groupOfNames and member DNs.
func TestSearchServesGroupEntries(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "johndoe", Email: "johndoe@icewarp.local", Password: "secret"})
	repo.Seed(users.User{Username: "jane", Email: "jane@icewarp.local"})
	repo.SeedGroup("group1", "johndoe", "jane")
	addr := startServerSchema(t, repo, groupSchema())

	conn := dial(t, addr)
	if err := conn.Bind("uid=johndoe,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN: testGroupBaseDN,
		Scope:  ldap.ScopeWholeSubtree,
		Filter: "(objectClass=groupOfNames)",
	})
	if err != nil {
		t.Fatalf("group search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d group entries, want 1", len(res.Entries))
	}
	e := res.Entries[0]
	if e.DN != "cn=group1,"+testGroupBaseDN {
		t.Errorf("group DN: %q", e.DN)
	}
	members := e.GetAttributeValues("member")
	if len(members) != 2 || members[0] != "uid=johndoe,"+testBaseDN || members[1] != "uid=jane,"+testBaseDN {
		t.Errorf("member DNs: %v", members)
	}
}

// TestSearchUserHasMemberOf: a user entry carries memberOf with group DNs.
func TestSearchUserHasMemberOf(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "johndoe", Email: "johndoe@icewarp.local", Password: "secret", Groups: []string{"group1"}})
	addr := startServerSchema(t, repo, groupSchema())

	conn := dial(t, addr)
	if err := conn.Bind("uid=johndoe,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN: testBaseDN, Scope: ldap.ScopeWholeSubtree, Filter: "(uid=johndoe)",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}
	// Server emits lower-cased keys; go-ldap matches exactly.
	if mo := res.Entries[0].GetAttributeValues("memberof"); len(mo) != 1 || mo[0] != "cn=group1,"+testGroupBaseDN {
		t.Fatalf("memberOf: got %v, want [cn=group1,%s]", mo, testGroupBaseDN)
	}
}

// TestSearchUserSubtreeSkipsGroups: a search under the users base must not
// return group entries (and must not enumerate them).
func TestSearchUserSubtreeSkipsGroups(t *testing.T) {
	repo := memory.New()
	repo.Seed(users.User{Username: "johndoe", Email: "johndoe@icewarp.local", Password: "secret"})
	repo.SeedGroup("group1", "johndoe")
	addr := startServerSchema(t, repo, groupSchema())

	conn := dial(t, addr)
	if err := conn.Bind("uid=johndoe,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN: testBaseDN, Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	for _, e := range res.Entries {
		if e.DN == "cn=group1,"+testGroupBaseDN {
			t.Fatal("user-subtree search returned a group entry")
		}
	}
}

// countingRepo returns a fixed lightweight list and counts per-user Get calls,
// so a test can assert how many entries the search handler enriches.
type countingRepo struct {
	users.Repository // unused methods (Create/Update/…) panic if called
	list             []users.User
	gets             int32
}

func (c *countingRepo) Authenticate(_ context.Context, _, password string) error {
	if password != "secret" {
		return users.ErrInvalidCredentials
	}
	return nil
}

func (c *countingRepo) List(_ context.Context, _ users.Query) ([]users.User, error) {
	return c.list, nil
}

func (c *countingRepo) Get(_ context.Context, username string) (users.User, error) {
	atomic.AddInt32(&c.gets, 1)
	for _, u := range c.list {
		if u.Username == username {
			return u, nil
		}
	}
	return users.User{}, users.ErrNotFound
}

// TestSearchEnrichesOnlyMatches is the call-volume regression: an entryUUID
// search across many users must enrich (Get) only the single match, not the
// whole directory.
func TestSearchEnrichesOnlyMatches(t *testing.T) {
	repo := &countingRepo{}
	for _, name := range []string{"alice", "bob", "carol", "dave", "erin", "frank"} {
		repo.list = append(repo.list, users.User{Username: name, Email: name + "@icewarp.local"})
	}
	addr := startServer(t, repo)

	conn := dial(t, addr)
	if err := conn.Bind("uid=alice,"+testBaseDN, "secret"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	target := stableUUID("carol")
	res, err := conn.Search(&ldap.SearchRequest{
		BaseDN: testBaseDN,
		Scope:  ldap.ScopeWholeSubtree,
		Filter: "(entryUUID=" + target + ")",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("uid") != "carol" {
		t.Fatalf("search returned %d entries, want just carol", len(res.Entries))
	}
	if got := atomic.LoadInt32(&repo.gets); got != 1 {
		t.Fatalf("enriched %d users for a single-match search, want 1", got)
	}
}
