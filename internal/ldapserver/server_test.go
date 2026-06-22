package ldapserver

import (
	"net"
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
