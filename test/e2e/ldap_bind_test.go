//go:build e2e_ldap

// Package e2e holds end-to-end tests that run against a live LDAP server (the
// bridge or a stock OpenLDAP). Run them with:
//
//	go test -tags e2e_ldap -count=1 ./test/e2e/...
//
// Connection details default to the local dev stack and can be overridden via
// the LDAP_E2E_URL, LDAP_E2E_ADMIN_DN and LDAP_E2E_ADMIN_PASSWORD env vars (see
// config_test.go).
package e2e

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestBind exercises the most basic LDAP operation: binding (authenticating)
// to the directory. A successful bind proves the server is reachable and the
// admin credentials are valid.
func TestBind(t *testing.T) {
	cfg := loadConfig()

	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		t.Fatalf("dial %s: %v", cfg.URL, err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.AdminDN, cfg.AdminPassword); err != nil {
		t.Fatalf("bind as %s: %v", cfg.AdminDN, err)
	}
}
