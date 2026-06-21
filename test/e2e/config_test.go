//go:build e2e_ldap

package e2e

import "os"

// Config holds the connection settings for the e2e suite. Every field has a
// default pointing at the dev stack and is overridable via the named env var.
// This is the single source of truth for the e2e test variables.
type Config struct {
	URL           string // LDAP_URL
	AdminDN       string // LDAP_ADMIN_DN
	AdminPassword string // LDAP_ADMIN_PASSWORD
	UserBaseDN    string // LDAP_USER_BASE_DN
}

// loadConfig reads the e2e settings from the environment, falling back to the
// dev-stack defaults.
func loadConfig() Config {
	return Config{
		URL:           env("LDAP_E2E_URL", "ldap://localhost:3389"),
		AdminDN:       env("LDAP_E2E_ADMIN_DN", "uid=admin,dc=icewarp,dc=local"),
		AdminPassword: env("LDAP_E2E_ADMIN_PASSWORD", "password"),
		UserBaseDN:    env("LDAP_E2E_USER_BASE_DN", "ou=people,dc=icewarp,dc=local"),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
