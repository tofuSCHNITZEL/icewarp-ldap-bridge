// Command ldap-bridge runs the LDAP bridge server: it speaks LDAP to clients
// (e.g. Keycloak's User Federation) and delegates to a user repository.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/verdigado/icewarp-ldap-bridge/internal/icewarp"
	"github.com/verdigado/icewarp-ldap-bridge/internal/ldapserver"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users/memory"
)

// envVars documents every environment variable the bridge reads. It is the
// single source for both the runtime defaults (via env) and the --help text
// (via usage). ICEWARP_ADMIN_EMAIL has no static default — it derives from
// ICEWARP_DOMAIN in buildRepository — and INTROSPECT_ICEWARP is off when empty.
var envVars = []struct{ name, def, desc string }{
	{"ICEWARP_URL", "http://icewarp:80/icewarpapi/", "IceWarp admin RPC endpoint"},
	{"ICEWARP_DOMAIN", "icewarp.local", "mail domain"},
	{"ICEWARP_ADMIN_EMAIL", "", "service account, must be an IceWarp admin (default: admin@$ICEWARP_DOMAIN)"},
	{"ICEWARP_ADMIN_PASSWORD", "", "service account password (required; no default — set it, e.g. via .env)"},
	{"LDAP_USER_BASE_DN", "ou=people,dc=icewarp,dc=local", "DN users are exposed under"},
	{"LDAP_EMAIL_AS_UID", "", "expose the primary email as the uid/RDN, for Keycloak's \"Use email as username\"; off when empty"},
	{"LOG_LEVEL", "info", "log level: debug | info | warn | error"},
	{"INTROSPECT_ICEWARP", "", "dir (or a truthy value) to dump raw IceWarp RPC bodies; off when empty"},
}

func main() {
	addr := flag.String("addr", ":3389", "address to listen on")
	useMemory := flag.Bool("use-in-memory-dummy", false, "use the in-memory dummy backend instead of IceWarp")
	flag.Usage = usage
	flag.Parse()

	logger := newLogger(env("LOG_LEVEL"))

	schema := ldapserver.Schema{
		BaseUserDN: env("LDAP_USER_BASE_DN"),
		Domain:     env("ICEWARP_DOMAIN"),
		EmailAsUID: truthy(env("LDAP_EMAIL_AS_UID")),
	}

	srv, err := ldapserver.New(buildRepository(*useMemory, logger), schema, logger)
	if err != nil {
		logger.Error("create server", "err", err)
		os.Exit(1)
	}

	// Stop the server on SIGINT/SIGTERM so in-flight requests and the cached
	// IceWarp session are released cleanly instead of dropped on process kill.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.Info("shutdown signal received, stopping")
		if err := srv.Stop(); err != nil {
			logger.Error("stop server", "err", err)
		}
	}()

	logger.Info("ldap-bridge listening", "addr", *addr, "base_dn", schema.BaseUserDN)
	if err := srv.Run(*addr); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// buildRepository selects the backend. The default is IceWarp, configured from
// the ICEWARP_* env vars (defaulting to the dev stack). The
// --use-in-memory-dummy flag swaps in the in-memory backend with a dev admin.
func buildRepository(useMemory bool, logger *slog.Logger) users.Repository {
	if useMemory {
		repo := memory.New()
		seedDev(repo)
		logger.Info("backend: in-memory dummy (dev admin seeded)")
		return repo
	}

	endpoint := env("ICEWARP_URL")
	domain := env("ICEWARP_DOMAIN")
	adminEmail := env("ICEWARP_ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = "admin@" + domain
	}
	adminPassword := env("ICEWARP_ADMIN_PASSWORD")
	if adminPassword == "" {
		logger.Error("ICEWARP_ADMIN_PASSWORD is required for the IceWarp backend (set it, e.g. via .env, or use --use-in-memory-dummy)")
		os.Exit(1)
	}

	opts := []icewarp.Option{icewarp.WithLogger(logger)}
	if dir := introspectDir(); dir != "" {
		opts = append(opts, icewarp.WithIntrospection(dir))
		logger.Info("icewarp introspection enabled", "dir", dir)
	}
	client := icewarp.NewClient(endpoint, adminEmail, adminPassword, opts...)
	logger.Info("backend: IceWarp", "url", endpoint, "domain", domain)
	return icewarp.NewRepository(client, domain, logger)
}

// seedDev gives the in-memory backend a single admin user to bind as, so the
// bridge is usable without a real backend.
func seedDev(repo *memory.Repository) {
	repo.Seed(users.User{
		Username: "admin",
		Fileas:   "Admin",
		Lastname: "Admin",
		Email:    "admin@icewarp.local",
		Password: "password",
	})
}

// newLogger builds a text logger at the given level (debug|info|warn|error).
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// introspectDir reads INTROSPECT_ICEWARP: unset or a falsy value (0/false/no/
// off) disables IceWarp request/response body dumps; a truthy value (1/true/
// yes/on) uses a default folder; any other value is the target directory.
func introspectDir() string {
	switch v := os.Getenv("INTROSPECT_ICEWARP"); strings.ToLower(v) {
	case "", "0", "false", "no", "off":
		return ""
	case "1", "true", "yes", "on":
		return "icewarp-introspect"
	default:
		return v
	}
}

// truthy reports whether an env value is an enabled flag (anything other than
// empty or an explicit falsy token).
func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// env returns the value of an environment variable, falling back to its
// documented default in envVars.
func env(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	for _, e := range envVars {
		if e.name == name {
			return e.def
		}
	}
	return ""
}

// usage prints the flag and environment-variable reference (the binary is the
// authoritative source for its own config — see envVars).
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, "ldap-bridge — LDAP front-end for IceWarp accounts (e.g. Keycloak User Federation).\n\n")
	fmt.Fprint(out, "Usage:\n  ldap-bridge [flags]\n\nFlags:\n")
	flag.PrintDefaults()
	fmt.Fprint(out, "\nEnvironment (IceWarp backend; defaults target the dev stack):\n")
	for _, e := range envVars {
		fmt.Fprintf(out, "  %-23s %s\n", e.name, e.desc)
		if e.def != "" {
			fmt.Fprintf(out, "  %-23s (default: %s)\n", "", e.def)
		}
	}
}
