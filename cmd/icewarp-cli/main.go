package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/verdigado/icewarp-ldap-bridge/internal/icewarp"
)

const cliPageSize = 250

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	global := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	url := global.String("url", envOr("ICEWARP_URL", ""), "IceWarp server `URL`")
	email := global.String("email", envOr("ICEWARP_ADMIN_EMAIL", ""), "admin `email`")
	password := global.String("password", envOr("ICEWARP_ADMIN_PASSWORD", ""), "admin `password`")
	domain := global.String("domain", envOr("ICEWARP_DOMAIN", ""), "mail `domain`")
	verbose := global.Bool("v", false, "verbose logging to stderr")
	global.Usage = printUsage
	global.Parse(os.Args[1:]) //nolint:errcheck // ExitOnError never returns an error

	args := global.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(2)
	}

	if *url == "" || *email == "" || *password == "" {
		die("--url, --email, --password are required (or ICEWARP_URL, ICEWARP_ADMIN_EMAIL, ICEWARP_ADMIN_PASSWORD)")
	}

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	client := icewarp.NewClient(*url, *email, *password, icewarp.WithLogger(logger))

	sub, subArgs := args[0], args[1:]
	switch sub {
	case "get-groups":
		if *domain == "" {
			die("--domain is required for get-groups")
		}
		cmdGetGroups(client, *domain, subArgs)
	case "list-accounts":
		if *domain == "" {
			die("--domain is required for list-accounts")
		}
		cmdListAccounts(client, *domain, subArgs)
	case "get-group-members":
		cmdGetGroupMembers(client, subArgs)
	case "get-account-properties":
		cmdGetAccountProperties(client, subArgs)
	case "get-account-card":
		cmdGetAccountCard(client, subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		printUsage()
		os.Exit(2)
	}
}

func cmdGetGroups(client *icewarp.Client, domain string, args []string) {
	fs := flag.NewFlagSet("get-groups", flag.ExitOnError)
	groupType := fs.Int("type", 7, "account type to filter (7=group/public-folder, 1=mailing-list, 8=resource)")
	offset := fs.Int("offset", 0, "start offset")
	count := fs.Int("count", 0, "max results per page (0=fetch all pages)")
	fs.Parse(args) //nolint:errcheck

	var accounts []icewarp.Account
	if *count > 0 {
		page, _, err := client.ListGroups(context.Background(), domain, *groupType, *offset, *count)
		check(err)
		accounts = page
	} else {
		for off := *offset; ; {
			page, total, err := client.ListGroups(context.Background(), domain, *groupType, off, cliPageSize)
			check(err)
			accounts = append(accounts, page...)
			off += len(page)
			if len(page) == 0 || off >= total {
				break
			}
		}
	}
	writeJSON(accounts)
}

func cmdListAccounts(client *icewarp.Client, domain string, args []string) {
	fs := flag.NewFlagSet("list-accounts", flag.ExitOnError)
	mask := fs.String("mask", "*", "name mask glob (* and ? wildcards)")
	offset := fs.Int("offset", 0, "start offset")
	count := fs.Int("count", 0, "max results per page (0=fetch all pages)")
	fs.Parse(args) //nolint:errcheck

	var accounts []icewarp.Account
	if *count > 0 {
		page, _, err := client.ListAccounts(context.Background(), domain, *mask, *offset, *count)
		check(err)
		accounts = page
	} else {
		for off := *offset; ; {
			page, total, err := client.ListAccounts(context.Background(), domain, *mask, off, cliPageSize)
			check(err)
			accounts = append(accounts, page...)
			off += len(page)
			if len(page) == 0 || off >= total {
				break
			}
		}
	}
	writeJSON(accounts)
}

func cmdGetGroupMembers(client *icewarp.Client, args []string) {
	fs := flag.NewFlagSet("get-group-members", flag.ExitOnError)
	offset := fs.Int("offset", 0, "start offset")
	count := fs.Int("count", 0, "max results per page (0=fetch all pages)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: icewarp-cli [global flags] get-group-members [--offset N] [--count N] GROUP_EMAIL")
		fs.PrintDefaults()
	}
	fs.Parse(args) //nolint:errcheck

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	groupEmail := fs.Arg(0)

	var members []string
	if *count > 0 {
		page, _, err := client.GetGroupMembers(context.Background(), groupEmail, *offset, *count)
		check(err)
		members = page
	} else {
		for off := *offset; ; {
			page, total, err := client.GetGroupMembers(context.Background(), groupEmail, off, cliPageSize)
			check(err)
			members = append(members, page...)
			off += len(page)
			if len(page) == 0 || off >= total {
				break
			}
		}
	}
	writeJSON(members)
}

func cmdGetAccountProperties(client *icewarp.Client, args []string) {
	fs := flag.NewFlagSet("get-account-properties", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: icewarp-cli [global flags] get-account-properties ACCOUNT_EMAIL PROP [PROP...]")
	}
	fs.Parse(args) //nolint:errcheck

	if fs.NArg() < 2 {
		fs.Usage()
		os.Exit(2)
	}
	accountEmail := fs.Arg(0)
	props := fs.Args()[1:]

	properties, err := client.GetAccountProperties(context.Background(), accountEmail, props...)
	check(err)

	type propOutput struct {
		Val  string            `json:"val,omitempty"`
		Card map[string]string `json:"card,omitempty"`
	}
	out := make(map[string]propOutput, len(properties))
	for name, p := range properties {
		po := propOutput{Val: p.Val}
		if m := p.Card.Map(); len(m) > 0 {
			po.Card = m
		}
		out[name] = po
	}
	writeJSON(out)
}

func cmdGetAccountCard(client *icewarp.Client, args []string) {
	fs := flag.NewFlagSet("get-account-card", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: icewarp-cli [global flags] get-account-card ACCOUNT_EMAIL")
	}
	fs.Parse(args) //nolint:errcheck

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	card, err := client.GetAccountCard(context.Background(), fs.Arg(0))
	check(err)
	writeJSON(card.Map())
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		die(err.Error())
	}
}

func check(err error) {
	if err != nil {
		die(err.Error())
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: icewarp-cli [global flags] SUBCOMMAND [flags] [args]

Global flags:
  --url URL          IceWarp server URL  (env: ICEWARP_URL)
  --email EMAIL      Admin email         (env: ICEWARP_ADMIN_EMAIL)
  --password PASS    Admin password      (env: ICEWARP_ADMIN_PASSWORD)
  --domain DOMAIN    Mail domain         (env: ICEWARP_DOMAIN)
  -v                 Verbose logging to stderr

Subcommands:
  get-groups           [--type N] [--offset N] [--count N]
  list-accounts        [--mask GLOB] [--offset N] [--count N]
  get-group-members    [--offset N] [--count N] GROUP_EMAIL
  get-account-properties  ACCOUNT_EMAIL PROP [PROP...]
  get-account-card        ACCOUNT_EMAIL

--count 0 (default) fetches all results by paging through the server.
Account types: 0=user 1=mailing-list 7=group/public-folder 8=resource
`)
}
