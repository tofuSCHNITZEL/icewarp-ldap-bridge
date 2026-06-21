package ldapserver

import (
	"strings"

	"github.com/google/uuid"
	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

// Schema defines how the bridge presents users over LDAP: the base DN they live
// under and the attribute mapping. It is the single place that knows the LDAP
// shape; repositories are unaware of it.
type Schema struct {
	// BaseUserDN is the DN users are exposed under, e.g.
	// "ou=people,dc=icewarp,dc=local". A user "jdoe" becomes
	// "uid=jdoe,<BaseUserDN>".
	BaseUserDN string
}

// userObjectClasses is the objectClass set every presented user carries.
var userObjectClasses = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}

func (s Schema) userDN(username string) string {
	return "uid=" + username + "," + s.BaseUserDN
}

// usernameFromDN extracts the uid value from a DN directly under BaseUserDN.
func (s Schema) usernameFromDN(dn string) (string, bool) {
	norm := normalizeDN(dn)
	suffix := "," + normalizeDN(s.BaseUserDN)
	if !strings.HasSuffix(norm, suffix) {
		return "", false
	}
	rdn := norm[:len(norm)-len(suffix)]
	attr, val, ok := strings.Cut(rdn, "=")
	if !ok || attr != "uid" || val == "" || strings.Contains(val, ",") {
		return "", false
	}
	return val, true
}

// attrs builds the LDAP attribute map for a user (lower-cased keys).
func (s Schema) attrs(u users.User) map[string][]string {
	a := map[string][]string{
		"objectclass": userObjectClasses,
		"uid":         {u.Username},
		// A real directory exposes a stable unique id; clients (Keycloak) use it
		// as the federation link, so it must not change across restarts.
		"entryuuid": {stableUUID(u.Username)},
	}
	if u.Fileas != "" {
		a["cn"] = []string{u.Fileas}
	} else {
		a["cn"] = []string{u.Username} // cn is mandatory for person
	}
	if u.Firstname != "" {
		a["givenname"] = []string{u.Firstname}
	}
	if u.Lastname != "" {
		a["sn"] = []string{u.Lastname}
	}
	// Optional name parts from the IceWarp card. Emitted only when present;
	// Keycloak decides via its mappers whether to consume them.
	if u.Middlename != "" {
		a["initials"] = []string{u.Middlename}
	}
	if u.Nickname != "" {
		a["displayname"] = []string{u.Nickname}
	}
	if u.Suffix != "" {
		a["generationqualifier"] = []string{u.Suffix}
	}
	if u.Title != "" {
		a["personaltitle"] = []string{u.Title}
	}
	if u.Email != "" {
		a["mail"] = []string{u.Email}
	}
	return a
}

// userFromAttrs builds a User from LDAP add attributes (any-case keys).
func userFromAttrs(username string, attrs map[string][]string) users.User {
	a := lowerKeys(attrs)
	return users.User{
		Username:   username,
		Fileas:     first(a["cn"]),
		Firstname:  first(a["givenname"]),
		Lastname:   first(a["sn"]),
		Middlename: first(a["initials"]),
		Nickname:   first(a["displayname"]),
		Suffix:     first(a["generationqualifier"]),
		Title:      first(a["personaltitle"]),
		Email:      first(a["mail"]),
		Password:   first(a["userpassword"]),
	}
}

// queryFromFilter extracts a best-effort username pushdown hint from an LDAP
// filter. It is only a hint: the full filter is still applied to results, so an
// over-broad hint is safe and a missed one only costs efficiency.
func queryFromFilter(filter string) users.Query {
	const key = "(uid="
	i := strings.Index(strings.ToLower(filter), key)
	if i < 0 {
		return users.Query{}
	}
	rest := filter[i+len(key):]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return users.Query{}
	}
	val := strings.TrimSpace(rest[:end])
	switch {
	case val == "" || val == "*":
		return users.Query{}
	case strings.HasSuffix(val, "*") && !strings.Contains(val[:len(val)-1], "*"):
		return users.Query{UsernamePrefix: val[:len(val)-1]}
	case !strings.Contains(val, "*"):
		return users.Query{Username: val}
	default:
		return users.Query{}
	}
}

// stableUUID derives a deterministic UUID from a username, so a user's id is
// the same on every read and across restarts.
func stableUUID(username string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(username)).String()
}

func first(vals []string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func lowerKeys(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}
