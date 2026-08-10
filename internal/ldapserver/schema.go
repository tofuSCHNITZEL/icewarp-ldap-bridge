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

	// Domain is the mail domain accounts live in (e.g. "icewarp.local"). It is
	// only needed to build/parse the uid when EmailAsUID is set.
	Domain string

	// EmailAsUID exposes the account's primary email as the uid (and thus the
	// RDN): "jdoe" becomes "uid=jdoe@icewarp.local,<BaseUserDN>". Set this to
	// match a Keycloak federation whose username/RDN attribute resolves to the
	// email (Keycloak's "Use email as username"); otherwise Keycloak's computed
	// RDN won't match the entry DN and it issues a rename the bridge can't serve.
	// When false (default) the uid is the bare mailbox local part.
	EmailAsUID bool

	// GroupBaseDN, when non-empty, enables serving groups as LDAP entries
	// ("cn=<group>,<GroupBaseDN>", objectClass groupOfNames) and adds a "memberOf"
	// attribute (the group DNs) to user entries. Point a Keycloak Group LDAP
	// mapper at it. Empty disables group entries and memberOf.
	GroupBaseDN string
}

// userObjectClasses is the objectClass set every presented user carries.
var userObjectClasses = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}

// groupObjectClasses is the objectClass set every presented group carries.
var groupObjectClasses = []string{"top", "groupOfNames"}

func (s Schema) groupDN(name string) string {
	return "cn=" + name + "," + s.GroupBaseDN
}

// groupNameFromDN extracts the cn of a group DN directly under GroupBaseDN.
func (s Schema) groupNameFromDN(dn string) (string, bool) {
	if s.GroupBaseDN == "" {
		return "", false
	}
	norm := normalizeDN(dn)
	suffix := "," + normalizeDN(s.GroupBaseDN)
	if !strings.HasSuffix(norm, suffix) {
		return "", false
	}
	rdn := norm[:len(norm)-len(suffix)]
	attr, val, ok := strings.Cut(rdn, "=")
	if !ok || attr != "cn" || val == "" || strings.Contains(val, ",") {
		return "", false
	}
	return val, true
}

// groupAttrs builds the LDAP attribute map for a group entry (lower-cased keys).
// member holds the member user DNs (respecting EmailAsUID via userDN).
func (s Schema) groupAttrs(g users.Group) map[string][]string {
	a := map[string][]string{
		"objectclass": groupObjectClasses,
		"cn":          {g.DisplayName},
		"displayName":   {g.DisplayName},
		"mail":        {g.Email},
		"uid":         {g.Name},
		"entryuuid":   {stableGroupUUID(g.Name)},
	}
	if len(g.Members) > 0 {
		members := make([]string, len(g.Members))
		for i, m := range g.Members {
			members[i] = s.userDN(m)
		}
		a["member"] = members
	}
	return a
}

func (s Schema) userDN(username string) string {
	return "uid=" + s.uidValue(username) + "," + s.BaseUserDN
}

// uidValue is the uid (and RDN) value presented for a mailbox local part: the
// primary email when EmailAsUID is set, otherwise the bare local part.
func (s Schema) uidValue(username string) string {
	if s.EmailAsUID {
		return username + "@" + s.Domain
	}
	return username
}

// usernameFromDN extracts the mailbox local part from the uid of a DN directly
// under BaseUserDN, undoing uidValue (stripping the domain when EmailAsUID).
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
	return s.localPartFromUID(val)
}

// localPartFromUID reduces a uid value to the mailbox local part. A bare local
// part is taken as-is; a domain-qualified uid must carry our Domain (a foreign
// domain is rejected), so a stray "@domain" never doubles up downstream.
func (s Schema) localPartFromUID(uid string) (string, bool) {
	at := strings.LastIndex(uid, "@")
	if at < 0 {
		return uid, true
	}
	local, dom := uid[:at], uid[at+1:]
	if local == "" || !strings.EqualFold(dom, s.Domain) {
		return "", false
	}
	return local, true
}

// attrs builds the LDAP attribute map for a user (lower-cased keys).
func (s Schema) attrs(u users.User) map[string][]string {
	a := map[string][]string{
		"objectclass": userObjectClasses,
		"uid":         {s.uidValue(u.Username)},
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
	// Optional name parts, named to mirror the IceWarp card fields
	// (middlename/nickname/suffix) rather than forcing them onto loosely-matching
	// inetOrgPerson attributes (initials/displayName/generationQualifier). The
	// honorific keeps the standard name personalTitle, because LDAP "title" means
	// job title. Emitted only when present; a Keycloak User Attribute mapper
	// consumes each by name.
	if u.Middlename != "" {
		a["middlename"] = []string{u.Middlename}
	}
	if u.Nickname != "" {
		a["nickname"] = []string{u.Nickname}
	}
	if u.Suffix != "" {
		a["suffix"] = []string{u.Suffix}
	}
	if u.Title != "" {
		a["personaltitle"] = []string{u.Title}
	}
	if u.Email != "" {
		a["mail"] = []string{u.Email}
	}
	// memberOf carries the group DNs when group entries are served, for a Keycloak
	// Group LDAP mapper (memberOf strategy). Read-only.
	if s.GroupBaseDN != "" && len(u.Groups) > 0 {
		dns := make([]string, len(u.Groups))
		for i, g := range u.Groups {
			dns[i] = s.groupDN(g)
		}
		a["memberof"] = dns
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
		Middlename: first(a["middlename"]),
		Nickname:   first(a["nickname"]),
		Suffix:     first(a["suffix"]),
		Title:      first(a["personaltitle"]),
		Email:      first(a["mail"]),
		Password:   first(a["userpassword"]),
	}
}

// queryFromFilter extracts a best-effort username pushdown hint from an LDAP
// filter. It is only a hint: the full filter is still applied to results, so an
// over-broad hint is safe and a missed one only costs efficiency. A uid value is
// reduced to the mailbox local part (stripping our domain), so a domain-qualified
// uid — always so under EmailAsUID — resolves to the right account instead of
// having the domain appended a second time.
func (s Schema) queryFromFilter(filter string) users.Query {
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
		if local, ok := s.localPartFromUID(val); ok {
			return users.Query{Username: local}
		}
		return users.Query{}
	default:
		return users.Query{}
	}
}

// groupFromMemberOfFilter extracts a membership pushdown hint: the group name
// from a "(memberOf=<groupDN>)" assertion, when the DN names a group under
// GroupBaseDN. It lets a "members of group X" search (Keycloak's
// GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE strategy) resolve X's members in one
// backend call instead of enumerating and enriching every user.
//
// Seeding candidates from the group's members is only sound when the memberOf
// assertion is a required conjunct, so its members are a superset of the result
// the full filter then narrows. We require that the filter be a pure conjunction
// — no OR, no NOT — which guarantees it: under "|" the term may be optional and
// under "!" negated, either of which would drop valid matches. Anything else
// (including a wildcard value, which can't name one group) is declined, and the
// caller falls back to enumeration, which always filters correctly.
func (s Schema) groupFromMemberOfFilter(filter string) (string, bool) {
	if s.GroupBaseDN == "" {
		return "", false
	}
	// Operators sit immediately after "(" (see parseFilter), so a substring check
	// reliably spots an OR/NOT anywhere in the filter.
	if strings.Contains(filter, "(|") || strings.Contains(filter, "(!") {
		return "", false
	}
	const key = "(memberof="
	i := strings.Index(strings.ToLower(filter), key)
	if i < 0 {
		return "", false
	}
	rest := filter[i+len(key):]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return "", false
	}
	dn := strings.TrimSpace(rest[:end])
	if dn == "" || strings.Contains(dn, "*") {
		return "", false
	}
	return s.groupNameFromDN(dn)
}

// stableUUID derives a deterministic UUID from a username, so a user's id is
// the same on every read and across restarts.
func stableUUID(username string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(username)).String()
}

// stableGroupUUID derives a deterministic UUID for a group, namespaced so it
// can't collide with a user's stableUUID.
func stableGroupUUID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("group:"+name)).String()
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
