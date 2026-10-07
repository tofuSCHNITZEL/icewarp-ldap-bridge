package ldapserver

import (
	"testing"

	"github.com/verdigado/icewarp-ldap-bridge/internal/users"
)

const (
	schemaBase   = "ou=people,dc=icewarp,dc=local"
	schemaDomain = "icewarp.local"
)

func localPartSchema() Schema { return Schema{BaseUserDN: schemaBase, Domain: schemaDomain} }
func emailUIDSchema() Schema {
	return Schema{BaseUserDN: schemaBase, Domain: schemaDomain, EmailAsUID: true}
}

func TestUserDN(t *testing.T) {
	if got := localPartSchema().userDN("jdoe"); got != "uid=jdoe,"+schemaBase {
		t.Errorf("local-part userDN: got %q", got)
	}
	if got := emailUIDSchema().userDN("jdoe"); got != "uid=jdoe@icewarp.local,"+schemaBase {
		t.Errorf("email userDN: got %q", got)
	}
}

func TestUsernameFromDN(t *testing.T) {
	cases := []struct {
		name   string
		schema Schema
		dn     string
		want   string
		ok     bool
	}{
		{"local-part bare", localPartSchema(), "uid=jdoe," + schemaBase, "jdoe", true},
		{"local-part case/space", localPartSchema(), "UID=JDoe, " + schemaBase, "jdoe", true},
		// A stray domain-qualified uid is normalised to the local part even when
		// EmailAsUID is off, so it never doubles up downstream.
		{"local-part with domain", localPartSchema(), "uid=jdoe@icewarp.local," + schemaBase, "jdoe", true},
		{"email mode", emailUIDSchema(), "uid=jdoe@icewarp.local," + schemaBase, "jdoe", true},
		{"email mode bare uid", emailUIDSchema(), "uid=jdoe," + schemaBase, "jdoe", true},
		{"foreign domain rejected", emailUIDSchema(), "uid=jdoe@other.example," + schemaBase, "", false},
		{"wrong base", localPartSchema(), "uid=jdoe,ou=other,dc=icewarp,dc=local", "", false},
		{"not uid", localPartSchema(), "cn=jdoe," + schemaBase, "", false},
		{"empty uid", localPartSchema(), "uid=," + schemaBase, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.schema.usernameFromDN(tc.dn)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("usernameFromDN(%q): got (%q,%v), want (%q,%v)", tc.dn, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// Round-trip: usernameFromDN(userDN(x)) == x in both modes.
func TestUIDRoundTrip(t *testing.T) {
	for _, s := range []Schema{localPartSchema(), emailUIDSchema()} {
		got, ok := s.usernameFromDN(s.userDN("jdoe"))
		if !ok || got != "jdoe" {
			t.Errorf("round-trip (EmailAsUID=%v): got (%q,%v)", s.EmailAsUID, got, ok)
		}
	}
}

func TestAttrsUID(t *testing.T) {
	u := users.User{Username: "jdoe", Email: "jdoe@icewarp.local"}
	if got := localPartSchema().attrs(u)["uid"]; len(got) != 1 || got[0] != "jdoe" {
		t.Errorf("local-part uid attr: got %v", got)
	}
	if got := emailUIDSchema().attrs(u)["uid"]; len(got) != 1 || got[0] != "jdoe@icewarp.local" {
		t.Errorf("email uid attr: got %v", got)
	}
}

// TestAttrsNameParts pins the LDAP attribute names for the optional name parts.
// They mirror the IceWarp card fields (middlename/nickname/suffix) rather than the
// loosely-matching inetOrgPerson attributes that used to carry them
// (initials/displayName/generationQualifier); the honorific keeps the standard
// name personalTitle. A regression here would silently break the realm mappers.
func TestAttrsNameParts(t *testing.T) {
	u := users.User{
		Username: "jdoe", Email: "jdoe@icewarp.local", Fileas: "John Doe",
		Firstname: "John", Lastname: "Doe", Middlename: "Quincy",
		Nickname: "Johnny", Suffix: "Jr", Title: "Dr",
	}
	a := localPartSchema().attrs(u)

	want := map[string]string{
		"cn": "John Doe", "givenname": "John", "sn": "Doe",
		"middlename": "Quincy", "nickname": "Johnny", "suffix": "Jr",
		"personaltitle": "Dr", "mail": "jdoe@icewarp.local",
	}
	for k, v := range want {
		if got := a[k]; len(got) != 1 || got[0] != v {
			t.Errorf("attr %q: got %v, want [%q]", k, got, v)
		}
	}
	// The old, pre-rename attribute names must not be emitted.
	for _, k := range []string{"initials", "displayname", "generationqualifier"} {
		if _, ok := a[k]; ok {
			t.Errorf("stale attribute %q still emitted", k)
		}
	}

	// Round-trip: userFromAttrs reads the same names back.
	got := userFromAttrs(u.Username, a)
	if got.Middlename != "Quincy" || got.Nickname != "Johnny" || got.Suffix != "Jr" || got.Title != "Dr" {
		t.Errorf("round-trip name parts: %+v", got)
	}
}

func TestGroupSchema(t *testing.T) {
	const groupBase = "ou=groups,dc=icewarp,dc=local"
	s := Schema{BaseUserDN: schemaBase, Domain: schemaDomain, GroupBaseDN: groupBase}

	// DN build + parse round-trip.
	if got := s.groupDN("group1"); got != "cn=group1,"+groupBase {
		t.Errorf("groupDN: got %q", got)
	}
	if name, ok := s.groupNameFromDN("CN=Group1, " + groupBase); !ok || name != "group1" {
		t.Errorf("groupNameFromDN: got (%q,%v)", name, ok)
	}
	if _, ok := s.groupNameFromDN("uid=jdoe," + schemaBase); ok {
		t.Error("groupNameFromDN matched a user DN")
	}

	// Group entry attributes: objectClass, cn, member DNs, entryUUID.
	g := users.Group{Name: "group1", Description: "Group One", Members: []string{"jdoe", "jane"}}
	a := s.groupAttrs(g)
	if got := a["cn"]; len(got) != 1 || got[0] != "Group One" {
		t.Errorf("group cn: %v", got)
	}
	if got := a["uid"]; len(got) != 1 || got[0] != g.Name {
		t.Errorf("group uid: %v", got)
	}
	if got := (Schema{EmailAsUID: true, Domain: schemaDomain}).groupAttrs(g)["uid"]; len(got) != 1 || got[0] != g.Name {
		t.Errorf("group uid with EmailAsUID: %v", got)
	}
	if got := a["member"]; len(got) != 2 || got[0] != "uid=jdoe,"+schemaBase || got[1] != "uid=jane,"+schemaBase {
		t.Errorf("group member DNs: %v", got)
	}
	if got := a["description"]; len(got) != 1 || got[0] != "Group One" {
		t.Errorf("group description: %v", got)
	}
	if len(a["entryuuid"]) != 1 || a["entryuuid"][0] == "" {
		t.Errorf("group entryuuid missing: %v", a["entryuuid"])
	}
	// Distinct from a same-named user's UUID.
	if a["entryuuid"][0] == stableUUID("group1") {
		t.Error("group entryUUID collides with user UUID")
	}
	withoutDisplayName := s.groupAttrs(users.Group{Name: g.Name})
	if got := withoutDisplayName["cn"]; len(got) != 1 || got[0] != g.Name {
		t.Errorf("group cn without display name: %v", got)
	}
	if got := withoutDisplayName["uid"]; len(got) != 1 || got[0] != g.Name {
		t.Errorf("group uid without display name: %v", got)
	}
	if _, ok := withoutDisplayName["description"]; ok {
		t.Error("empty group description emitted")
	}
	if a["entryuuid"][0] != withoutDisplayName["entryuuid"][0] {
		t.Error("group entryUUID depends on display name")
	}

	// memberOf on user entries carries the group DNs.
	u := users.User{Username: "jdoe", Groups: []string{"group1", "public-folders"}}
	mo := s.attrs(u)["memberof"]
	if len(mo) != 2 || mo[0] != "cn=group1,"+groupBase || mo[1] != "cn=public-folders,"+groupBase {
		t.Errorf("memberOf: %v", mo)
	}
	// No memberOf when GroupBaseDN is unset.
	if _, ok := localPartSchema().attrs(u)["memberof"]; ok {
		t.Error("memberOf emitted without GroupBaseDN")
	}
}

func TestQueryFromFilter(t *testing.T) {
	cases := []struct {
		name   string
		schema Schema
		filter string
		want   users.Query
	}{
		{"exact", localPartSchema(), "(uid=jdoe)", users.Query{Username: "jdoe"}},
		// The double-domain regression: a domain-qualified uid must push down the
		// bare local part, not "jdoe@icewarp.local" (which fetch would re-qualify).
		{"exact qualified", localPartSchema(), "(uid=jdoe@icewarp.local)", users.Query{Username: "jdoe"}},
		{"exact qualified email mode", emailUIDSchema(), "(&(uid=jdoe@icewarp.local)(objectclass=inetorgperson))", users.Query{Username: "jdoe"}},
		{"prefix", localPartSchema(), "(uid=jd*)", users.Query{UsernamePrefix: "jd"}},
		{"presence", localPartSchema(), "(uid=*)", users.Query{}},
		{"foreign domain not pushed", emailUIDSchema(), "(uid=jdoe@other.example)", users.Query{}},
		{"no uid", localPartSchema(), "(entryUUID=abc)", users.Query{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.schema.queryFromFilter(tc.filter); got != tc.want {
				t.Fatalf("queryFromFilter(%q): got %+v, want %+v", tc.filter, got, tc.want)
			}
		})
	}
}
