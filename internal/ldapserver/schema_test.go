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
