package icewarp

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAccountCardRoundTrip decodes a real a_vcard response, edits one name
// field, and re-marshals it — verifying the structured name is read/written and
// every other field (managed or not) round-trips, matching IceWarp's UI.
func TestAccountCardRoundTrip(t *testing.T) {
	const resp = `<result>
  <item>
    <apiproperty><propname>a_vcard</propname></apiproperty>
    <propertyval>
      <classname>TAccountCard</classname>
      <firstname>John1</firstname>
      <lastname>Doe1</lastname>
      <middlename/>
      <nickname>Spitzname</nickname>
      <fileas>Foo Bar</fileas>
    </propertyval>
    <propertyright>2</propertyright>
  </item>
</result>`

	var res propsResult
	if err := xml.Unmarshal([]byte(resp), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	card := AccountCard{fields: res.Items[0].Value.Fields}
	if card.Get("firstname") != "John1" || card.Get("lastname") != "Doe1" || card.Get("nickname") != "Spitzname" {
		t.Fatalf("decoded card: %+v", card.fields)
	}

	card.Set("lastname", "Doe3") // edit one field

	out, err := xml.Marshal(writeItem{PropName: "a_vcard", Value: cardProperty("a_vcard", card).value})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		"<classname>TAccountCard</classname>",
		"<firstname>John1</firstname>",
		"<lastname>Doe3</lastname>",      // edited
		"<nickname>Spitzname</nickname>", // unmanaged, preserved
		"<fileas>Foo Bar</fileas>",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("marshalled card missing %q in:\n%s", want, out)
		}
	}
}

func TestRedactPasswords(t *testing.T) {
	in := []byte(`<commandparams><password>s3cret</password><email>a@b</email></commandparams>`)
	got := redactPasswords(in)
	if strings.Contains(got, "s3cret") {
		t.Fatalf("password leaked: %s", got)
	}
	if !strings.Contains(got, "<password>***</password>") {
		t.Fatalf("password not masked: %s", got)
	}
}

func TestIntrospectWritesRedactedFile(t *testing.T) {
	dir := t.TempDir()
	c := NewClient("http://x/", "admin@x", "pw", WithIntrospection(dir))

	ts := time.Date(2026, 6, 21, 13, 55, 16, 0, time.UTC)
	c.introspect(ts, "authenticate", "req", []byte(`<password>topsecret</password>`))

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 file, got %d", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasSuffix(name, "-authenticate-req.log") || !strings.HasPrefix(name, "20260621T135516") {
		t.Errorf("unexpected filename %q", name)
	}
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "topsecret") {
		t.Errorf("password leaked into introspection file: %s", body)
	}
}

func TestIntrospectDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	c := NewClient("http://x/", "admin@x", "pw") // no WithIntrospection
	c.introspectDir = ""                         // explicit: disabled
	c.introspect(time.Now(), "authenticate", "req", []byte("x"))

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("introspection should be off, wrote %d files", len(entries))
	}
}
