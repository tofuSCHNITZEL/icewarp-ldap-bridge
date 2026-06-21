package icewarp

import "encoding/xml"

// --- public domain types ---

// Account is one entry from a getaccountsinfolist search.
type Account struct {
	Name         string `xml:"name"`         // display name (u_name)
	Email        string `xml:"email"`        // primary address
	DisplayEmail string `xml:"displayemail"` // shown address
	AccountType  int    `xml:"accounttype"`  // 0 = user, 7 = public folder/resource
	State        int    `xml:"accountstate>state"`
	AdminType    int    `xml:"admintype"` // 0 = normal, 1 = admin
}

// Disabled reports whether the account is disabled (state 1).
func (a Account) Disabled() bool { return a.State == 1 }

// Property is a typed value read from getaccountproperties. Which fields are
// populated depends on Class.
type Property struct {
	Val  string      // TPropertyString scalar
	Card AccountCard // TAccountCard contact card
}

// Properties maps property name to its typed value.
type Properties map[string]Property

// AuthToken is the successful result of a user bind (getauthtoken). A non-empty
// Token means the credentials are valid; the name fields come free with it.
type AuthToken struct {
	Email     string
	GivenName string
	Surname   string
	Token     string
}

// WriteProperty is a property value to write (createaccount / setaccountproperties).
type WriteProperty struct {
	propName string
	value    propertyValue
}

// StringProperty builds a TPropertyString write item (most scalar props).
func StringProperty(propName, val string) WriteProperty {
	return WriteProperty{propName, propertyValue{class: "TPropertyString", val: val}}
}

// cardProperty builds a TAccountCard write item that re-sends the whole card.
func cardProperty(propName string, card AccountCard) WriteProperty {
	return WriteProperty{propName, propertyValue{class: "TAccountCard", card: card.fields}}
}

// AccountCard is the value of the a_vcard (TAccountCard) property: the account's
// structured name and full contact card. IceWarp's admin UI keeps the name
// fields here (firstname/lastname/fileas/nickname/…), not in a_name/u_name, and
// rewrites the entire card on every save. Callers do the same — read it with
// Client.GetAccountCard, change fields with Set, write it back with
// Client.SetAccountCard — so unmanaged fields survive the round-trip.
type AccountCard struct {
	fields []cardField
}

// cardField is one child element of <propertyval>, decoded via ",any" so the
// whole card round-trips regardless of which fields a server version sends.
type cardField struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// Get returns the named field's value (empty if absent).
func (c AccountCard) Get(name string) string {
	for _, f := range c.fields {
		if f.XMLName.Local == name {
			return f.Value
		}
	}
	return ""
}

// Set updates the named field, appending it if the card doesn't carry it yet.
func (c *AccountCard) Set(name, value string) {
	for i := range c.fields {
		if c.fields[i].XMLName.Local == name {
			c.fields[i].Value = value
			return
		}
	}
	c.fields = append(c.fields, cardField{XMLName: xml.Name{Local: name}, Value: value})
}

// --- request param structs (each marshals to <commandparams>) ---

type authParams struct {
	XMLName  xml.Name `xml:"commandparams"`
	AuthType int      `xml:"authtype"`
	Email    string   `xml:"email"`
	Password string   `xml:"password"`
}

type authTokenParams struct {
	XMLName         xml.Name `xml:"commandparams"`
	Email           string   `xml:"email"`
	Password        string   `xml:"password"`
	Digest          string   `xml:"digest"`
	AuthType        int      `xml:"authtype"`
	PersistentLogin int      `xml:"persistentlogin"`
}

type listParams struct {
	XMLName xml.Name   `xml:"commandparams"`
	Domain  string     `xml:"domainstr"`
	Filter  listFilter `xml:"filter"`
	Offset  int        `xml:"offset,omitempty"`
	Count   int        `xml:"count,omitempty"`
}

type listFilter struct {
	NameMask string `xml:"namemask"`
	TypeMask *int   `xml:"typemask,omitempty"`
}

type getPropsParams struct {
	XMLName xml.Name     `xml:"commandparams"`
	Email   string       `xml:"accountemail"`
	List    propNameList `xml:"accountpropertylist"`
}

type propNameList struct {
	Items []propNameItem `xml:"item"`
}

type propNameItem struct {
	PropName string `xml:"propname"`
}

type setPropsParams struct {
	XMLName xml.Name  `xml:"commandparams"`
	Email   string    `xml:"accountemail"`
	Values  writeList `xml:"propertyvaluelist"`
}

type createParams struct {
	XMLName xml.Name  `xml:"commandparams"`
	Domain  string    `xml:"domainstr"`
	Props   writeList `xml:"accountproperties"`
}

type writeList struct {
	Items []writeItem `xml:"item"`
}

type writeItem struct {
	PropName string        `xml:"apiproperty>propname"`
	Value    propertyValue `xml:"propertyval"`
}

func writeItems(props []WriteProperty) []writeItem {
	items := make([]writeItem, len(props))
	for i, p := range props {
		items[i] = writeItem{PropName: p.propName, Value: p.value}
	}
	return items
}

type setPasswordParams struct {
	XMLName      xml.Name `xml:"commandparams"`
	Email        string   `xml:"accountemail"`
	IgnorePolicy int      `xml:"ignorepolicy"`
	Password     string   `xml:"password"`
}

type deleteParams struct {
	XMLName xml.Name    `xml:"commandparams"`
	Domain  string      `xml:"domainstr"`
	List    accountList `xml:"accountlist"`
}

type accountList struct {
	Class string   `xml:"classname"`
	Items []string `xml:"val>item"`
}

// propertyValue marshals to the class-specific shape inside <propertyval>.
type propertyValue struct {
	class string
	val   string
	card  []cardField
}

func (p propertyValue) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := encodeText(e, "classname", p.class); err != nil {
		return err
	}
	switch p.class {
	case "TPropertyString":
		if err := encodeText(e, "val", p.val); err != nil {
			return err
		}
	case "TAccountCard":
		// Emit every field of the card in its original order, so a written card
		// round-trips the fields we don't manage (nickname, addresses, …).
		for _, f := range p.card {
			if err := encodeText(e, f.XMLName.Local, f.Value); err != nil {
				return err
			}
		}
	}
	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

func encodeText(e *xml.Encoder, name, text string) error {
	return e.EncodeElement(text, xml.StartElement{Name: xml.Name{Local: name}})
}

// --- response structs (decode the <result> payload) ---

// resultScalar matches a <result>TEXT</result> payload (writes, authenticate).
type resultScalar struct {
	XMLName xml.Name `xml:"result"`
	Value   string   `xml:",chardata"`
}

type authTokenResult struct {
	XMLName   xml.Name    `xml:"result"`
	Email     string      `xml:"email"`
	Name      accountName `xml:"name"`
	AuthToken string      `xml:"authtoken"`
}

type accountName struct {
	Class   string `xml:"classname"`
	Given   string `xml:"name"`
	Surname string `xml:"surname"`
}

type listResult struct {
	XMLName      xml.Name  `xml:"result"`
	Items        []Account `xml:"item"`
	Offset       int       `xml:"offset"`
	OverallCount int       `xml:"overallcount"`
}

type propsResult struct {
	XMLName xml.Name       `xml:"result"`
	Items   []propRespItem `xml:"item"`
}

type propRespItem struct {
	PropName string  `xml:"apiproperty>propname"`
	Value    propVal `xml:"propertyval"`
	Right    int     `xml:"propertyright"`
}

type propVal struct {
	// Class is decoded only so <classname> isn't swept into Fields by ",any".
	Class  string      `xml:"classname"`
	Val    string      `xml:"val"`  // TPropertyString scalar
	Fields []cardField `xml:",any"` // TAccountCard leaf fields (empty for other classes)
}
