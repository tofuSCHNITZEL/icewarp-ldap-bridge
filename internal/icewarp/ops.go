package icewarp

import (
	"context"
	"errors"
	"fmt"
)

// Authenticate logs the service account in and caches the session id. It is
// called automatically by the session commands; call it directly only to
// validate credentials up front. The bad-credentials failure is tarpitted
// (~25-30s), so give the context ample timeout.
func (c *Client) Authenticate(ctx context.Context) error {
	// Clear the cached sid first so a failed re-auth doesn't leave a stale
	// invalid session that session() would return on the next call.
	c.mu.Lock()
	c.sid = ""
	c.mu.Unlock()

	var res resultScalar
	sid, err := c.call(ctx, "", "authenticate", authParams{
		AuthType: 0,
		Email:    c.email,
		Password: c.password,
	}, &res)
	if err != nil {
		return err
	}
	if sid == "" {
		return errors.New("icewarp: authenticate succeeded but returned no sid")
	}
	c.mu.Lock()
	c.sid = sid
	c.mu.Unlock()
	return nil
}

// GetAuthToken validates a user's password by binding as them (no admin session
// needed). It returns the auth token plus the account's name on success, or
// ErrInvalidCredentials / ErrAccountDisabled / ErrTwoFactorRequired on failure.
//
// The invalid-credentials path is tarpitted ~25-30s server-side; the context
// timeout for this call should be >= 60s.
func (c *Client) GetAuthToken(ctx context.Context, email, password string) (*AuthToken, error) {
	var res authTokenResult
	_, err := c.call(ctx, "", "getauthtoken", authTokenParams{
		Email:           email,
		Password:        password,
		Digest:          "",
		AuthType:        0,
		PersistentLogin: 0,
	}, &res)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			switch ae.UID {
			case "auth_login_invalid":
				return nil, ErrInvalidCredentials
			case "account_disabled_2":
				return nil, ErrAccountDisabled
			case "auth_two_factor_required":
				return nil, ErrTwoFactorRequired
			}
		}
		return nil, err
	}
	if res.AuthToken == "" {
		return nil, ErrInvalidCredentials
	}
	return &AuthToken{
		Email:     res.Email,
		GivenName: res.Name.Given,
		Surname:   res.Name.Surname,
		Token:     res.AuthToken,
	}, nil
}

// ListAccounts searches a domain. nameMask is a case-insensitive glob (*, ?)
// matched against both login and display name ("*" for all). offset/count page
// the results; pass count <= 0 for the server default. It returns the page of
// accounts plus the overall match count (for paging).
func (c *Client) ListAccounts(ctx context.Context, domain, nameMask string, offset, count int) ([]Account, int, error) {
	if nameMask == "" {
		nameMask = "*"
	}
	var res listResult
	err := c.sessionCall(ctx, "getaccountsinfolist", listParams{
		Domain: domain,
		Filter: listFilter{NameMask: nameMask},
		Offset: offset,
		Count:  count,
	}, &res)
	if err != nil {
		return nil, 0, err
	}
	return res.Items, res.OverallCount, nil
}

// ListGroups searches a domain for accounts of a single accounttype (7 = group,
// 1 = mailing list — see docs/icewarp-api.md). offset/count page the results
// (pass count <= 0 for the server default); it returns the page plus the
// overall match count for that type.
func (c *Client) ListGroups(ctx context.Context, domain string, accountType, offset, count int) ([]Account, int, error) {
	var res listResult
	err := c.sessionCall(ctx, "getaccountsinfolist", listParams{
		Domain: domain,
		Filter: listFilter{NameMask: "*", TypeMask: &accountType},
		Offset: offset,
		Count:  count,
	}, &res)
	if err != nil {
		return nil, 0, err
	}
	return res.Items, res.OverallCount, nil
}

// GetGroupMembers reads the member addresses of a group (or list/resource) by its
// address. offset/count page the results (pass count <= 0 for the server
// default); it returns the page of member addresses plus the overall count.
func (c *Client) GetGroupMembers(ctx context.Context, groupEmail string, offset, count int) ([]string, int, error) {
	var res memberInfoResult
	if err := c.sessionCall(ctx, "getaccountmemberinfolist", memberInfoParams{
		Who:    groupEmail,
		Offset: offset,
		Count:  count,
	}, &res); err != nil {
		return nil, 0, err
	}
	members := make([]string, 0, len(res.Items))
	for _, it := range res.Items {
		if it.Val != "" {
			members = append(members, it.Val)
		}
	}
	return members, res.OverallCount, nil
}

// GetAccountProperties reads the named properties of one account.
func (c *Client) GetAccountProperties(ctx context.Context, email string, props ...string) (Properties, error) {
	items := make([]propNameItem, len(props))
	for i, p := range props {
		items[i] = propNameItem{PropName: p}
	}

	var res propsResult
	err := c.sessionCall(ctx, "getaccountproperties", getPropsParams{
		Email: email,
		List:  propNameList{Items: items},
	}, &res)
	if err != nil {
		return nil, err
	}

	out := make(Properties, len(res.Items))
	for _, it := range res.Items {
		out[it.PropName] = Property{
			Val:  it.Value.Val,
			Card: AccountCard{fields: it.Value.Fields},
		}
	}
	return out, nil
}

// GetAccountCard reads the a_vcard (TAccountCard) property — the account's
// structured name and full contact card. The whole card is returned so callers
// can change a few fields and write it back without dropping the rest.
func (c *Client) GetAccountCard(ctx context.Context, email string) (AccountCard, error) {
	props, err := c.GetAccountProperties(ctx, email, "a_vcard")
	if err != nil {
		return AccountCard{}, err
	}
	return props["a_vcard"].Card, nil
}

// SetAccountCard writes the whole a_vcard card back (read-modify-write). IceWarp
// re-sends every card field on save, so a partial write would blank the fields
// it omits; always pass a card read via GetAccountCard with only the wanted
// fields changed.
func (c *Client) SetAccountCard(ctx context.Context, email string, card AccountCard) error {
	return c.SetAccountProperties(ctx, email, cardProperty("a_vcard", card))
}

// SetAccountProperties writes properties to an account. A no-op write (setting
// an unchanged value) still succeeds; an unknown property name makes the server
// report nothing-applied, surfaced here as an error.
func (c *Client) SetAccountProperties(ctx context.Context, email string, props ...WriteProperty) error {
	var res resultScalar
	if err := c.sessionCall(ctx, "setaccountproperties", setPropsParams{
		Email:  email,
		Values: writeList{Items: writeItems(props)},
	}, &res); err != nil {
		return err
	}
	return checkApplied(res, "setaccountproperties")
}

// SetAccountPassword changes an account's password (LDAP modify userPassword).
// ignorePolicy bypasses the server password policy when true.
func (c *Client) SetAccountPassword(ctx context.Context, email, password string, ignorePolicy bool) error {
	ignore := 0
	if ignorePolicy {
		ignore = 1
	}
	var res resultScalar
	if err := c.sessionCall(ctx, "setaccountpassword", setPasswordParams{
		Email:        email,
		IgnorePolicy: ignore,
		Password:     password,
	}, &res); err != nil {
		return err
	}
	return checkApplied(res, "setaccountpassword")
}

// CreateAccount provisions an account in domain. props must include at least
// u_mailbox and u_type (use StringProperty). Set the structured name afterward
// via the a_vcard card (SetAccountCard) and a password via SetAccountPassword.
func (c *Client) CreateAccount(ctx context.Context, domain string, props ...WriteProperty) error {
	var res resultScalar
	if err := c.sessionCall(ctx, "createaccount", createParams{
		Domain: domain,
		Props:  writeList{Items: writeItems(props)},
	}, &res); err != nil {
		return err
	}
	return checkApplied(res, "createaccount")
}

// DeleteAccounts removes the given full addresses from a domain.
func (c *Client) DeleteAccounts(ctx context.Context, domain string, emails ...string) error {
	var res resultScalar
	if err := c.sessionCall(ctx, "deleteaccounts", deleteParams{
		Domain: domain,
		List:   accountList{Class: "tpropertystringlist", Items: emails},
	}, &res); err != nil {
		return err
	}
	return checkApplied(res, "deleteaccounts")
}

// AddGroupMembers adds members (full addresses) to a group/list/resource by its
// address. Adds are idempotent server-side. The bridge itself doesn't write
// membership (group mapping is read-only via the u_groups property); this exists
// for provisioning and e2e fixtures.
func (c *Client) AddGroupMembers(ctx context.Context, groupEmail string, memberEmails ...string) error {
	items := make([]memberItem, len(memberEmails))
	for i, m := range memberEmails {
		items[i] = memberItem{Class: "tpropertymember", Val: m}
	}
	var res resultScalar
	if err := c.sessionCall(ctx, "addaccountmembers", addMembersParams{
		Email:   groupEmail,
		Members: memberList{Class: "tpropertymembers", Items: items},
	}, &res); err != nil {
		return err
	}
	return checkApplied(res, "addaccountmembers")
}

// checkApplied turns the write result semantics (1 = applied, 0 = not applied)
// into an error.
func checkApplied(res resultScalar, command string) error {
	if res.Value != "1" {
		return fmt.Errorf("icewarp: %s not applied (result=%q)", command, res.Value)
	}
	return nil
}
