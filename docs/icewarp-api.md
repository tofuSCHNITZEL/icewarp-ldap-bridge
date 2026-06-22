# IceWarp Admin RPC — API reference for the bridge

Complete description of the IceWarp admin RPC API for the commands the
LDAP bridge uses. Everything here is **verified live** against the running dev
server and cross-checked against the admin console's own client code (the
console builds these exact stanzas), so there is nothing left to
reverse-engineer.

- **Build:** `14.3.0.3` — "Epos Update 3 build 3", RHEL8 x64
  (`C_Version` = `14.3.0.3`, `C_Niceversion` = `Epos Update 3 build 3`).
  Command and property names differ across IceWarp releases; this reference is
  only guaranteed for this build. Re-verify after a server upgrade.
- **Authoritative sources used:** live probing of `/icewarpapi/`; the admin
  console client JS (`html/admin/client/inc/wm_user.js`, `javascript.js`,
  `bundle.js`) which generates the stanzas — for groups/membership specifically
  `wa_accountmembers.js` (the member commands) and `wa_list.js` (the
  `Get<Label>InfoList` naming) plus `obj_groupmembers.js`; the server-side PHP tunnel
  (`html/_shared/api/apitunnel.php`) which fixes the parameter order for
  `authenticate` / `getauthtoken`; and network captures (HAR) of the admin
  console reading/writing a user's name (the `a_vcard` flow in §5/§6).

---

## 1. Transport & envelope

- **Endpoint:** `POST /icewarpapi/`
  - Host dev stack: `http://localhost:8081/icewarpapi/`
  - From the devcontainer (compose network): `http://icewarp:80/icewarpapi/`
- **Request header:** `Content-Type: text/xml` (UTF-8). The response comes back
  as `application/xml`.
- **Request body:**

  ```xml
  <iq sid="SID" id="N">
    <query xmlns="admin:iq:rpc">
      <commandname>COMMAND</commandname>
      <commandparams>… params …</commandparams>
    </query>
  </iq>
  ```

  - `sid` is an **attribute on `<iq>`**. Omit it for the session-less commands
    (`authenticate`, `getauthtoken`); include it on every other command.
  - `id` is an optional client correlation id echoed back; the bridge can drop
    it.
  - `xmlns="admin:iq:rpc"` is mandatory and exact (wrong namespace →
    `iq_query_xmlns_invalid`).
- **Command names are matched case-insensitively.** `createaccount` and
  `GetServerProperties` both work. The console uses mixed case; this doc uses
  the lowercase form the bridge sends.
- **Response body:**

  ```xml
  <iq type="result" sid="SID"><query xmlns="admin:iq:rpc">PAYLOAD</query></iq>
  <iq type="error"  sid="SID"><query xmlns="admin:iq:rpc"><error uid="…"/></query></iq>
  ```

  - `type="result"` → success; payload is `<result>…</result>`.
  - `type="error"` → failure; payload is a single `<error uid="…"/>` (see the
    [error catalogue](#9-error-uid-catalogue)). Detect failure on
    `iq/@type == "error"`, not by parsing `<result>`.

### Property value classes

Account/server properties are typed. The `<propertyval>` wrapper carries a
`<classname>` plus class-specific children. The ones the bridge meets:

| classname            | shape inside `<propertyval>`                         | used for |
| -------------------- | ---------------------------------------------------- | -------- |
| `TPropertyString`    | `<val>TEXT</val>`                                    | most scalar `u_*` props (name, mailbox, disabled flag) |
| `TPropertyNoValue`   | *(empty)*                                            | unset property |
| `TPropertyStringList`| `<val><item>A</item><item>B</item></val>`           | aliases, `deleteaccounts` account list |
| `TPropertyMembers`   | `<val>` of `TPropertyMember` items, each `<val>ADDRESS</val>` + optional `default`/`recieve`/`post`/`digest` rights | group / mailing-list membership writes (§10) |
| `TAccountName`       | `<name>GIVEN</name><surname>FAMILY</surname>`        | `a_name` — a legacy givenName/surname split (see §5) |
| `TAccountCard`       | `<classname>TAccountCard</classname>` + ~70 leaf fields (`firstname`, `lastname`, `fileas`, `nickname`, addresses, phones, …) | `a_vcard` — the contact card; **the structured-name store the admin UI actually edits** |
| `TAccountState`      | `<state>0\|1</state>` (read-only)                     | enabled/disabled in account lists |

### Property read item / write item

A **read** (`getaccountproperties`) asks for property names and gets typed
values back:

```xml
<!-- request: which props to read -->
<accountpropertylist><item><propname>u_name</propname></item>…</accountpropertylist>

<!-- response: one <item> per property -->
<item>
  <apiproperty><propname>u_name</propname></apiproperty>
  <propertyval><classname>TPropertyString</classname><val>OIDC Test</val></propertyval>
  <propertyright>2</propertyright>
</item>
```

`propertyright`: `2` = read/write, `1` = read-only, `0` = no access.

A **write** (`setaccountproperties`, `createaccount`) sends the value back in the
same item shape:

```xml
<item>
  <apiproperty><propname>a_name</propname></apiproperty>
  <propertyval><classname>TAccountName</classname><name>Bridge</name><surname>Probe</surname></propertyval>
</item>
```

The list element is named **`propertyvaluelist`** for `setaccountproperties`
but **`accountproperties`** for `createaccount`. This is the one nesting detail
guessing gets wrong.

---

## 2. `authenticate` — service-account session login

- **sid required:** no — this is what *creates* the session.
- **Parameters** (flat children of `<commandparams>`; order per the PHP client):

  | element    | req | type / values                         | notes |
  | ---------- | --- | ------------------------------------- | ----- |
  | `authtype` | yes | `0` = plaintext password, `1` = RSA digest | bridge uses `0` |
  | `email`    | yes | full address, e.g. `admin@icewarp.local` | |
  | `password` | yes | string                                | |

- **Request:**

  ```xml
  <iq><query xmlns="admin:iq:rpc"><commandname>authenticate</commandname>
    <commandparams>
      <authtype>0</authtype>
      <email>admin@icewarp.local</email>
      <password>…</password>
    </commandparams></query></iq>
  ```

- **Success:** `<result>1</result>`, and the **`sid` is an attribute on the
  response `<iq>`**. Store it; attach it to every later command.
- **Errors:**
  - `auth_login_invalid` — wrong credentials. **Tarpitted** (~25–30 s, see
    [§8](#8-failed-bind--anti-brute-force-tarpit)). A misconfigured service
    password will make startup auth hang for ~30 s, not fail fast.
- **Rights:** any valid account can authenticate (a non-admin login succeeds and
  returns a sid). Per-command authorization is enforced separately, so the
  bridge **must use an admin service account** or the account-management
  commands will be denied.

---

## 3. `getauthtoken` — LDAP user bind (password validation)

The bind primitive: validate a user's own password. **No admin session needed.**

- **sid required:** no.
- **Parameters:**

  | element           | req | type / values | notes |
  | ----------------- | --- | ------------- | ----- |
  | `email`           | yes | user address  | |
  | `password`        | yes | string        | sent here when `authtype=0` |
  | `digest`          | yes | empty string  | used instead of `password` when `authtype=1`; send empty |
  | `authtype`        | yes | `0` = plaintext, `1` = RSA digest | bridge uses `0` |
  | `persistentlogin` | yes | `0` / `1`     | bridge uses `0` |
  | `totpcode`        | no  | string        | only if 2FA is enforced; omit otherwise |

- **Request:**

  ```xml
  <iq><query xmlns="admin:iq:rpc"><commandname>getauthtoken</commandname>
    <commandparams>
      <email>user@icewarp.local</email>
      <password>…</password>
      <digest></digest>
      <authtype>0</authtype>
      <persistentlogin>0</persistentlogin>
    </commandparams></query></iq>
  ```

- **Success** (correct password, enabled account):

  ```xml
  <result>
    <email>user@icewarp.local</email>
    <name><classname>TAccountName</classname><name>Given</name><surname>Family</surname></name>
    <avatartoken/>
    <authtoken>2FD16498F17BAF4688028BD198537CED</authtoken>
    <avatarurl>…</avatarurl>
  </result>
  ```

  A non-empty `<authtoken>` = bind success. (The `<name>` block is a free bonus —
  givenName/surname without a second call.)
- **Errors:**

  | uid                  | when                                          | latency | LDAP mapping |
  | -------------------- | --------------------------------------------- | ------- | ------------ |
  | `auth_login_invalid` | wrong password, **or** unknown account, **or** unknown domain | **tarpit ~25–30 s** | `LDAPResultInvalidCredentials` |
  | `account_disabled_2` | correct password but account is **disabled**  | **immediate** | `LDAPResultInvalidCredentials` |

  Wrong password and unknown account return the **same** uid — no account
  enumeration. The disabled-account case is the one fast, distinguishable
  failure. See [§8](#8-failed-bind--anti-brute-force-tarpit) for timeout
  guidance.

---

## 4. `getaccountsinfolist` — LDAP search (list / lookup)

- **sid required:** yes.
- **Parameters:**

  | element     | req | type / values | notes |
  | ----------- | --- | ------------- | ----- |
  | `domainstr` | yes | domain, e.g. `icewarp.local` | empty → `domain_parameter_empty` |
  | `filter`    | no  | wrapper, see below | server-side filter |
  | `offset`    | no  | int           | pagination start (default 0) |
  | `count`     | no  | int           | page size |

  `filter` is a **wrapper element**, not a flat value:

  ```xml
  <filter>
    <namemask>oidc*</namemask>   <!-- required inside filter; default "*" -->
    <typemask>0</typemask>       <!-- optional: restrict by accounttype -->
  </filter>
  ```

  - **`namemask` filters server-side** (the earlier "filter ignored" note was a
    wrong XML shape — it must be wrapped as `<filter><namemask>…`). It is a
    **case-insensitive glob** (`*`, `?`) matched against **both the login name
    and the display name** (`OIDC*`, `oidct*`, `*test*`, `ADMIN*` all match the
    same account). `*` returns everything.
  - `typemask` restricts to an `accounttype` (e.g. `0` = users, `7` = groups).
  - `planmask` / `servicemask` also exist (not needed by the bridge).
  - For exact LDAP filter semantics (e.g. `(mail=x)` vs `(uid=x)`), push a coarse
    `namemask` down and **post-filter in Go** — the glob can't express full LDAP
    matching rules.

- **Success:** `<result>` with repeated `<item>`, then `<offset>` and
  `<overallcount>` (use `overallcount` for paging):

  ```xml
  <result>
    <item>
      <name>OIDC Test</name>
      <email>oidctest@icewarp.local</email>
      <displayemail>oidctest@icewarp.local</displayemail>
      <accounttype>0</accounttype>
      <accountstate><classname>TAccountState</classname><state>0</state></accountstate>
      <admintype>0</admintype>
      <quota>…</quota><planid/><serviceinfo>…</serviceinfo>
    </item>
    …
    <offset>0</offset>
    <overallcount>3</overallcount>
  </result>
  ```

  | field          | meaning |
  | -------------- | ------- |
  | `name`         | display name (`u_name`) |
  | `email`        | primary address |
  | `displayemail` | shown address (usually same as `email`) |
  | `accounttype`  | `0` = user, `1` = mailing list, `7` = group, `8` = resource (also `2`–`6`: executable / notification / static route / catalog / list server). The built-in `public-folders` account is a type-`7` group. |
  | `accountstate/state` | **`0` = enabled, `1` = disabled** |
  | `admintype`    | `0` = normal, `1` = admin |

- **Errors:** `session_invalid`; `domain_parameter_empty` (empty `domainstr`).

---

## 5. `getaccountproperties` — read per-account properties

- **sid required:** yes.
- **Parameters:**

  | element              | req | type | notes |
  | -------------------- | --- | ---- | ----- |
  | `accountemail`       | yes | address | missing → `account_email_parameter_missing` |
  | `accountpropertylist`| yes | list of `<item><propname>X</propname></item>` | which props to read |
  | `accountpropertyset` | no  | — | property-set selector; omit |

- **Request / success:** see [§1 read item](#property-read-item--write-item).
  One response `<item>` per requested property.
- **Properties the bridge cares about:**

  | propname           | class           | meaning |
  | ------------------ | --------------- | ------- |
  | `a_vcard`          | `TAccountCard`  | **the contact card — the structured name the admin UI edits**: `firstname`, `lastname`, `middlename`, `title`, `suffix`, plus `fileas` (the "Display as" name) and `nickname` |
  | `u_mailbox`        | `TPropertyString` | local part (e.g. `oidctest`) |
  | `u_accountdisabled`| `TPropertyString` | `0` = enabled, `1` = disabled |
  | `u_name`           | `TPropertyString` | a display-name **string**, separate from the card (see note) |
  | `a_name`           | `TAccountName`  | givenName/surname split — **legacy/secondary** (see note) |
  | `u_groups`         | `TPropertyString` | **the user→groups reverse lookup**: a `;`-separated list of the group addresses the account belongs to (see note) |

  > **`u_groups` is the per-user group membership.** Reading it returns the
  > groups (type-7 accounts, e.g. the built-in `public-folders`) the user is a
  > member of, as a single `;`-separated string of full addresses with a trailing
  > `;` (e.g. `public-folders@icewarp.local;group1@icewarp.local;`). This is the
  > reverse of the per-group `GetAccountMemberInfoList` (§10.1) and means a
  > user's groups need **no** group enumeration — they come free with the
  > account's other properties in one `getaccountproperties` call. Read-only in
  > practice for the bridge (membership is provisioned in IceWarp).

  > **Names live in `a_vcard`, not `a_name`/`u_name`.** Verified from the admin
  > console (HAR capture, same build): opening a user's name editor reads
  > `a_vcard` (`TAccountCard`), and `firstname`/`lastname`/`fileas`/`nickname`
  > there are the values the UI shows. `a_name` and `u_name` are a *separate*
  > store that can hold stale, divergent values (e.g. card `John1`/`Doe1` while
  > `a_name` reads `John`/`Doe2`). The bridge maps LDAP `givenName`←`firstname`,
  > `sn`←`lastname`, and `cn`←`fileas` (falling back to `u_name`) — all from the
  > card.

- **Errors:** `account_invalid` (no such account); `session_invalid`;
  `account_email_parameter_missing`.

---

## 6. `setaccountproperties` — write per-account properties

> The write command is `setaccountproperties` — **not** `accountpropertyset`
> (which returns `invoker_commandname_invalid`).

- **sid required:** yes.
- **Parameters:**

  | element             | req | notes |
  | ------------------- | --- | ----- |
  | `accountemail`      | yes | target account |
  | `propertyvaluelist` | yes | list of write items (see [§1](#property-read-item--write-item)) |

- **Request** (disable an account):

  ```xml
  <iq sid="SID"><query xmlns="admin:iq:rpc"><commandname>setaccountproperties</commandname>
    <commandparams>
      <accountemail>user@icewarp.local</accountemail>
      <propertyvaluelist>
        <item>
          <apiproperty><propname>u_accountdisabled</propname></apiproperty>
          <propertyval><classname>TPropertyString</classname><val>1</val></propertyval>
        </item>
      </propertyvaluelist>
    </commandparams></query></iq>
  ```

- **Success / result semantics:** `<result>1</result>` = applied (an
  idempotent no-op write — setting the value it already has — still returns
  `1`). **`<result>0</result>` = the property was not applied** (e.g. unknown
  property name). Treat `result != 1` as a soft failure, not success.
- **Side effect:** writing `a_name` (given/surname) **recomposes `u_name`** into
  `"Given Family"`. (`a_name`/`u_name` are the legacy name store — see §5; the
  admin UI and the bridge write the structured name to `a_vcard` instead.)
- **Writing `a_vcard` is a full read-modify-write.** The admin console re-sends
  the **entire** `TAccountCard` — all ~70 fields, empties included — on every
  save (verified, HAR capture), so a partial write blanks the fields it omits.
  Always read the card with `getaccountproperties`, change only the wanted
  fields, and write the whole card back in one `setaccountproperties` item.
- **Errors:** `account_invalid`; `session_invalid`;
  `account_email_parameter_missing`.

---

## 7. `setaccountpassword` — password write-back (LDAP modify)

- **sid required:** yes.
- **Parameters:**

  | element        | req | type / values | notes |
  | -------------- | --- | ------------- | ----- |
  | `accountemail` | yes | address       | |
  | `ignorepolicy` | yes | `0` / `1`     | `1` bypasses the password policy |
  | `password`     | yes | new password  | |

- **Request:**

  ```xml
  <iq sid="SID"><query xmlns="admin:iq:rpc"><commandname>setaccountpassword</commandname>
    <commandparams>
      <accountemail>user@icewarp.local</accountemail>
      <ignorepolicy>0</ignorepolicy>
      <password>…</password>
    </commandparams></query></iq>
  ```

- **Success:** `<result>1</result>`. Verified end-to-end (change → re-bind with
  the new password via `getauthtoken` → restore).
- **Errors:**
  - `account_password_policy` — password fails policy and `ignorepolicy=0`
    (policy: mixed case + digit + special char, and must not contain the account
    name).
  - `account_invalid`; `session_invalid`.

---

## 8. `createaccount` — provision a test account (e2e fixture)

- **sid required:** yes.
- **Parameters:**

  | element            | req | notes |
  | ------------------ | --- | ----- |
  | `domainstr`        | yes | existing domain; empty → `domain_parameter_empty` |
  | `accountproperties`| yes | list of write items — **note the element name is `accountproperties`, not `propertyvaluelist`** |

  **Minimum required properties** inside `accountproperties`:

  | propname    | value      | omitted → error |
  | ----------- | ---------- | --------------- |
  | `u_mailbox` | local part | `account_mailbox_property_missing` |
  | `u_type`    | account type | `account_type_property_missing` |

  `u_type` selects the account type: `0` = user, `7` = group, `1` = mailing
  list, `8` = resource. Creating a **group** is just `createaccount` with
  `u_type=7`; manage its members with the commands in [§10](#10-groups--membership).

  Practically also set `u_name` (display string) here, set the structured name
  in `a_vcard` via a follow-up `setaccountproperties` (see §5/§6 — the card is a
  read-modify-write, so create first, then read and write it back), and set a
  password via this command or a follow-up `setaccountpassword`.

- **Request** (minimal viable create):

  ```xml
  <iq sid="SID"><query xmlns="admin:iq:rpc"><commandname>createaccount</commandname>
    <commandparams>
      <domainstr>icewarp.local</domainstr>
      <accountproperties>
        <item>
          <apiproperty><propname>u_mailbox</propname></apiproperty>
          <propertyval><classname>TPropertyString</classname><val>e2euser</val></propertyval>
        </item>
        <item>
          <apiproperty><propname>u_type</propname></apiproperty>
          <propertyval><classname>TPropertyString</classname><val>0</val></propertyval>
        </item>
      </accountproperties>
    </commandparams></query></iq>
  ```

- **Success:** `<result>1</result>`. The account appears in
  `getaccountsinfolist` immediately, enabled (`state=0`).
- **Errors:** `account_mailbox_property_missing`, `account_type_property_missing`,
  `domain_parameter_empty`, `session_invalid`, plus `account_password_policy`
  if you set a weak password in the same call.

---

## 9. `deleteaccounts` — tear down a test account (e2e fixture)

- **sid required:** yes.
- **Parameters:**

  | element       | req | notes |
  | ------------- | --- | ----- |
  | `domainstr`   | yes | domain of the accounts |
  | `accountlist` | yes | a `TPropertyStringList` of full addresses |

- **Request:**

  ```xml
  <iq sid="SID"><query xmlns="admin:iq:rpc"><commandname>deleteaccounts</commandname>
    <commandparams>
      <domainstr>icewarp.local</domainstr>
      <accountlist>
        <classname>tpropertystringlist</classname>
        <val>
          <item>e2euser@icewarp.local</item>
        </val>
      </accountlist>
    </commandparams></query></iq>
  ```

- **Success:** `<result>1</result>`; the account is gone from
  `getaccountsinfolist`.
- **Errors:** `session_invalid`; `domain_parameter_empty`.

---

## 10. Groups & membership

A **group** is an account with `accounttype` / `u_type` = `7`. Its lifecycle
reuses the ordinary account commands — there is no separate "group" command for
create/delete/rename:

| group operation        | command                              | how |
| ---------------------- | ------------------------------------ | --- |
| create group           | `createaccount` (§8)                 | `u_type=7`, plus `u_mailbox` and `u_name` |
| delete group           | `deleteaccounts` (§9)                | full address in the `accountlist` |
| list groups            | `getaccountsinfolist` (§4)           | `filter/typemask=7` |
| rename / display name  | `getaccountproperties` / `setaccountproperties` (§5/§6) | `u_name`, `a_vcard` |

**Membership is a separate store, keyed by the group's email** (the `who` /
`accountemail` parameter below). The same membership commands serve groups,
mailing lists and resources. The per-member rights (`default`, `recieve` —
*sic, misspelled on the server* — `post`, `digest`) are mailing-list semantics
and are **inert for plain groups** (they read back `0` regardless of what you
write).

### 10.1 `GetAccountMemberInfoList` — read members

- **sid required:** yes.
- **Parameters:**

  | element  | req | notes |
  | -------- | --- | ----- |
  | `who`    | yes | group address; unknown account → `account_invalid` |
  | `offset` | no  | pagination start (default 0) |
  | `count`  | no  | page size |
  | `filter` | no  | `<filter><namemask>…</namemask></filter>` — same case-insensitive glob as §4, filters members server-side |

- **Success:** repeated `<item>`, then `<offset>` and `<overallcount>` (page like §4):

  ```xml
  <result>
    <item>
      <val>johndoe@icewarp.local</val>   <!-- the member address -->
      <default>0</default><recieve>0</recieve><post>0</post><digest>0</digest>
      <params/>
    </item>
    <offset>0</offset>
    <overallcount>1</overallcount>
  </result>
  ```

  The member **address is in `<val>`** — there is no `<name>`/display field, so
  resolving member display names needs a separate `getaccountproperties` lookup.

### 10.2 `addaccountmembers` — add members

- **sid required:** yes.
- **Parameters:** `accountemail` (the group) + `members`, a `TPropertyMembers`
  list of `TPropertyMember` items.
- **Request:**

  ```xml
  <iq sid="SID"><query xmlns="admin:iq:rpc"><commandname>addaccountmembers</commandname>
    <commandparams>
      <accountemail>group1@icewarp.local</accountemail>
      <members>
        <classname>tpropertymembers</classname>
        <val>
          <item><classname>tpropertymember</classname><val>johndoe@icewarp.local</val><default>1</default></item>
        </val>
      </members>
    </commandparams></query></iq>
  ```

- **Success:** `<result>1</result>`. **Idempotent** — re-adding an existing
  member returns `1` and does not duplicate.
- **No validation of member addresses.** The server stores whatever string you
  send: a non-existent account (`ghost@icewarp.local`) is accepted and listed,
  and a **bracketed domain token** `[icewarp.local]` adds the *whole domain* as a
  member (this is what the admin UI's account-picker emits for a domain
  selection). The bridge should send only real, individual addresses.
- **Errors:** `account_invalid` (no such group), `session_invalid`.

### 10.3 `deleteaccountmembers` — remove specific members

Same shape as `addaccountmembers` (rights omitted). `<result>1</result>` on
success; removing an absent member is a no-op `1`.

```xml
<commandparams>
  <accountemail>group1@icewarp.local</accountemail>
  <members>
    <classname>tpropertymembers</classname>
    <val><item><classname>tpropertymember</classname><val>johndoe@icewarp.local</val></item></val>
  </members>
</commandparams>
```

### 10.4 `deleteAllAccountMembers` — clear members

- **Parameters:** `accountemail` + `filter/namemask` (`*` = all). Removes every
  member matching the mask. `<result>1</result>`.

### 10.5 `editaccountmembers` / `EditAllAccountMembersRights` — member rights

Set per-member (`editaccountmembers`) or all-member
(`EditAllAccountMembersRights`) rights flags (`default`, `recieve` *(sic)*,
`post`, `digest`). **Mailing-list only** — irrelevant to plain groups, where the
flags do not stick. Documented for completeness; the bridge does not need them.

### Caveats

- **Membership is not validated** — arbitrary / non-existent addresses and
  `[domain]` tokens are accepted (§10.2). Treat the member list as opaque
  strings, not verified accounts.
- **Adds are idempotent; rights flags are inert for groups.**
- **Deleting a group purges its membership** (verified: delete + recreate of the
  same address comes back empty).
- **Account create/delete is applied with a small async lag.** A single
  create-then-add is read-after-write consistent, but hammering one group address
  with rapid create/delete/add in a tight loop can briefly desync the member
  store (adds returning `result=1` without taking effect). For a bridge that
  doesn't churn the same address in a loop this is not a concern; if you do,
  poll/retry rather than assuming immediate consistency.

---

## Cross-cutting

### Session lifecycle

- `authenticate` mints a `sid`; attach it to every session command.
- The `sid` is invalidated by a server-managed idle/absolute timeout and by a
  server restart. The exact TTL is **not reliably introspectable** (the
  `*_sessiontimeout` config vars are for SMTP/IMAP protocol sessions, not the
  admin RPC sid), so **do not hard-code a TTL**.
- **Correct handling:** on any command that returns
  `<error uid="session_invalid"/>` — including a missing or wrong sid —
  re-`authenticate` and retry the command once. This is robust across builds and
  restarts.

### Failed-bind / anti-brute-force tarpit

- Both `getauthtoken` **and** `authenticate` apply an anti-brute-force delay
  before returning `auth_login_invalid` on bad credentials.
- Measured **24–30 s and progressive** — the delay grows with consecutive
  failures (24.1 s → 27.3 s → 29.4 s observed back-to-back). Treat ~21 s (an
  earlier single measurement) as a floor, not the worst case.
- The disabled-account fast-fail (`account_disabled_2`) is **not** tarpitted
  (~3 ms).
- **Client timeout for the bind path must comfortably exceed the worst case.**
  Use **≥ 60 s** per `getauthtoken` request, and account for the delay
  compounding under a burst of bad passwords. The non-bind admin commands are
  fast (single-digit ms) and can use a short timeout.

### Account enabled/disabled

- `accountstate/state` in `getaccountsinfolist`: `0` = enabled, `1` = disabled.
- Toggled by the `u_accountdisabled` property (`0`/`1`) via
  `setaccountproperties`; the change is reflected immediately in the list and in
  `getauthtoken` (disabled → `account_disabled_2`).

### `result` value semantics on writes

- `<result>1</result>` = command applied (idempotent no-op writes also return
  `1`).
- `<result>0</result>` = nothing applied — e.g. an unknown/invalid property name
  in `setaccountproperties`. The command still returns `type="result"`, so the
  bridge must check the `<result>` value, not just the `type`.

---

## Error-uid catalogue

| uid                                | command(s)                     | meaning | suggested LDAP result |
| ---------------------------------- | ------------------------------ | ------- | --------------------- |
| `auth_login_invalid`               | `getauthtoken`, `authenticate` | wrong password / unknown account / unknown domain (**tarpit**) | `InvalidCredentials` |
| `account_disabled_2`               | `getauthtoken`                 | correct password, account disabled (**immediate**) | `InvalidCredentials` |
| `session_invalid`                  | all session commands           | missing / expired / wrong `sid` | re-authenticate, retry |
| `account_invalid`                  | `getaccountproperties`, `set*`, `*accountmembers` (§10) | no such account / group | `NoSuchObject` |
| `account_email_parameter_missing`  | account commands               | `accountemail` omitted | `ProtocolError` (bridge bug) |
| `domain_parameter_empty`           | `getaccountsinfolist`, `create/deleteaccounts` | `domainstr` empty | `ProtocolError` (bridge bug) |
| `account_mailbox_property_missing` | `createaccount`                | no `u_mailbox` | — (fixture bug) |
| `account_type_property_missing`    | `createaccount`                | no `u_type` | — (fixture bug) |
| `account_password_policy`          | `setaccountpassword`, `createaccount` | weak password, `ignorepolicy=0` | `ConstraintViolation` |
| `iq_query_xmlns_invalid`           | any                            | `<query>` namespace ≠ `admin:iq:rpc` | — (bridge bug) |
| `invoker_commandname_invalid`      | any                            | unknown `commandname` | — (bridge bug) |

---

## Bridge command map (quick reference)

| LDAP op (from Keycloak)        | IceWarp command        | sid | key params |
| ------------------------------ | ---------------------- | --- | ---------- |
| `bind` (validate password)     | `getauthtoken`         | no  | `email`, `password`, `authtype=0` |
| `search` (list / lookup)       | `getaccountsinfolist`  | yes | `domainstr`, `filter/namemask`, `offset`, `count` |
| read/write name (given/surname/display) | `getaccountproperties` / `setaccountproperties` | yes | `accountemail`, `a_vcard` (`TAccountCard`, full read-modify-write) |
| enable/disable                 | `setaccountproperties` | yes | `accountemail`, `propertyvaluelist` (`u_accountdisabled`) |
| `modify userPassword`          | `setaccountpassword`   | yes | `accountemail`, `ignorepolicy`, `password` |
| e2e: create fixture            | `createaccount`        | yes | `domainstr`, `accountproperties` (`u_mailbox`, `u_type`) |
| e2e: delete fixture            | `deleteaccounts`       | yes | `domainstr`, `accountlist` (TPropertyStringList) |
| service-account login          | `authenticate`         | no  | `authtype=0`, `email`, `password` |
| `search` groups                | `getaccountsinfolist`  | yes | `domainstr`, `filter/typemask=7` |
| read group members             | `GetAccountMemberInfoList` | yes | `who`, `offset`, `count`, `filter/namemask` |
| add group members              | `addaccountmembers`    | yes | `accountemail`, `members` (TPropertyMembers) |
| remove group members           | `deleteaccountmembers` / `deleteAllAccountMembers` | yes | `accountemail`, `members` / `filter` |
| create group                   | `createaccount`        | yes | `domainstr`, `accountproperties` (`u_type=7`) |
| delete group                   | `deleteaccounts`       | yes | `domainstr`, `accountlist` |
