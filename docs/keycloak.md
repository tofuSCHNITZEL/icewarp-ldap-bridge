# Keycloak LDAP federation (what the bridge must serve)

What Keycloak's **LDAP User Federation** provider sends over the wire, and the
minimum an LDAP server must implement to be a working federation source for it.
Gathered by reading Keycloak's source; scope is the bridge, not a full
reference.

Source (in the gitignored `keycloak/` reference checkout):

- `federation/ldap/.../idm/store/ldap/LDAPOperationManager.java` — issues the
  actual JNDI/LDAP operations.
- `federation/ldap/.../idm/store/ldap/LDAPContextManager.java` — connection and
  bind setup, StartTLS.
- `federation/ldap/.../idm/store/LDAPIdentityStore.java` — capability probing,
  password updates, rename decisions.

Line numbers below are from that checkout and may drift with the Keycloak
version; treat them as pointers, not anchors.

## Connection model

- Keycloak authenticates **all normal operations** as the configured admin /
  service-account DN (`Context.SECURITY_PRINCIPAL` / `SECURITY_CREDENTIALS`),
  set in `LDAPContextManager.setAdminConnectionAuthProperties` (~120–143).
- **User authentication is a separate bind on a separate connection.**
  `LDAPOperationManager.authenticate` (~486–583) opens a fresh context, sets the
  user's DN + password, and triggers the bind via `reconnect(...)` (~533). A
  successful bind = valid credentials; an error = rejected.
- The connection is LDAPv3, simple bind. StartTLS is optional (see below).

## Operations Keycloak uses

### Core — needed for a functioning federation

| Operation | Keycloak entry point | What the server must do |
| --------- | -------------------- | ----------------------- |
| **Bind (admin)** | `LDAPContextManager` (~120–143) | Authenticate the service account; allow it to read/search (and write, if provisioning). |
| **Bind (user)** | `LDAPOperationManager.authenticate` (~486–583) | Validate a user's password by binding as their DN. |
| **Root DSE read** | `LDAPIdentityStore.queryServerCapabilities` (~312–345) | Answer a base-scoped search with an **empty base DN**, returning exactly one entry whose `supportedControl` / `supportedExtension` / `supportedFeatures` advertise capabilities. Keycloak uses this to decide whether it may page. |
| **Search** | `LDAPOperationManager.search` (~254–292) | Honor `SUBTREE`, `ONELEVEL` and `OBJECT` scopes and RFC 4515 filters — including compound `(&...)`, `(\|...)`, `(!...)`, equality, presence `(attr=*)` and substring `(attr=a*b*)`. Return requested attributes. |
| **Paged search** | `LDAPOperationManager.searchPaginated` (~294–366) | Accept the **Paged Results control** (`1.2.840.113556.1.4.319`, RFC 2696) and return results across pages with a cookie. Only used when pagination is enabled in config and a limit is set. |
| **Add** | `LDAPOperationManager.createSubContext` (~636–689) | Create entries (`createSubcontext`) when Keycloak provisions users/groups (import/write modes). |
| **Modify** | `LDAPOperationManager.modifyAttributes` (~585–634) | Apply `REPLACE` / `ADD` / `REMOVE` attribute modifications. |
| **Password update** | `LDAPIdentityStore.updatePassword` (~359–403) | Default path: `REPLACE` the `userPassword` attribute (OpenLDAP). Active Directory path replaces `unicodePwd` (UTF‑16LE, quoted). |

Filters are built dynamically by `LDAPQueryConditionsBuilder`; a typical user
lookup is `(&(objectClass=inetOrgPerson)(uid=jdoe))` and enumeration uses
presence/substring filters over the users base DN.

### Conditional — only in narrow cases

| Operation | Keycloak entry point | When |
| --------- | -------------------- | ---- |
| **ModifyDN / rename** | `LDAPOperationManager.renameEntry` → `context.rename` (~195–242) | Only when an attribute used in the RDN (e.g. the username) changes; gated by `LDAPIdentityStore.checkRename`. |
| **Delete** | `LDAPOperationManager.removeEntry` (~158–183) | Write-back deletion; recursively unbinds children first. |
| **StartTLS** | `LDAPContextManager.startTLS` (~103–117) | Only if `startTls=true`. |
| **Password Modify extended op (RFC 3062)** | `LDAPOperationManager.passwordModifyExtended` (~733–742) | Only if `useExtendedPasswordModifyOp=true`; otherwise the attribute path above is used. |

### Not used

- **Compare** — no compare operations in the federation code.
- **Enumeration / `listBindings`** — used only internally for recursive delete,
  never for browsing.

## Minimum an LDAP server must implement

To back Keycloak federation in the common read + authenticate configuration:

1. **LDAPv3 simple bind** — for the service account and for per-user password
   checks.
2. **Search** with `SUBTREE` / `ONELEVEL` / `OBJECT` scopes and RFC 4515
   filters (boolean operators, equality, presence, substring), returning the
   requested attributes.
3. **A Root DSE** (empty base, base scope) returning one entry with
   `supportedControl`. If it advertises the paged-results control, Keycloak will
   page; if not, it falls back to unpaged searches.
4. **Paged Results control** (`1.2.840.113556.1.4.319`) if you advertise it.

For write-back (sync to LDAP / provisioning) additionally:

5. **Add**, **Modify** (`REPLACE`/`ADD`/`REMOVE`), and **Delete**.
6. **Password update** via `REPLACE userPassword`.
7. **ModifyDN** if usernames (RDNs) can change.

## How this maps to the bridge

The bridge is built on `gldap`, which covers bind, search, add, modify and
delete — all the core operations above. Four gaps to be aware of:

- **No ModifyDN or Compare routes** in `gldap` v0.1.14, so the bridge cannot
  serve a rename. Keycloak only renames on RDN changes; configuring the RDN to
  a stable attribute avoids it. If Keycloak has **"Use email as username"**
  enabled it expects the RDN to be the email — set `LDAP_EMAIL_AS_UID` so the
  bridge's `uid`/RDN matches and no rename is attempted.
- **Search filters are matched on identity attributes** (`uid`, `mail`,
  `objectClass`, `entryUUID`). The structured name lives in each account's
  `a_vcard` card, which the bridge reads only for the entries a search actually
  returns — not for every account on every search (so a single-user lookup
  doesn't read the whole directory's cards). A filter on a name-only attribute
  (`sn`, `givenName`, …) therefore won't match server-side; Keycloak filters
  only on identity attributes, so this isn't a limitation for it.
- **Paged results** are advertised in our Root DSE, but the server returns the
  full result set in a single response. go-ldap's `SearchWithPaging` aggregates
  and stops cleanly, so paged clients still get every entry.
- **No `createTimestamp` / `modifyTimestamp`.** The IceWarp admin RPC exposes no
  account create/modify time (not in `getaccountsinfolist`, `getaccountproperties`,
  or the `a_vcard` card), so the bridge can't emit those operational attributes.
  Keycloak auto-creates "creation date" and "modification date" mappers — delete
  or ignore them; they resolve to nothing. More importantly, **"Sync changed
  users" depends on `modifyTimestamp`** and so can't work — use **"Sync all
  users"** instead. (Faking a value is worse: `modifyTimestamp = now` would make
  every sync think all users changed.)

The attributes each entry exposes — and which IceWarp `a_vcard` field backs
each — are documented in the [README attribute-mapping table](../README.md#attribute-mapping).
Configure a Keycloak *User Attribute LDAP mapper* for whichever optional name
parts (`initials`, `displayName`, `generationQualifier`, `personalTitle`) you
want; the rest are ignored.

### Groups

The bridge serves IceWarp groups (accounttype 7) read-only as LDAP entries
(`LDAP_GROUP_BASE_DN`, default `ou=groups,dc=icewarp,dc=local`), sourced from the
per-group member list and the per-user `u_groups` property. Groups become entries
(`cn=<group>,<base>`, `groupOfNames`, `member` = user DNs) and users gain
`memberOf` (group DNs). Point a Keycloak *Group LDAP Mapper* at the base DN to
import real Keycloak groups; for a plain group claim, add a *Group Membership*
protocol mapper on top.

- **Membership resolution** — the mapper's *User Groups Retrieve Strategy* picks
  the source: `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` (default) searches groups for
  `member=<userDN>`; `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` reads the user's
  `memberOf` (set *Member-Of LDAP Attribute* = `memberOf`). Prefer
  `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` — it maps onto IceWarp's native lookups and
  never scans the whole user list (see the README *Groups* section). A user's
  group membership is resolved at **sync/login**, not on admin detail view, so
  trigger a user sync after wiring the mapper.
- **Read-only** — configure the mapper read-only; a writable group mapper would
  silently no-op (same as the read-only user-attribute gotcha).
- **Empty groups** are emitted without a `member` attribute (`groupOfNames`
  formally requires one); enable "Ignore Missing Groups" if that matters.

The e2e suite in `test/e2e/` exercises the core operations against both a real
OpenLDAP and the bridge; see `ldap_keycloak_test.go`.
