# IceWarp (dev stack notes)

Learnings about the IceWarp Server image and its `tool` CLI, gathered while
working the local dev stack. Scope is this image's admin and integration
surface, not a full product reference.

## The image

- Image: `icewarptechnology/icewarp-server:14` (build `14.3.0.3 RHEL8 x64`).
- Licensed product. The placeholder default in `.env.example` will not pull; a
  real image reference is required. With `ICEWARP_LICENSE` unset the container
  requests a 30-day trial automatically.
- Runs as `root` inside the container. Install dir is `/opt/icewarp`; config is
  `/etc/icewarp/icewarp.conf` (defines `IWS_INSTALL_DIR=/opt/icewarp`).
- Persistent data lives in the `icewarp_data` volume mounted at
  `/opt/icewarp-data` (`path.dat`, `status/`, mail store).
- Backing store is MariaDB (`icewarp-mariadb` service), not the bundled SQLite.
- The entrypoint waits for the **Laforge** document-preview service on startup
  and can't be told to skip it, so Laforge runs even if you never use previews.
- In our compose file, container port 80 is published on `localhost:8081`
  (web admin / webmail / REST API) and 443 on `8443`.

## Access

- Web admin console: <http://localhost:8081/admin/>
- Admin login: `admin@icewarp.local`, password from `ICEWARP_ADMIN_PASSWORD` in
  `.env` (see `.env.example`).
- Primary domain: `icewarp.local` (`ICEWARP_DOMAIN`).

### Two separate web apps

The same port serves two different UIs, and they share one login form — the URL
path decides which you get:

- **`/admin/`** — the admin console. User and domain management lives here, under
  **Management** → expand the `icewarp.local` domain → **Accounts**. This is where
  `tool` CLI changes show up; clicking an account exposes the same fields the CLI
  sets (`u_name`, password, the Disabled checkbox = `u_accountdisabled`, …).
- **`/webmail/`** — the WebClient (end-user mail UI). No account-management
  section by design; logging in here is the usual wrong turn when looking for
  user administration.

Bare `/admin` (no trailing slash) 302-redirects into `/admin/`.

## The `tool` CLI

IceWarp ships a command-line admin tool. Inside the container:

```bash
docker compose exec icewarp /opt/icewarp/tool.sh <command> <object> <args>
```

`tool.sh` is a thin wrapper that sources `/etc/icewarp/icewarp.conf` and execs
`/opt/icewarp/tool` (reports as `tool v4.0`). Built-in help:

```bash
docker compose exec icewarp /opt/icewarp/tool.sh help            # command list
docker compose exec icewarp /opt/icewarp/tool.sh help tutorial   # worked examples
docker compose exec icewarp /opt/icewarp/tool.sh help create     # per-command
```

### Commands

| Command  | Purpose                              |
| -------- | ------------------------------------ |
| `create` | create an object                     |
| `delete` | delete an object                     |
| `set`    | modify an object's variables         |
| `get`    | display an object's variables        |
| `check`  | validate object data                 |
| `import` / `export` | bulk account/domain CSV   |

Objects are `domain`, `account`, `remoteaccount`, `service`, `system`, etc.
Variables are prefixed by object type: `d_*` (domain), `u_*` (account),
`c_*` (system), `st_*` (service status).

> Note: the tutorial text shows `tool modify account ...`, but `modify` is **not**
> a real command — it falls through to generic help. The actual command is `set`.

### Account management

```bash
# create (under the existing domain)
tool.sh create account NAME@icewarp.local u_name "Full Name" u_password "PW" u_comment "..."

# list / inspect
tool.sh get account "*@icewarp.local" u_name
tool.sh get account NAME@icewarp.local u_comment u_accountdisabled

# modify
tool.sh set account NAME@icewarp.local u_comment "new comment"

# disable / re-enable  (1 = disabled, 0 = enabled)
tool.sh set account NAME@icewarp.local u_accountdisabled 1
tool.sh set account NAME@icewarp.local u_accountdisabled 0

# delete
tool.sh delete account NAME@icewarp.local
```

Useful account variables seen so far: `u_name`, `u_password`, `u_comment`,
`u_accountdisabled`. (`u_enable` does not exist — querying it errors.)

### Gotchas

- **Password policy** is enforced on create/set. A password needs mixed case,
  digit, and special char, and is rejected if it contains the account name.
  Failure exits non-zero with `Password policy violation.`
- Accounts must sit under an existing domain (`icewarp.local` here); creating an
  account in a missing domain fails.
- A couple of system accounts exist by default: `admin@icewarp.local` and
  `public-folders@icewarp.local`. There's also an internal
  `##internalservicedomain.icewarp.com##` domain — ignore it.
- Querying an unknown variable still prints the known ones but exits non-zero,
  so don't treat a non-zero exit as "command failed" without reading output.

## APIs & integration surface

Probed against the running on-prem image (`14.3.0.3`). Codes below are from
`curl` against `http://localhost:8081`.

### Not available on-prem

- **The public/cloud REST API is not here.** The Swagger at
  <https://www.icewarp.com/product/api/> (`api.icewarp.com/v2`) describes
  IceWarp **Cloud**. Its server URLs point at hosted IceWarp, and none of its
  paths resolve on-prem: `/v2/accounts`, `/api/v2/...`, `/api/v1/...` all return
  **404**. The `c_cloudapi_*` config vars (`c_cloudapi_hostname`,
  `c_cloudapi_autoconfigure`, `c_cloudapi_msr_url`) are about pointing this
  server *at* a cloud API, not exposing one — and they're empty here.
- **No working OAuth2 / OIDC provider.** `/.well-known/openid-configuration`
  → 404. An OAuth module *is* configured (`modules/liboauthmodule.so`, present
  on disk, routed at `/oauth/` in `config/webserver.dat`) and `c_system_oauth_*`
  token-expiry vars exist, but **every** request under `/oauth/*` returns
  **501 Not Implemented** — proper `POST /oauth/token` grant, `GET
  /oauth/authorize?...`, userinfo, jwks, all of them. A random path like
  `/zzz` returns 404, so `/oauth` is a *reserved-but-inert* prefix, not just
  missing. Treat IceWarp-as-OIDC-IdP as **not usable on this build**. It may be
  license/edition-gated; not confirmed.

### What is available

1. **HTTP admin RPC at `/icewarpapi/`** — the remotely callable admin API. It's
   the same XML-RPC the web admin console uses: POST `<iq>` stanzas in the
   `admin:iq:rpc` namespace, each carrying a `<commandname>` + `<commandparams>`.
   **No SSH or co-location needed** — any HTTP(S) client with admin credentials
   can drive it. Verified end-to-end against the running server (see "HTTP admin
   RPC" below). This supersedes the earlier assumption that admin operations
   required the local `tool` CLI.
   - Note: `GET /rpc/` is 404 (the `/rpc` → `/rpc/` 302 is just a redirect) and
     `admin/server/proxy.php?com=` is only a debug log/tunnel — `/icewarpapi/`
     is the real endpoint.
2. **The `tool` CLI** — equivalent automation for local/console use. Runs in the
   container, or against a remote server with `-r=admin:pass@host:controlport`.
   Same engine as the RPC; handy for scripting and one-offs, though `/icewarpapi/`
   is preferable for remote automation since it runs anywhere.
3. **Server-side PHP API library** (`html/_shared/api/*.php`: `api.php`,
   `account.php`, `domain.php`, `apitunnel.php`, `services.php`, …) — the object
   model the bundled web apps use in-process. Useful as a *catalogue* of
   available objects/commands, but it calls native pipe functions, so it is not
   something you invoke over the network from outside. Note: `idp.php`
   (`IceWarpServer.IDP`) is a **backup/archive file API** (`AddFiles`,
   `RestoreFiles`), *not* an identity provider — the name is misleading.
4. **WebClient API** — `/webmail/server/webmail.php` (200), the endpoint the
   webmail frontend calls; user-level operations behind a webmail session.
5. **Standard protocols** (the durable, version-independent integration points):
   - IMAP / POP / SMTP — credential validation and mail.
   - WebDAV / CalDAV / CardDAV — `/webdav/` (401), `/.well-known/caldav` and
     `/.well-known/carddav` (302 → real collection). Groupware data.
   - ActiveSync — `/Microsoft-Server-ActiveSync` (401). Autodiscover (401).
6. **Bundled OpenLDAP** — ships at `/opt/icewarp/ldap` but `slapd` is **not**
   running by default.

### HTTP admin RPC — verified flow

All calls are `POST /icewarpapi/` with `Content-Type: text/xml` and an `<iq>`
body. Verified against the running server.

**Authenticate → session id.** `authenticate` returns the `sid` as an attribute
on the response `<iq>`; put that `sid` on every subsequent stanza.

```xml
<iq><query xmlns="admin:iq:rpc"><commandname>authenticate</commandname>
  <commandparams><authtype>0</authtype>
    <email>admin@icewarp.local</email><password>…</password>
  </commandparams></query></iq>
<!-- → <iq type="result" sid="…"><result>1</result> -->
```

**Verify a user's credentials (no session needed).** `getauthtoken` with the
user's own email+password: correct → `<authtoken>…`; wrong → `<error
uid="auth_login_invalid"/>`. This is the credential-check primitive.

**List/search accounts.** `getaccountsinfolist` with `domainstr`, plus `filter`,
`offset`, `count` (real pagination/filtering). Each `<item>` has `name`, `email`,
and `accountstate.state` (the enabled/disabled flag).

**Read/write account properties.** `getaccountproperties` / `accountpropertyset`
for arbitrary `u_*` properties; `setaccountpassword` (`accountemail`,
`ignorepolicy`, `password`) for password changes. Create/delete via
`createaccount` / `deleteaccounts`.

**No usable account create/modify time.** The admin API exposes no timestamp on
any account surface — the property model has no date field at all.

The webmail WebClient API does return `ITM_CREATED` / `ITM_MODIFIED`, but on a
user's contact card, not the account: the modified time bumps on any card
edit/sync and not on account changes (password, enable/disable), so it is a poor
proxy for create/modify. And the bridge can't read it regardless — every webmail
session needs the user's own password, which the bridge never holds (it only
validates passwords at bind and discards them). The admin "open webmail" path
opens the admin's own mailbox and can't impersonate a user. **Not usable.**

## Dev test account

A non-admin test user for development:

- `oidctest@icewarp.local` / `Br1dge-Feasible-2026!`
