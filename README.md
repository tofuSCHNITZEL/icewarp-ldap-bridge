# IceWarp LDAP Bridge

Bridges Keycloak's LDAP User Federation to the IceWarp admin RPC API, so Keycloak
can use IceWarp as its identity source. The bridge speaks LDAP to clients
(bind/search/add/modify/delete) and translates each request into IceWarp account
operations.

## Setup

`cmd/ldap-bridge` is the server: it speaks LDAP to clients and translates each
request into IceWarp admin RPC operations.

```bash
go build -o bin/ldap-bridge ./cmd/ldap-bridge
./bin/ldap-bridge                      # listens on :3389

# or run directly
go run ./cmd/ldap-bridge -addr :3391   # custom listen address
```

`scripts/run-bridge.sh` wraps this: it loads `.env`, prints the effective
(non-secret) config, and starts the bridge.

`ldap-bridge --help` is the authoritative reference for the flags and
environment variables; the table below mirrors it for convenience.

### Running as a systemd service

systemd is Linux-only, so `/usr/local/bin/ldap-bridge` must be a Linux binary.
`go build` targets the OS/arch it runs on, so building on Windows or macOS
produces a binary systemd can't execute — cross-compile for Linux instead:

```bash
GOOS=linux GOARCH=amd64 go build -o bin/ldap-bridge ./cmd/ldap-bridge
```

(on Windows/PowerShell: `$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o bin/ldap-bridge ./cmd/ldap-bridge`)

Example unit running the built binary, reading config from an env file:

```ini
# /etc/systemd/system/ldap-bridge.service
[Unit]
Description=IceWarp LDAP Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/ldap-bridge/ldap-bridge.env
ExecStart=/usr/local/bin/ldap-bridge -addr :3389
Restart=on-failure
RestartSec=5s
User=ldap-bridge
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`/etc/ldap-bridge/ldap-bridge.env` holds the `ICEWARP_*`/`LDAP_*` variables from
the table below (same format as `.env`); keep it `chmod 600`, since it carries
`ICEWARP_ADMIN_PASSWORD`. `DynamicUser=yes` runs the service as an ephemeral
unprivileged user; drop it (and set a real `User=`) if the env file needs
group-based access instead. `AmbientCapabilities=CAP_NET_BIND_SERVICE` is only
needed if `-addr` binds a privileged port (<1024).

Alternatively, skip the env file by removing `EnvironmentFile=` and set the variables directly in the unit with
`Environment=` (one variable per line, so no quoting/escaping surprises with
special characters):

```ini
Environment=ICEWARP_URL=http://icewarp:80/icewarpapi/
Environment=ICEWARP_DOMAIN=icewarp.local
Environment=ICEWARP_ADMIN_EMAIL=admin@icewarp.local
Environment=ICEWARP_ADMIN_PASSWORD=changeme
```

Since the unit file itself then carries `ICEWARP_ADMIN_PASSWORD`, restrict it
with `chmod 600` (unit files under `/etc/systemd/system/` are root-owned by
default, but double-check) and prefer `EnvironmentFile=` when the secret needs
to be managed separately from the unit (e.g. deployed/rotated independently).

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ldap-bridge
journalctl -u ldap-bridge -f   # follow logs
```

### Configuration

The IceWarp backend is configured via environment variables (defaults target the
dev stack):

| Variable                           | Default                         | Notes                                                                                              |
| ---------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------- |
| `ICEWARP_URL`                      | `http://icewarp:80/icewarpapi/` | admin RPC endpoint                                                                                 |
| `ICEWARP_DOMAIN`                   | `icewarp.local`                 | mail domain                                                                                        |
| `ICEWARP_ADMIN_EMAIL`              | `admin@<ICEWARP_DOMAIN>`        | service account; must be an IceWarp **admin**                                                      |
| `ICEWARP_ADMIN_PASSWORD`           | _(required)_                    | no default; set it (the dev value is in `.env.example`)                                            |
| `LDAP_USER_BASE_DN`                | `ou=people,dc=icewarp,dc=local` | DN users are exposed under                                                                         |
| `LDAP_EMAIL_AS_UID`                | _(off)_                         | expose the primary email as the `uid`/RDN (Keycloak "Use email as username")                       |
| `LDAP_GROUP_BASE_DN`               | `ou=groups,dc=icewarp,dc=local` | serve groups as LDAP entries + add `memberOf` to users (Keycloak Group mapper); empty disables it  |
| `LDAP_GROUP_INCLUDE_MAILING_LISTS` | _(off)_                         | also expose IceWarp mailing lists (accounttype 1) as LDAP groups, alongside groups (accounttype 7) |
| `LDAP_ALLOW_ANONYMOUS_READS`       | _(off)_                         | serve searches on connections without a bind (anonymous read access)                               |
| `CACHE_REFRESH_INTERVAL`           | `10m`                           | how often the cached directory snapshot is refreshed; `0`/`off` serves every read from IceWarp     |
| `LOG_LEVEL`                        | `info`                          | `debug` \| `info` \| `warn` \| `error`                                                             |
| `INTROSPECT_ICEWARP`               | _(off)_                         | a dir (or truthy) dumps raw IceWarp request/response bodies to disk                                |

Logging is `log/slog` to stderr. At `debug` the server logs one line per incoming
LDAP request and one per outgoing IceWarp RPC call.

**Cached directory snapshot.** The IceWarp API is slow and an LDAP subtree search
would otherwise cost one call per user, so the bridge keeps the whole directory
(users, their names and group memberships, and group members) in memory and
refreshes it every `CACHE_REFRESH_INTERVAL` in the background. Searches are
answered from that snapshot; binds always go to IceWarp (credentials are never
cached), and writes through the bridge update the snapshot immediately. A change
made _outside_ the bridge becomes visible at the next refresh — a lookup of an
account the snapshot doesn't know still falls through to IceWarp, so brand-new
accounts are found right away. If a refresh fails the previous snapshot keeps
serving rather than failing searches (which Keycloak could read as mass deletion).

**No create/modify timestamps — use full sync.** IceWarp exposes no account
creation or modification time the bridge can serve (see `docs/icewarp.md`), so
entries carry no `createTimestamp`/`modifyTimestamp`. Keycloak's _Periodic Changed
Users Sync_ relies on `modifyTimestamp` to find changed accounts and would sync
nothing — configure the LDAP federation with **Periodic Full Sync** instead.

### Attribute mapping

The bridge serves a fixed schema of user and group entries (no other container
entries): each account is one entry at `uid=<username>,<LDAP_USER_BASE_DN>` (e.g.
`uid=jdoe,ou=people,dc=icewarp,dc=local`) with objectClasses `top`, `person`,
`organizationalPerson`, `inetOrgPerson`. The `uid` RDN is the key — on the IceWarp
backend it is the mailbox local part.

Set `LDAP_EMAIL_AS_UID` to expose the **primary email** as the `uid`/RDN instead
(`uid=jdoe@icewarp.local,ou=people,…`). Use this when Keycloak's federation has
**"Use email as username"** enabled: Keycloak then expects the RDN to be the
email, and a mismatch makes it issue a rename (ModifyDN) the bridge can't serve —
the connection drops and the edit is lost. The `entryUUID` (the federation link)
is unaffected, so the toggle doesn't re-link existing users.

Each entry carries these attributes (lower-cased on the wire). The name parts come
from the IceWarp `a_vcard` contact card and are **read/write** — in Keycloak, add
a _User Attribute LDAP mapper_ for whichever you want; the rest are ignored.
Optional attributes appear only when the source field is non-empty. The optional
name parts use the IceWarp field names (`middlename`/`nickname`/`suffix`) rather
than near-equivalent inetOrgPerson attributes, so each mapper is a 1:1 pass-through;
the standard `givenName`/`sn`/`cn`/`mail`/`uid` set is kept for the load-bearing
fields.

| LDAP attribute  | IceWarp source                                                 | notes                                                                                                 |
| --------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `uid`           | mailbox local part (or primary email with `LDAP_EMAIL_AS_UID`) | username; the RDN                                                                                     |
| `cn`            | card `fileas` (→ `u_name`)                                     | display name; mandatory                                                                               |
| `givenName`     | card `firstname`                                               | first name                                                                                            |
| `sn`            | card `lastname`                                                | last name                                                                                             |
| `middlename`    | card `middlename`                                              | middle name (optional)                                                                                |
| `nickname`      | card `nickname`                                                | nickname (optional)                                                                                   |
| `suffix`        | card `suffix`                                                  | name suffix, e.g. Jr/III (optional)                                                                   |
| `personalTitle` | card `title`                                                   | honorific, e.g. Herr/Dr (optional); standard name kept — LDAP `title` means _job_ title               |
| `mail`          | primary address                                                | **rejected on modify** (rename unsupported)                                                           |
| `memberOf`      | `u_groups` (group DNs)                                         | group memberships as group DNs, multi-valued; **read-only**; present when `LDAP_GROUP_BASE_DN` is set |
| `userPassword`  | `getauthtoken` / `setaccountpassword`                          | write-only (bind / password set)                                                                      |
| `entryUUID`     | derived from username                                          | stable federation link                                                                                |

### Groups

The bridge exposes IceWarp groups (accounttype 7) read-only as LDAP entries
(`LDAP_GROUP_BASE_DN`, default `ou=groups,dc=icewarp,dc=local`): each group is an
entry (`cn=<group>,<base>`, objectClass `groupOfNames`, `member` = user DNs) and
each user entry gains a `memberOf` of group DNs. Point a Keycloak _Group LDAP
mapper_ at the base DN to import them as Keycloak **groups** (hierarchy, role
mappings); for a plain group claim, add a _Group Membership_ protocol mapper on
top. Set the env var empty to disable groups entirely.

Set `LDAP_GROUP_INCLUDE_MAILING_LISTS` to also expose IceWarp mailing lists
(accounttype 1) the same way, alongside groups; off by default. The IceWarp
display name of each group or mailing list is exposed as its LDAP `cn`,
`description`, and `displayName`; `cn` falls back to the mailbox local part if
the display name is empty, while `description` and `displayName` are omitted.
The group `uid` is always the mailbox local part (the former `cn` value),
regardless of `LDAP_EMAIL_AS_UID`. Group DNs and `memberOf` references still use
the mailbox local part
(`cn=<mailbox>,<group base DN>`) and remain stable when the display name changes.

**Use the mapper's `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` retrieve strategy** (the
Keycloak default). It lines up with IceWarp's native lookups, so no operation
scans the whole user list. `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE` also works,
but it lists a group's members via a user search (`memberOf=<group>`); the bridge
pushes that down to the group's member list, so the common case stays cheap, yet
any query that bypasses the pushdown enriches every user — slow on a large
directory. There is no such pitfall with `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE`.

A group entry (`cn=<group>,<LDAP_GROUP_BASE_DN>`) carries these attributes:

| LDAP attribute | IceWarp source                             | notes                                                                          |
| -------------- | ------------------------------------------ | ------------------------------------------------------------------------------ |
| `objectClass`  | fixed                                      | `top`, `groupOfNames`                                                          |
| `cn`           | group mailbox local part                   | the RDN                                                                        |
| `member`       | group members (`GetAccountMemberInfoList`) | member user DNs (`uid=<user>,<LDAP_USER_BASE_DN>`); omitted for an empty group |
| `entryUUID`    | derived from the group name                | stable; namespaced so it never collides with a user's                          |

Groups are **read-only** — the bridge never provisions group membership, so keep
the Keycloak mapper read-only.

**Browsing above `LDAP_USER_BASE_DN`/`LDAP_GROUP_BASE_DN`.** A search based at
their shared parent DN (or an empty base DN) lists them as `organizationalUnit`
entries, so an LDAP browser can be pointed at the org DN (e.g.
`dc=icewarp,dc=local`) or connected with no base DN at all and still see
"people"/"groups" as subordinate folders to expand — there is no backing data
for these entries beyond the DN itself.

**Operations:** bind (validate a password by binding as the user's DN), search
(RFC 4515 filters — boolean, equality, presence, substring — post-filtered in Go),
add/modify/delete, and a Root DSE advertising paged results. ModifyDN/rename and
Compare are not supported (the underlying `gldap` server has no routes for them).

## Development

Local dev stack via Docker Compose: Postgres, Keycloak, IceWarp, and OpenLDAP.

1. Copy the env template:

   ```bash
   cp .env.example .env
   ```

2. Set `ICEWARP_IMAGE` in `.env` to the official IceWarp Server image (licensed
   product — the placeholder default will not pull).

3. Start the stack:

   ```bash
   docker compose up -d
   ```

### Services

| Service  | URL / Port            | Credentials                              |
| -------- | --------------------- | ---------------------------------------- |
| Keycloak | http://localhost:8080 | admin / password                         |
| IceWarp  | http://localhost:8081 | —                                        |
| Postgres | localhost:5432        | postgres / password                      |
| OpenLDAP | localhost:1389        | uid=admin,dc=icewarp,dc=local / password |

OpenLDAP is seeded on first start from `docker/ldap/ldifs/` with a small org tree
(`ou=people`, `ou=groups`) and two test users (`jdoe`, `asmith`, both with
password `password`) using the stock LDAP schema. Keycloak stores its data in the
`keycloak` database, created automatically on first Postgres start.

### Devcontainer

A VS Code devcontainer is committed at `.devcontainer/devcontainer.json`. It adds
a `devcontainer` service to the same compose project (via
`docker-compose.devcontainer.yaml`) and ships Go plus the Claude Code CLI, so you
can develop the bridge inside the stack. "Reopen in Container" brings up the other
services automatically.

Inside the container, reach the services by name on their **container** ports, not
`localhost`:

| Service  | From the devcontainer  | From the host         |
| -------- | ---------------------- | --------------------- |
| Keycloak | `http://keycloak:8080` | http://localhost:8080 |
| IceWarp  | `http://icewarp:80`    | http://localhost:8081 |
| Postgres | `postgres:5432`        | localhost:5432        |

### Keycloak realm

A `dev` realm is committed at `docker/keycloak/realms/dev-realm.json` and is
imported automatically the first time the stack starts (`start-dev
--import-realm`). On later starts the realm already exists in the database, so the
import is skipped and your admin-console changes are kept.

The realms directory is mounted into the container at
`/opt/keycloak/data/import`. After changing the realm in the admin console, export
it to persist the change back into the repo (`--users skip` leaves user accounts
out):

```bash
docker compose run --rm keycloak export \
  --dir /opt/keycloak/data/import --realm dev --users skip
```

This runs the export in a throwaway container against the same database, so it
doesn't collide with the running server (`exec` into the live container fails on
the management port). The file lands in `docker/keycloak/realms/dev-realm.json`.

To re-import an updated export, delete the realm first (or reset the Keycloak
database) — startup import never overwrites an existing realm.

### Tests

There are three suites. The two e2e suites are gated behind build tags, so the
unit suite stays dependency-free. `-count=1` on the e2e suites disables the test
cache (they depend on external server state).

#### 1. Unit tests

No external dependencies — run anywhere:

```bash
go test ./...
```

#### 2. LDAP e2e — `test/e2e/`, tag `e2e_ldap`

Drives a live LDAP server over the wire, asserting the protocol behaviour
(bind/search/CRUD/Root DSE). Because all LDAP logic lives in the server, the same
suite runs against **the bridge (either backend)** or a stock **OpenLDAP**; point
`LDAP_E2E_*` at the target (see `test/e2e/config_test.go` for the variables). The
bind account must be a user DN under the base DN (`uid=admin,ou=people,…`, not the
root).

```bash
# against the bridge with the in-memory backend (seeded admin / "password");
# no live IceWarp needed
go run ./cmd/ldap-bridge --use-in-memory-dummy &
LDAP_E2E_URL=ldap://localhost:3389 \
  LDAP_E2E_ADMIN_DN=uid=admin,ou=people,dc=icewarp,dc=local \
  LDAP_E2E_ADMIN_PASSWORD=password \
  go test -tags e2e_ldap -count=1 ./test/e2e/...

# against the bridge with the IceWarp backend (live IceWarp; bind as a real
# account — the wrong-password test hits IceWarp's ~25-30s tarpit). Load the
# dev credentials from .env first so the bridge and the bind share them:
set -a; source .env; set +a
go run ./cmd/ldap-bridge &
LDAP_E2E_URL=ldap://localhost:3389 \
  LDAP_E2E_ADMIN_DN=uid=admin,ou=people,dc=icewarp,dc=local \
  LDAP_E2E_ADMIN_PASSWORD="$ICEWARP_ADMIN_PASSWORD" \
  go test -tags e2e_ldap -count=1 -timeout 300s ./test/e2e/...

# against the reference OpenLDAP (docker compose up -d ldap)
LDAP_E2E_URL=ldap://ldap:389 \
  LDAP_E2E_ADMIN_DN=uid=admin,dc=icewarp,dc=local \
  LDAP_E2E_ADMIN_PASSWORD=password \
  go test -tags e2e_ldap -count=1 ./test/e2e/...
```

#### 3. IceWarp client e2e — `internal/icewarp/`, tag `e2e_icewarp`

Exercises the IceWarp admin RPC client directly against a live IceWarp instance
(auth, account CRUD, the `a_vcard` name round-trip). Connection defaults target
the dev stack (reachable as `icewarp:80` from the devcontainer), but the admin
password has no default — load it from `.env` (the suite skips if it's unset).
Override any of these via `ICEWARP_*`.

```bash
set -a; source .env; set +a
go test -tags e2e_icewarp -count=1 ./internal/icewarp/
```
