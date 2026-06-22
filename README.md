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

### Configuration

The IceWarp backend is configured via environment variables (defaults target the
dev stack):

| Variable                 | Default                         | Notes                                                              |
| ------------------------ | ------------------------------- | ------------------------------------------------------------------ |
| `ICEWARP_URL`            | `http://icewarp:80/icewarpapi/` | admin RPC endpoint                                                 |
| `ICEWARP_DOMAIN`         | `icewarp.local`                 | mail domain                                                        |
| `ICEWARP_ADMIN_EMAIL`    | `admin@<ICEWARP_DOMAIN>`        | service account; must be an IceWarp **admin**                      |
| `ICEWARP_ADMIN_PASSWORD` | *(required)*                    | no default; set it (the dev value is in `.env.example`)            |
| `LDAP_USER_BASE_DN`      | `ou=people,dc=icewarp,dc=local` | DN users are exposed under                                         |
| `LDAP_EMAIL_AS_UID`      | *(off)*                         | expose the primary email as the `uid`/RDN (Keycloak "Use email as username") |
| `LDAP_GROUP_ATTRIBUTE`   | `departmentNumber`              | multi-valued attribute carrying group memberships; empty disables it |
| `LOG_LEVEL`              | `info`                          | `debug` \| `info` \| `warn` \| `error`                             |
| `INTROSPECT_ICEWARP`     | *(off)*                         | a dir (or truthy) dumps raw IceWarp request/response bodies to disk |

Logging is `log/slog` to stderr. At `debug` the server logs one line per incoming
LDAP request and one per outgoing IceWarp RPC call.

### Attribute mapping

The bridge serves a fixed, **users-only** schema (no groups, no container
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
a *User Attribute LDAP mapper* for whichever you want; the rest are ignored.
Optional attributes appear only when the source field is non-empty.

| LDAP attribute        | IceWarp source                | notes                                       |
| --------------------- | ----------------------------- | ------------------------------------------- |
| `uid`                 | mailbox local part            | username; the RDN                           |
| `cn`                  | card `fileas` (→ `u_name`)    | display name; mandatory                     |
| `givenName`           | card `firstname`              | first name                                  |
| `sn`                  | card `lastname`               | last name                                   |
| `initials`            | card `middlename`             | middle name (optional)                      |
| `displayName`         | card `nickname`               | nickname (optional)                         |
| `generationQualifier` | card `suffix`                 | name suffix, e.g. Jr/III (optional)         |
| `personalTitle`       | card `title`                  | honorific, e.g. Herr/Dr (optional)          |
| `mail`                | primary address               | **rejected on modify** (rename unsupported) |
| `departmentNumber`    | `u_groups` (group local parts)| group memberships, multi-valued; **read-only**; attribute name set by `LDAP_GROUP_ATTRIBUTE` (optional) |
| `userPassword`        | `getauthtoken` / `setaccountpassword` | write-only (bind / password set)    |
| `entryUUID`           | derived from username         | stable federation link                      |

**Group memberships** are exposed as a multi-valued attribute (default
`departmentNumber`, set by `LDAP_GROUP_ATTRIBUTE`; empty disables it), each value
being a group's mailbox local part. It is sourced from the per-user `u_groups`
property, so it costs no extra IceWarp calls and needs no group tree. To surface
it in tokens, add a Keycloak *User Attribute LDAP mapper* (`departmentNumber` → a
user attribute, **Read Only**) plus a protocol/claim mapper. It is read-only — the
bridge never writes group membership, so keep the mapper read-only.

**Operations:** bind (validate a password by binding as the user's DN), search
(RFC 4515 filters — boolean, equality, presence, substring — post-filtered in Go),
add/modify/delete, and a Root DSE advertising paged results. ModifyDN/rename and
Compare are not supported (the underlying `gldap` server has no routes for them).

See [docs/keycloak.md](docs/keycloak.md) for Keycloak-specific federation notes
(sync modes, the missing create/modify timestamps).

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

| Service  | URL / Port            | Credentials                               |
| -------- | --------------------- | ----------------------------------------- |
| Keycloak | http://localhost:8080 | admin / password                          |
| IceWarp  | http://localhost:8081 | —                                         |
| Postgres | localhost:5432        | postgres / password                       |
| OpenLDAP | localhost:1389        | uid=admin,dc=icewarp,dc=local / password  |

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
