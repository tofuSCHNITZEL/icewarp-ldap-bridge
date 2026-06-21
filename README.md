# IceWarp LDAP Bridge

Bridges Keycloak's LDAP User Federation to the IceWarp REST API, so Keycloak can
use IceWarp as its identity source.

## Development

Local dev stack via Docker Compose: Postgres, Keycloak, and IceWarp.

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

| Service  | URL / Port            | Credentials         |
| -------- | --------------------- | ------------------- |
| Keycloak | http://localhost:8080 | admin / password    |
| IceWarp  | http://localhost:8081 | —                   |
| Postgres | localhost:5432        | postgres / password |

Keycloak stores its data in the `keycloak` database, created automatically on
first Postgres start.

### Keycloak realm

A `dev` realm is committed at `docker/keycloak/realms/dev-realm.json` and is
imported automatically the first time the stack starts (`start-dev
--import-realm`). On later starts the realm already exists in the database, so
the import is skipped and your admin-console changes are kept.

The realms directory is mounted into the container at
`/opt/keycloak/data/import`. After changing the realm in the admin console,
export it to persist the change back into the repo (`--users skip` leaves user
accounts out):

```bash
docker compose run --rm keycloak export \
  --dir /opt/keycloak/data/import --realm dev --users skip
```

This runs the export in a throwaway container against the same database, so it
doesn't collide with the running server (`exec` into the live container fails on
the management port). The file lands in `docker/keycloak/realms/dev-realm.json`.

To re-import an updated export, delete the realm first (or reset the Keycloak
database) — startup import never overwrites an existing realm.
