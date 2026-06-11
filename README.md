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
first Postgres start. Realm exports placed in `docker/keycloak/realms/` are
imported on startup (`--import-realm`).
