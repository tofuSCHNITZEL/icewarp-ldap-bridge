# IceWarp reference snapshot (local only)

A copy of the static, human-readable parts of the running IceWarp container,
kept here so the code can be explored offline — e.g. from the devcontainer,
which has no Docker access. Everything in this folder except this README is
**gitignored**: IceWarp is a licensed, proprietary product, so its files must
never be committed or published.

## Populate

Run on the **host**, with the stack up:

```bash
docker compose up -d icewarp
scripts/dump-icewarp-reference.sh
```

This copies a few subtrees out of the `icewarp` container into this folder.
Re-run it to refresh; edit the script to pull more paths.

## What lands here

| Path            | What it is                                                              |
| --------------- | ---------------------------------------------------------------------- |
| `src/`          | All IceWarp PHP source as a browsable tree (~6 MB). The API object model is at `src/html/_shared/api/`. |
| `webserver.dat` | HTTP routing / module mounts (e.g. the `/oauth/` route)                 |

Only PHP source is copied — not the 1.4 GB install dir, which is mostly AV
engines and compiled binaries with no source value. The config dir holds
keys/certs, so individual config files are pulled, never the whole directory.

See [docs/icewarp.md](../docs/icewarp.md) for what these mean and how the bridge
uses the live server.
