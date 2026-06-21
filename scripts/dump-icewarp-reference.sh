#!/usr/bin/env bash
# Copy IceWarp's readable source out of the running container into .icewarp-ref/
# for offline code exploration (e.g. from the devcontainer, which has no Docker
# access). Run on the HOST with the stack up:
#
#   docker compose up -d icewarp
#   scripts/dump-icewarp-reference.sh
#
# Copies only PHP source (~6 MB) plus webserver.dat — NOT the full 1.4 GB
# install dir, which is mostly AV engines and compiled binaries with no source
# value. The target is gitignored; IceWarp is proprietary, so its files must
# never be committed.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
dest="$repo_root/.icewarp-ref"

if ! docker compose ps --status running --services 2>/dev/null | grep -qx icewarp; then
  echo "icewarp container is not running. Start it first: docker compose up -d icewarp" >&2
  exit 1
fi

echo "copying PHP source -> src/ ..."
rm -rf "${dest:?}/src"
mkdir -p "$dest/src"
docker compose exec -T icewarp sh -c \
  'cd /opt/icewarp && find . -name "*.php" -type f -print0 | tar -cf - --null -T -' \
  | tar -xf - -C "$dest/src"

echo "copying webserver.dat ..."
docker compose cp icewarp:/opt/icewarp-data/config/webserver.dat "$dest/webserver.dat"

echo "done -> $dest"
