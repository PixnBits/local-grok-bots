#!/usr/bin/env bash
# Build local-grok-bots and lgb-permhook into LGB_OUT_DIR.
# Unprivileged. Does not fetch, install, or touch a running service.
#   LGB_REPO=. LGB_OUT_DIR=/var/tmp/lgb-build-placeholder bash deploy/build.sh
#   bash deploy/build.sh [repo] [out-dir]
set -euo pipefail
[[ ${EUID:-$(id -u)} -ne 0 ]] || { echo "run unprivileged, not root" >&2; exit 1; }

REPO=${LGB_REPO:-.}
OUT=${LGB_OUT_DIR:-/var/tmp/lgb-build-placeholder}
if [[ $# -ge 1 && -n ${1:-} ]]; then
  REPO=$1
fi
if [[ $# -ge 2 && -n ${2:-} ]]; then
  OUT=$2
fi

mkdir -p "$OUT"

build_one() {
  local pkg=$1 name=$2
  local dest="$OUT/$name"
  ( cd "$REPO" && go build -trimpath -buildvcs=false -o "$dest.tmp" "$pkg" )
  chmod 0755 "$dest.tmp"
  mv -f "$dest.tmp" "$dest"
  ( cd "$OUT" && sha256sum "$(basename "$dest")" > "$dest.sha256" )
  echo "built: $dest"
  cat "$dest.sha256"
}

build_one ./cmd/local-grok-bots local-grok-bots
build_one ./cmd/lgb-permhook lgb-permhook
