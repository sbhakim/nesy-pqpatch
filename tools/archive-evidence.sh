#!/usr/bin/env bash
# Archive and restore the two directories that hold irreplaceable experiment
# evidence but are deliberately excluded from git:
#
#   runs/                          -- run manifests + canonical decision traces
#   src/pqpatch/proposer/cache/    -- content-addressed model responses
#
# The cache is the determinism boundary: without it, no run reproduces offline
# and re-running costs real API spend. Both directories are gitignored, so a
# lost working tree loses the evidence. This script is the backup of record.
#
# Usage:
#   tools/archive-evidence.sh archive            # write a timestamped archive
#   tools/archive-evidence.sh list               # show archives
#   tools/archive-evidence.sh restore <file>     # restore from an archive
#   tools/archive-evidence.sh verify <file>      # check archive checksum
#
# Destination defaults to $HOME/pqpatch-evidence-archive; override with
# PQPATCH_ARCHIVE_DIR. Keep it OUTSIDE the repo (and ideally on backed-up
# storage or a cloud-synced folder).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_DIR="${PQPATCH_ARCHIVE_DIR:-$HOME/pqpatch-evidence-archive}"
RUNS_DIR="${PQPATCH_RUNS_DIR:-$REPO_ROOT/runs}"
CACHE_DIR="${PQPATCH_CACHE_DIR:-$REPO_ROOT/src/pqpatch/proposer/cache}"

count_files() { find "$1" -type f ! -name '.gitkeep' 2>/dev/null | wc -l | tr -d ' '; }

cmd_archive() {
  mkdir -p "$ARCHIVE_DIR"
  local n_runs n_cache stamp out
  n_runs=$(count_files "$RUNS_DIR")
  n_cache=$(count_files "$CACHE_DIR")
  if [ "$n_runs" -eq 0 ] && [ "$n_cache" -eq 0 ]; then
    echo "nothing to archive: runs/ and cache/ are both empty" >&2
    exit 1
  fi
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  out="$ARCHIVE_DIR/pqpatch-evidence-$stamp.tar.gz"
  tar -czf "$out" -C "$REPO_ROOT" \
      --exclude='__pycache__' \
      "$(realpath --relative-to="$REPO_ROOT" "$RUNS_DIR")" \
      "$(realpath --relative-to="$REPO_ROOT" "$CACHE_DIR")"
  sha256sum "$out" | awk '{print $1}' > "$out.sha256"
  cat > "$out.manifest" <<EOF
archived_utc   = $stamp
git_sha        = $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
git_dirty      = $(test -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" && echo yes || echo no)
run_dirs       = $(find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d ! -name '_latex' 2>/dev/null | wc -l | tr -d ' ')
run_files      = $n_runs
cache_payloads = $n_cache
sha256         = $(cat "$out.sha256")
EOF
  echo "archived -> $out"
  sed 's/^/    /' "$out.manifest"
}

cmd_list() {
  [ -d "$ARCHIVE_DIR" ] || { echo "no archive directory at $ARCHIVE_DIR"; exit 0; }
  ls -lh "$ARCHIVE_DIR"/pqpatch-evidence-*.tar.gz 2>/dev/null || echo "no archives in $ARCHIVE_DIR"
}

cmd_verify() {
  local f="${1:?usage: verify <archive.tar.gz>}"
  [ -f "$f.sha256" ] || { echo "missing $f.sha256" >&2; exit 1; }
  echo "$(cat "$f.sha256")  $f" | sha256sum -c -
}

cmd_restore() {
  local f="${1:?usage: restore <archive.tar.gz>}"
  [ -f "$f" ] || { echo "no such archive: $f" >&2; exit 1; }
  if [ -f "$f.sha256" ]; then cmd_verify "$f"; fi
  echo "restoring into $REPO_ROOT (existing files with the same path are overwritten)"
  tar -xzf "$f" -C "$REPO_ROOT"
  echo "runs files:  $(count_files "$RUNS_DIR")"
  echo "cache files: $(count_files "$CACHE_DIR")"
  echo
  echo "Now confirm reproducibility:  PQPATCH_OFFLINE=1 python -m pqpatch.eval.tables"
}

case "${1:-}" in
  archive) cmd_archive ;;
  list)    cmd_list ;;
  verify)  shift; cmd_verify "$@" ;;
  restore) shift; cmd_restore "$@" ;;
  *) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
