#!/usr/bin/env bash
set -euo pipefail
usage() {
  cat <<'HELP'
Access Broker 0.8.2 — local npm-pack installer
Usage: bash install.sh [--dry-run] [--force] [--openclaw-bin PATH]
  --dry-run            Verify package and print command; no installation
  --force              Explicitly trust source AND permit replacement; back up first
  --openclaw-bin PATH  Use an existing OpenClaw executable (or OPENCLAW_BIN)
  --help               Show this help without requiring OpenClaw
Does not configure TLS, Telegram, secrets, tool permissions, or restart Gateway.
OpenClaw itself owns installation/config records and capability-consent prompts.
HELP
}
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
DRY=0
FORCE=0
CLI=${OPENCLAW_BIN:-openclaw}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --dry-run) DRY=1; shift ;;
    --force) FORCE=1; shift ;;
    --openclaw-bin) (($# >= 2)) || fail '--openclaw-bin needs a path'; CLI=$2; shift 2 ;;
    *) fail "Unknown option: $1 (see --help)" ;;
  esac
done
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PACKAGE="$ROOT/releases/local-openclaw-ssh-broker-0.8.2.tgz"
[[ -f "$PACKAGE" && -f "$ROOT/SHA256SUMS" ]] || fail 'Incomplete release: package or SHA256SUMS missing'
command -v node >/dev/null 2>&1 || fail 'Node.js missing. Install the Node version supported by your OpenClaw first.'
command -v npm >/dev/null 2>&1 || fail 'npm missing. Install the npm supplied with your Node distribution.'
command -v "$CLI" >/dev/null 2>&1 || fail 'OpenClaw not found. Install OpenClaw first or pass --openclaw-bin /absolute/path/to/openclaw.'
# Baseline of the OpenClaw 2026.10.5 host used to prepare this distribution.
node -e 'const [a,b]=process.versions.node.split(".").map(Number); if(!((a===24&&b>=16)||(a===26&&b>=1)))process.exit(1)' || fail 'This installer baseline requires Node 24.16+ (24.x) or 26.1+ (26.x); follow your OpenClaw engine requirements too.'
if command -v sha256sum >/dev/null 2>&1; then
  (cd -- "$ROOT" && sha256sum --check SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd -- "$ROOT" && shasum -a 256 --check SHA256SUMS)
else
  fail 'Need sha256sum (Linux) or shasum (macOS) to verify release integrity.'
fi
CMD=("$CLI" plugins install "npm-pack:$PACKAGE")
if ((FORCE)); then
  printf '%s\n' 'WARNING: --force trusts this source and may replace an existing plugin. Back up your configuration and plugin first.' >&2
  CMD+=(--force)
fi
printf 'Command:'
printf ' %q' "${CMD[@]}"
printf '\n'
if ((DRY)); then
  printf '%s\n' 'Dry run only. No OpenClaw command was executed.'
  exit 0
fi
"${CMD[@]}"
printf '%s\n' 'Install command completed. Continue with INSTALL.md: configuration, HTTPS, tool policy and verification.'
