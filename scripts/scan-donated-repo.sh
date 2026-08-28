#!/usr/bin/env bash
# Scan a candidate repository for secrets before adopting it into the org.
#
# Scans the FULL git history, not just the working tree. A key deleted in a
# later commit is still in history and still readable by anyone who clones the
# repo, so a working-tree-only scan is worthless for this purpose.
#
# Never prints a secret value. Reports only rule name, file path and commit.
#
# EXIT CODES
#   0  clean, scanned with the full gitleaks ruleset
#   1  findings, do not import
#   2  INCONCLUSIVE. Only the narrow built-in fallback ran, or the scan errored.
#      A clean result from the fallback is NOT a pass. Pass --allow-weak-scan
#      to accept it anyway for a quick look.
#
# Usage:   ./scan-donated-repo.sh <git-url-or-local-path> [--allow-weak-scan]

set -uo pipefail

TARGET=""
ALLOW_WEAK=0
for arg in "$@"; do
  case "$arg" in
    --allow-weak-scan) ALLOW_WEAK=1 ;;
    *) [ -z "$TARGET" ] && TARGET="$arg" ;;
  esac
done
if [ -z "$TARGET" ]; then
  echo "usage: $0 <git-url-or-local-path> [--allow-weak-scan]" >&2
  exit 2
fi

WORKDIR="$(mktemp -d)"
REPO="$WORKDIR/repo.git"
ERRLOG="$WORKDIR/errors.log"
: > "$ERRLOG"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> Mirror-cloning (full history) ..."
if ! git clone --mirror --quiet "$TARGET" "$REPO" 2>"$WORKDIR/clone.err"; then
  echo "FAILED to clone. git said:" >&2
  sed 's/^/    /' "$WORKDIR/clone.err" >&2
  exit 2
fi

COMMITS=$(git -C "$REPO" rev-list --all --count)
BRANCHES=$(git -C "$REPO" branch | wc -l | tr -d ' ')
TAGS=$(git -C "$REPO" tag | wc -l | tr -d ' ')
echo "    $COMMITS commits, $BRANCHES branches, $TAGS tags"

# Findings go to a file, not a shell variable. Several scans run inside
# pipelines, which bash executes in a subshell, so a counter variable would be
# incremented in the child and lost. That silently under-reports.
HITS="$WORKDIR/findings.txt"
: > "$HITS"
report() { printf '  [%s] %s\n' "$1" "$2" | tee -a "$HITS"; }
count_hits() { wc -l < "$HITS" | tr -d ' '; }

ENGINE="native"
if command -v gitleaks >/dev/null 2>&1; then
  ENGINE="gitleaks"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ENGINE="docker"
fi
echo "==> Scanning with: $ENGINE"
echo

# ------------------------------------------------------------------ gitleaks
if [ "$ENGINE" != "native" ]; then
  REPORT="$WORKDIR/report.json"
  # --redact is mandatory: without it real secret values are printed.
  if [ "$ENGINE" = "gitleaks" ]; then
    gitleaks detect --source="$REPO" --redact \
      --report-format=json --report-path="$REPORT" >"$WORKDIR/scan.log" 2>&1
  else
    docker run --rm -v "$REPO:/repo:ro" -v "$WORKDIR:/out" \
      zricethezav/gitleaks:latest detect --source=/repo --redact \
      --report-format=json --report-path=/out/report.json \
      >"$WORKDIR/scan.log" 2>&1
  fi
  RC=$?
  # gitleaks exits 0 = clean, 1 = leaks found, anything else = it broke.
  if [ "$RC" -gt 1 ] || [ ! -f "$REPORT" ]; then
    echo "SCANNER ERROR (exit $RC). This is NOT a clean result." >&2
    tail -15 "$WORKDIR/scan.log" >&2
    exit 2
  fi
  if command -v python >/dev/null 2>&1; then
    python - "$REPORT" <<'PY' | tee -a "$HITS"
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    data = []
seen = set()
for f in data:
    key = (f.get('File','?'), f.get('RuleID','?'))
    if key in seen:
        continue
    seen.add(key)
    print(f"  [{f.get('RuleID','?')}] {f.get('File','?')} (commit {str(f.get('Commit',''))[:8]})")
PY
  else
    grep -o '"RuleID":"[^"]*"' "$REPORT" | sort -u | tee -a "$HITS"
  fi
  [ "$(count_hits)" -eq 0 ] && echo "  none"
fi

# -------------------------------------------------------------------- native
if [ "$ENGINE" = "native" ]; then
  echo "-- Sensitive filenames ever committed --"
  if ! git -C "$REPO" log --all --diff-filter=A --name-only --format='' \
       2>>"$ERRLOG" | sed '/^$/d' | sort -u > "$WORKDIR/allfiles.txt"; then
    echo "ERROR walking history" >> "$ERRLOG"
  fi

  while IFS= read -r f; do
    base=$(basename "$f")
    case "$base" in
      *.example|*.sample|*.template|*.dist) continue ;;
    esac
    case "$base" in
      .env|.env.*|*.pem|*.key|*.p12|*.pfx|*.jks|*.keystore|\
      id_rsa|id_dsa|id_ecdsa|id_ed25519|\
      credentials|credentials.json|service-account*.json|serviceaccount*.json|\
      keys.yml|keys.yaml|secrets.env|secrets.yml|secrets.yaml|\
      wallet.json|keystore.json|mnemonic*|seed.txt|.netrc|.npmrc|.pypirc)
        report "sensitive-filename" "$f" ;;
    esac
  done < "$WORKDIR/allfiles.txt"
  [ "$(count_hits)" -eq 0 ] && echo "  none"

  echo
  echo "-- Credential patterns in history --"
  BEFORE=$(count_hits)

  # Revisions are fed through xargs in chunks. Passing every rev on one command
  # line overflows the argument limit on large repos, and the old version sent
  # that error to /dev/null and printed CLEAN. A failed scan must never look
  # like a passing one.
  git -C "$REPO" rev-list --all > "$WORKDIR/revs.txt" 2>>"$ERRLOG"

  scan_pattern() {
    local label="$1" pattern="$2" out="$WORKDIR/p.tmp"
    : > "$out"
    # -l prints only "rev:path", never the matching line, so no value leaks.
    xargs -a "$WORKDIR/revs.txt" -n 120 \
      git -C "$REPO" grep -I -l -E "$pattern" -- 2>>"$ERRLOG" \
      >>"$out" || true
    sed 's/^[0-9a-f]*://' "$out" | sort -u | head -20 \
      | while IFS= read -r hit; do [ -n "$hit" ] && report "$label" "$hit"; done
  }

  scan_pattern "private-key-block"  '\-\-\-\-\-BEGIN [A-Z ]*PRIVATE KEY\-\-\-\-\-'
  scan_pattern "pgp-private-block"  'BEGIN PGP PRIVATE KEY BLOCK'
  scan_pattern "aws-access-key"     'AKIA[0-9A-Z]{16}'
  scan_pattern "github-token"       'gh[pousr]_[A-Za-z0-9]{36}'
  scan_pattern "slack-token"        'xox[baprs]-[0-9A-Za-z-]{10,}'
  scan_pattern "openai-key"         'sk-[A-Za-z0-9]{32,}'
  scan_pattern "google-api-key"     'AIza[0-9A-Za-z_-]{35}'
  scan_pattern "stripe-key"         'sk_live_[0-9A-Za-z]{24,}'
  # Crypto material. This ecosystem runs nodes and wallets, so seed phrases and
  # raw hex keys are the likeliest thing to matter and the likeliest to be
  # missed by generic provider-pattern scanners.
  scan_pattern "hex-private-key"    '(private[_-]?key|privkey|secret[_-]?key)["'"'"' :=]+(0x)?[0-9a-fA-F]{64}'
  scan_pattern "eth-private-key"    '0x[0-9a-fA-F]{64}'
  scan_pattern "seed-phrase"        '(mnemonic|seed[_-]?phrase|recovery[_-]?phrase)["'"'"' :=]+[a-z]+( [a-z]+){11,}'
  scan_pattern "generic-secret"     '(password|passwd|api[_-]?key|auth[_-]?token|access[_-]?token)["'"'"' ]*[:=][ ]*["'"'"'][^"'"'"']{12,}'

  [ "$(count_hits)" -eq "$BEFORE" ] && echo "  none"
fi

FINDINGS=$(count_hits)

# A scan that errored is inconclusive, never clean.
if [ -s "$ERRLOG" ]; then
  echo
  echo "!! The scan produced errors, so a clean result cannot be trusted:" >&2
  head -10 "$ERRLOG" | sed 's/^/    /' >&2
  [ "$FINDINGS" -eq 0 ] && exit 2
fi

echo
echo "=========================================="
if [ "$FINDINGS" -eq 0 ]; then
  if [ "$ENGINE" = "native" ] && [ "$ALLOW_WEAK" -eq 0 ]; then
    echo "  INCONCLUSIVE - fallback scanner only"
    echo "=========================================="
    cat <<'EOF'

No findings, but only the narrow built-in scanner ran. It checks a short list
of patterns. gitleaks checks hundreds, including many wallet and provider
formats this fallback does not know about.

Do NOT treat this as a pass for a real import. Start Docker Desktop (or
install gitleaks) and run again.

For a quick look only:  re-run with --allow-weak-scan
EOF
    exit 2
  fi
  echo "  CLEAN across $COMMITS commits"
  echo "=========================================="
  echo
  echo "Safe to proceed. Re-run this immediately before the transfer completes,"
  echo "since the author can push new commits between now and then."
  exit 0
fi

echo "  $FINDINGS POTENTIAL SECRET(S) FOUND"
echo "=========================================="
cat <<'EOF'

DO NOT IMPORT THIS REPO YET.

1. Tell the author exactly which credentials are exposed, and have them
   ROTATE every one. If the repo has ever been public, treat each hit as
   already compromised. Scrubbing history does not un-leak a published key.

2. Import the project WITHOUT its history (fresh single commit).

3. Separately, read every .github/workflows/*.yml by hand. This scanner finds
   secret-shaped strings; it cannot recognise a workflow that exfiltrates
   secrets, because that is malicious logic, not a leaked value.
EOF
exit 1
