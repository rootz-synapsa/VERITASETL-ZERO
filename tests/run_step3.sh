#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"
rc=0
python3 tests/acceptance/rr_at_03_direct_bypass.py || rc=1
python3 tests/acceptance/rr_at_04_replay.py || rc=1
echo
python3 tests/security/secret_scan.py evidence || rc=1
echo
echo "== evidence/index.json =="
jq -r '.gates[] | "\(.gate)\t\(.status)\tsecret_free=\(.secret_free)\t\(.evidence_file)"' evidence/index.json
echo
if [ $rc -eq 0 ]; then echo "STEP 0-3 CHECKPOINT: ALL PASS"; else echo "STEP 0-3 CHECKPOINT: FAIL"; fi
exit $rc
