#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"
rc=0
python3 tests/acceptance/ea_02_03_sandbox_containment.py || rc=1
echo
echo "== Regression: RR-AT-01..04 and EA-04 must stay PASS =="
python3 tests/acceptance/ea_04_independent_verifier.py || rc=1
for t in rr_at_01_pre_execution_denial rr_at_02_toctou rr_at_03_direct_bypass rr_at_04_replay; do
  python3 "tests/acceptance/$t.py" > /dev/null || rc=1
done
echo
python3 tests/security/secret_scan.py evidence packages tests || rc=1
echo
echo "== evidence/index.json =="
jq -r '.gates[] | "\(.gate)\t\(.status)\tsecret_free=\(.secret_free)\t\(.evidence_file)"' evidence/index.json
echo
if [ $rc -eq 0 ]; then echo "STEP 7 CHECKPOINT: ALL PASS"; else echo "STEP 7 CHECKPOINT: FAIL"; fi
exit $rc
