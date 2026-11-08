#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"
rc=0
python3 tests/acceptance/ea_04_independent_verifier.py || rc=1
C1=evidence/ea/EA-04/C1_legit
if [ -f "$C1/normalized.csv" ]; then
  echo; echo "-- C1 normalized.csv (verified rows) --"; cat "$C1/normalized.csv"
  echo; echo "-- C1 exceptions.csv (row-level REQUIRES_REVIEW) --"; cut -d, -f1-3 "$C1/exceptions.csv"
fi
echo; echo "== Regression: RR-AT-01..04 must stay PASS =="
for t in rr_at_01_pre_execution_denial rr_at_02_toctou rr_at_03_direct_bypass rr_at_04_replay; do
  if python3 "tests/acceptance/$t.py" > "/tmp/vz_$t.log" 2>&1; then grep -E '^==>' "/tmp/vz_$t.log"
  else rc=1; grep -E '^==>|\[FAIL\]|Error|Traceback' "/tmp/vz_$t.log" | head -n 20; fi
done
echo
python3 tests/security/secret_scan.py evidence fixtures packages || rc=1
echo; echo "== evidence/index.json =="
jq -r '.gates[] | "\(.gate)\t\(.status)\tsecret_free=\(.secret_free)\t\(.evidence_file)"' evidence/index.json
echo
if [ $rc -eq 0 ]; then echo "STEP 5-6 CHECKPOINT: ALL PASS"; else echo "STEP 5-6 CHECKPOINT: FAIL"; fi
exit $rc
