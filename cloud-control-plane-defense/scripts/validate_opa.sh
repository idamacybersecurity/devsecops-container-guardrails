#!/usr/bin/env bash
set -euo pipefail
umask 077

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ccpd-opa.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=========================================="
echo "CLOUD CONTROL-PLANE OPA SECURITY GATE"
echo "=========================================="

for command in terraform conftest; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $command" >&2
        exit 1
    fi
done

echo
echo "=== 1. COMPLIANT FIXTURE ==="
conftest test \
    --policy "$PROJECT/policies" \
    "$PROJECT/policies/fixtures/valid-plan.json"

echo
echo "=== 2. ADVERSARIAL FIXTURE ==="
set +e
conftest test \
    --policy "$PROJECT/policies" \
    "$PROJECT/policies/fixtures/invalid-plan.json" \
    > "$TMP_DIR/negative.log" 2>&1
NEGATIVE_STATUS=$?
set -e

cat "$TMP_DIR/negative.log"

FAIL_COUNT="$(python3 -c '
import re, sys
from pathlib import Path

content = Path(sys.argv[1]).read_text()
content = re.sub(r"\x1b\[[0-9;]*m", "", content)
print(len(re.findall(r"FAIL\s+-", content)))
' "$TMP_DIR/negative.log")"

if [[ "$NEGATIVE_STATUS" -eq 0 || "$FAIL_COUNT" -ne 8 ]]; then
    echo "ERROR: Expected rejection with exactly 8 violations."
    echo "Exit status: $NEGATIVE_STATUS; violations: $FAIL_COUNT"
    exit 1
fi

echo "PASS: All 8 adversarial violations were rejected."

echo
echo "=== 3. GENERATE FRESH TERRAFORM PLAN ==="
terraform -chdir="$PROJECT/terraform" plan \
    -input=false \
    -out="$TMP_DIR/current.tfplan"

echo
echo "=== 4. EXPORT PLAN JSON ==="
terraform -chdir="$PROJECT/terraform" show -json \
    "$TMP_DIR/current.tfplan" \
    > "$TMP_DIR/current-plan.json"

echo
echo "=== 5. ENFORCE OPA POLICIES ON REAL PLAN ==="
conftest test \
    --policy "$PROJECT/policies" \
    "$TMP_DIR/current-plan.json"

echo
echo "=========================================="
echo "PASS: OPA SECURITY GATE COMPLETED"
echo "No infrastructure changes were applied."
echo "=========================================="
