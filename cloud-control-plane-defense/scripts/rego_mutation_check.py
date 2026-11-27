#!/usr/bin/env python3
"""Disable each `deny` rule in a temp copy; conftest verify must then FAIL.
A surviving mutant means a rule could silently stop working."""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

POLICIES = Path("policies")
HEADER = re.compile(r"^deny contains msg if \{$", re.M)


def verify(path):
    return subprocess.run(["conftest", "verify", "--policy", str(path)],
                          capture_output=True, text=True).returncode


base = verify(POLICIES)
print(f"baseline: conftest verify exit={base} (must be 0)")
if base != 0:
    sys.exit(2)

survivors = 0
total = 0
for rego in sorted(POLICIES.glob("*.rego")):
    text = rego.read_text()
    for m in HEADER.finditer(text):
        total += 1
        line = text.count("\n", 0, m.start()) + 1
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / "policies"
            shutil.copytree(POLICIES, dst)
            mutated = text[:m.end()] + "\n    false" + text[m.end():]
            (dst / rego.name).write_text(mutated)
            killed = verify(dst) != 0
        print(f"{rego.name}:{line:<4} rule disabled -> tests {'FAIL (killed)' if killed else 'STILL PASS (SURVIVED)'}")
        survivors += 0 if killed else 1

print(f"rules mutated: {total} | killed: {total - survivors} | survived: {survivors}")
sys.exit(1 if survivors else 0)
