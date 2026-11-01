"""Demo assertion gate for CI."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from oci_rm_plan_gate import gate, load_plan

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
failed = 0
def check(name, cond):
    global failed
    print(f"{'PASS' if cond else 'FAIL'} {name}")
    failed += 0 if cond else 1

blocked = gate(load_plan(EXAMPLES / "plan-blocked.json"))
clean = gate(load_examples := load_plan(EXAMPLES / "plan-clean.json"))
rules_blocked = {f["rule"] for f in blocked["findings"] if f["verdict"] == "block"}
check("blocked plan verdict is block", blocked["verdict"] == "block")
check("bucket destroy blocked (RM001)", "RM001" in rules_blocked)
check("open SSH ingress blocked (RM002)", "RM002" in rules_blocked)
check("untagged + non-free shape are warnings, not blocks",
      {"RM003", "RM004"} <= {f["rule"] for f in blocked["findings"]}
      and blocked["summary"]["warn"] == 2)
check("no-op change produces no finding", all("vcn" not in f["address"] for f in blocked["findings"]))
check("clean plan verdict is pass", clean["verdict"] == "pass" and clean["summary"] == {"block": 0, "warn": 0})
check("internal SSH ingress is not flagged", all(f["rule"] != "RM002" for f in clean["findings"]))
print(f"validate: {'all checks passed' if not failed else str(failed) + ' check(s) failed'}")
sys.exit(1 if failed else 0)
