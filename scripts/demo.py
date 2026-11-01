"""Visible end-to-end demo: two plans through the pre-apply gate."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from oci_rm_plan_gate import gate, load_plan

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def show(plan_file: str) -> dict:
    changes = load_plan(EXAMPLES / plan_file)
    result = gate(changes)
    print(f"== {plan_file}: {result['changes_reviewed']} managed change(s) reviewed, verdict: {result['verdict'].upper()}")
    for f in result["findings"]:
        print(f"  [{f['verdict'].upper():5}] {f['rule']} {f['address']}")
        print(f"         {f['message']}")
    print(f"  summary: {json.dumps(result['summary'])}\n")
    return result


def main() -> int:
    blocked = show("plan-blocked.json")
    clean = show("plan-clean.json")
    assert blocked["verdict"] == "block" and clean["verdict"] == "pass"
    print("demo: blocked plan stopped before apply, clean plan passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
