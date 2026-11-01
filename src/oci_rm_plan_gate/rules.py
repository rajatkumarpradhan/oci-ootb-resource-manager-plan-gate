"""Safety rules reviewed between a Resource Manager plan job and its apply job.

Each rule is a documented, deterministic check over resource_changes. BLOCK
rules stop the apply; WARN rules are review notes. The free-tier shape check
is an advisory guardrail, not a billing guarantee.
"""
from __future__ import annotations

from dataclasses import dataclass

from .plan import Change

# Destroying these by automation is where irreversible data loss happens.
PROTECTED_TYPES = {
    "oci_objectstorage_bucket",
    "oci_kms_vault",
    "oci_kms_key",
    "oci_database_db_system",
    "oci_database_autonomous_database",
}
ADMIN_PORTS = (22, 3389)  # SSH, RDP
REQUIRED_FREEFORM_TAGS = ("cost-center",)
# Oracle Always Free compute shapes (advisory list; limits/eligibility change).
ALWAYS_FREE_SHAPES = {"VM.Standard.E2.1.Micro", "VM.Standard.A1.Flex"}


@dataclass(frozen=True)
class Finding:
    rule: str
    verdict: str  # "block" | "warn"
    address: str
    message: str


def _covers_port(opts: dict | None, port: int) -> bool:
    """Does this protocol option block admit `port`? Caller decides absence semantics."""
    if not isinstance(opts, dict):
        return False
    try:
        lo, hi = int(opts.get("min", 0)), int(opts.get("max", 65535))
        return lo <= port <= hi
    except (TypeError, ValueError):
        return True  # unparseable restriction - treat as open, flag by review


def _entry_admits_port(entry: dict, port: int) -> bool:
    tcp, udp = entry.get("tcp_options"), entry.get("udp_options")
    if not tcp and not udp:
        return True  # no port restriction = all ports
    return _covers_port(tcp, port) or _covers_port(udp, port)


def _open_admin_rules(after: dict) -> list[str]:
    """Ingress entries from 0.0.0.0/0 that reach an admin port."""
    hits = []
    entries = list(after.get("ingress_security_rules") or []) or [after]
    for e in entries:
        if not isinstance(e, dict) or not e:
            continue
        source = str(e.get("source", ""))
        if source != "0.0.0.0/0":
            continue
        for port in ADMIN_PORTS:
            if _entry_admits_port(e, port):
                hits.append(f"0.0.0.0/0 -> port {port}")
    return sorted(set(hits))


def check_change(c: Change) -> list[Finding]:
    findings = []
    if c.resource_type in PROTECTED_TYPES and c.deletes:
        kind = "replacement (delete+create)" if c.replaces else "destroy"
        findings.append(Finding(
            "RM001", "block", c.address,
            f"{kind} of protected {c.resource_type} {c.name!r} - needs explicit human approval before apply"))
    if c.resource_type in ("oci_core_security_list",
                           "oci_core_network_security_group_security_rule",
                           "oci_core_network_security_group") and (c.creates or "update" in c.actions):
        for hit in _open_admin_rules(c.after):
            findings.append(Finding(
                "RM002", "block", c.address,
                f"ingress {hit} opens an admin port to the internet in {c.name!r}"))
    if c.creates and c.resource_type.startswith("oci_"):
        tags = c.after.get("freeform_tags") or {}
        missing = [t for t in REQUIRED_FREEFORM_TAGS if t not in tags]
        if missing:
            findings.append(Finding(
                "RM003", "warn", c.address,
                f"created {c.resource_type} {c.name!r} missing freeform tag(s): {', '.join(missing)} (project convention, not an OCI rule)"))
    if c.resource_type == "oci_core_instance" and c.creates:
        shape = str(c.after.get("shape", ""))
        if shape and shape not in ALWAYS_FREE_SHAPES:
            findings.append(Finding(
                "RM004", "warn", c.address,
                f"instance {c.name!r} uses shape {shape!r}, not on the Always Free list - advisory check, verify cost before apply"))
    return findings


def gate(changes: list[Change]) -> dict:
    findings = [f for c in changes for f in check_change(c)]
    blocks = [f for f in findings if f.verdict == "block"]
    return {
        "verdict": "block" if blocks else "pass",
        "changes_reviewed": len(changes),
        "findings": [f.__dict__ for f in findings],
        "summary": {"block": len(blocks),
                    "warn": sum(1 for f in findings if f.verdict == "warn")},
        "scope": ("Offline review of a Terraform plan JSON between plan and apply, in the "
                  "spirit of an OCI Resource Manager job gate. It does not call OCI, does "
                  "not evaluate module internals beyond resource_changes, and cannot see "
                  "drift that is not in the plan."),
    }
