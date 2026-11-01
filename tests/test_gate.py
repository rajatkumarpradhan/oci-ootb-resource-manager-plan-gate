"""Gate rules: protected destroys, open admin ingress, tags, free-tier shapes."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from oci_rm_plan_gate import Change, PlanError, check_change, gate, load_plan

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def change(actions, rtype="oci_core_instance", name="x", after=None):
    return Change(address=f"{rtype}.{name}", resource_type=rtype, name=name,
                  actions=tuple(actions), after=after or {})


class ProtectedDestroyTests(unittest.TestCase):
    def test_bucket_destroy_blocked(self):
        f = check_change(change(["delete"], "oci_objectstorage_bucket", "backups"))
        self.assertEqual([(x.rule, x.verdict) for x in f], [("RM001", "block")])

    def test_replacement_of_vault_blocked(self):
        f = check_change(change(["delete", "create"], "oci_kms_vault", "v"))
        self.assertIn("replacement", f[0].message)
        self.assertEqual(f[0].verdict, "block")

    def test_unprotected_destroy_not_blocked(self):
        f = check_change(change(["delete"], "oci_core_instance", "tmp"))
        self.assertEqual(f, [])


class OpenIngressTests(unittest.TestCase):
    def test_ssh_open_to_world_blocked(self):
        after = {"ingress_security_rules": [
            {"stateless": False, "source": "0.0.0.0/0",
             "tcp_options": {"min": 22, "max": 22}}]}
        f = check_change(change(["update"], "oci_core_security_list", "sl", after))
        self.assertIn("RM002", {x.rule for x in f})

    def test_port_range_covering_rdp_blocked(self):
        after = {"source": "0.0.0.0/0", "tcp_options": {"min": 3000, "max": 4000}}
        f = check_change(change(["create"], "oci_core_network_security_group_security_rule", "r", after))
        self.assertTrue(any("3389" in x.message for x in f))

    def test_internal_source_and_safe_ports_pass(self):
        after = {"ingress_security_rules": [
            {"stateless": False, "source": "10.0.0.0/16", "tcp_options": {"min": 22, "max": 22}},
            {"stateless": False, "source": "0.0.0.0/0", "tcp_options": {"min": 443, "max": 443}}]}
        f = check_change(change(["update"], "oci_core_security_list", "sl", after))
        self.assertNotIn("RM002", {x.rule for x in f})

    def test_no_port_restriction_means_all_ports(self):
        after = {"source": "0.0.0.0/0"}
        f = check_change(change(["create"], "oci_core_network_security_group_security_rule", "r", after))
        self.assertIn("RM002", {x.rule for x in f})


class WarnRuleTests(unittest.TestCase):
    def test_missing_cost_center_tag_warns(self):
        f = check_change(change(["create"], "oci_core_vcn", "v", {"freeform_tags": {}}))
        self.assertEqual([(x.rule, x.verdict) for x in f], [("RM003", "warn")])

    def test_non_free_shape_warns_advisory(self):
        f = check_change(change(["create"], "oci_core_instance", "i",
                                {"shape": "VM.Standard.E5.Flex",
                                 "freeform_tags": {"cost-center": "lab"}}))
        self.assertEqual([(x.rule, x.verdict) for x in f], [("RM004", "warn")])
        self.assertIn("advisory", f[0].message)

    def test_always_free_shape_quiet(self):
        f = check_change(change(["create"], "oci_core_instance", "i",
                                {"shape": "VM.Standard.E2.1.Micro",
                                 "freeform_tags": {"cost-center": "lab"}}))
        self.assertEqual(f, [])


class GateTests(unittest.TestCase):
    def test_verdict_block_only_on_block_findings(self):
        warn_only = [change(["create"], "oci_core_vcn", "v", {"freeform_tags": {}})]
        self.assertEqual(gate(warn_only)["verdict"], "pass")
        blocked = gate(load_plan(EXAMPLES / "plan-blocked.json"))
        self.assertEqual(blocked["verdict"], "block")
        self.assertEqual(blocked["summary"], {"block": 2, "warn": 2})
        self.assertEqual(blocked["changes_reviewed"], 4)

    def test_noop_changes_produce_no_findings(self):
        f = check_change(change(["no-op"], "oci_core_vcn", "v"))
        self.assertEqual(f, [])

    def test_bad_plan_rejected_not_crashed(self):
        with self.assertRaises(PlanError):
            load_plan(EXAMPLES / "does-not-exist.json")


if __name__ == "__main__":
    unittest.main()
