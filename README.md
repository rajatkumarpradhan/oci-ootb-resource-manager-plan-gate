# oci-ootb-resource-manager-plan-gate

A pre-apply **safety gate** for Terraform plans, modeled on Oracle Cloud Infrastructure (OCI) **Resource Manager** - the built-in, fully managed OCI service that provisions infrastructure from Terraform configurations through plan and apply jobs. In a real stack, the risky moment is between "plan job succeeded" and "apply job starts": this repo implements that review step as real runnable code over the plan JSON the workflow already produces (`terraform show -json`), and proves it in CI.

> **No OCI tenancy or credentials are needed or contacted.** The plans under `examples/` are synthetic. The gate reads a plan file and prints a verdict; it does not call OCI, create resources, or run Terraform.

## Why this models the real service

- Resource Manager is a built-in OCI service with **no dedicated charge**: per [Oracle's Resource Manager FAQ](https://www.oracle.com/cloud/cloud-native/resource-manager/faq/), "There is no dedicated charge for Oracle Cloud Infrastructure Resource Manager" (checked 2026-11-02); you pay only for the resources your configuration creates. Its plan/apply job model is documented in the [Resource Manager overview](https://docs.oracle.com/en-us/iaas/Content/ResourceManager/Concepts/resourcemanager.htm).
- The gate runs where a careful team inserts review in that flow: after the plan job, before apply. Same input (plan JSON), same decision (go / no-go), encoded as deterministic rules instead of eyeballs.

## What the gate catches

| Rule | Verdict | Meaning |
| --- | --- | --- |
| RM001 | **block** | destroy or replacement (delete+create) of a protected resource type: buckets, KMS vaults/keys, DB systems, Autonomous Databases - the irreversible-data-loss class |
| RM002 | **block** | security list / NSG rule creating ingress from `0.0.0.0/0` that reaches an admin port (SSH 22 / RDP 3389), including port ranges that cover them and unrestricted rules |
| RM003 | warn | created resource missing the project's required freeform tag (`cost-center`) - stated as a project convention, not an OCI rule |
| RM004 | warn | compute instance on a non-Always-Free shape - **advisory** free-tier guardrail, not a billing guarantee |

`no-op` changes are ignored. Data-source (`data.` mode) changes are skipped. The verdict is `block` only when a BLOCK rule fires; warnings never block.

## Quickstart

```bash
python scripts/demo.py        # two synthetic plans through the gate: one blocked, one clean
python scripts/validate.py    # assertion gate used in CI
python -m unittest discover -s tests -v
```

The demo's blocked plan tries to destroy a backups bucket and open SSH to the internet; the clean plan creates an Always Free tagged instance with internal-only ingress and passes.

## Honest limits

- Offline review of `resource_changes` only: it cannot see drift that is not in the plan, module internals beyond the plan output, or whether the credentials behind a real apply could even succeed.
- Port math covers the common TCP/UDP option shapes; unusual protocol values are treated conservatively (unrestricted = all ports).
- The Always Free shape list and required tags are project conventions kept honest in messages; check Oracle's current free-tier page before relying on them.

## References

- Oracle, [Resource Manager FAQ](https://www.oracle.com/cloud/cloud-native/resource-manager/faq/): fully managed Terraform-based provisioning; no dedicated charge (checked 2026-11-02).
- Oracle, [Resource Manager overview](https://docs.oracle.com/en-us/iaas/Content/ResourceManager/Concepts/resourcemanager.htm): stacks, plan jobs and apply jobs.
- HashiCorp, [`terraform show -json` plan format](https://developer.hashicorp.com/terraform/internals/json-format): the `resource_changes` structure this tool reads.
