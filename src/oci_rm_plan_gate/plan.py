"""Terraform plan JSON model (the format Resource Manager plan jobs produce)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class Change:
    address: str
    resource_type: str
    name: str
    actions: tuple  # subset of create/read/update/delete ("no-op" when unchanged)
    after: dict

    @property
    def creates(self) -> bool:
        return "create" in self.actions

    @property
    def deletes(self) -> bool:
        return "delete" in self.actions

    @property
    def replaces(self) -> bool:
        return self.creates and self.deletes


def load_plan(path) -> list[Change]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        changes = raw["resource_changes"]
        assert isinstance(changes, list)
        out = []
        for c in changes:
            if c.get("mode", "managed") != "managed":
                continue
            ch = c.get("change", {})
            out.append(Change(
                address=str(c["address"]),
                resource_type=str(c["type"]),
                name=str(c.get("name", "")),
                actions=tuple(ch.get("actions", [])),
                after=ch.get("after") or {},
            ))
        return out
    except (OSError, json.JSONDecodeError, KeyError, AssertionError) as e:
        raise PlanError(f"cannot load Terraform plan JSON {path}: {e}") from e
