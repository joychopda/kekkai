"""The Dependency Rule, executable.

The architecture claims that the decision engine is independent of every vendor and framework.
A claim a build cannot check is a habit, not a rule -- so this walks the AST of every module in
the inner two rings and fails the build if one reaches outward.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "kekkai"
INNER_RINGS = ("domain", "application")

#: Nothing in the inner rings may name any of these. The first three are vendors; the last two
#: are outer rings of our own, which would invert the dependency direction just as badly.
FORBIDDEN = ("langchain", "laya", "typesafe", "httpx", "kekkai.config", "kekkai.adapters")


def inner_modules() -> list[Path]:
    return sorted(p for ring in INNER_RINGS for p in (PACKAGE_ROOT / ring).rglob("*.py"))


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import: cannot reach another top-level package
                continue
            if node.module:
                names.add(node.module)
    return names


def test_inner_rings_exist():
    modules = inner_modules()
    assert modules, "expected modules under domain/ and application/"


@pytest.mark.parametrize("path", inner_modules(), ids=lambda p: str(p.relative_to(PACKAGE_ROOT)))
def test_module_does_not_import_outward(path: Path):
    for imported in imported_names(path):
        for banned in FORBIDDEN:
            assert not (imported == banned or imported.startswith(banned + ".")), (
                f"{path.relative_to(PACKAGE_ROOT)} imports {imported!r}, which points outward. "
                "The decision engine must stay testable with no backend and no agent framework."
            )


def test_core_imports_with_every_vendor_absent(monkeypatch):
    """Prove the claim rather than only checking the source text.

    Blocks the vendor packages in `sys.modules` and imports the whole inner ring. If anything
    reached outward at import time, this raises.
    """
    for name in ("langchain", "laya", "typesafe", "typesafe_sdk", "httpx"):
        monkeypatch.setitem(sys.modules, name, None)
    for module in [m for m in list(sys.modules) if m.startswith("kekkai.")]:
        monkeypatch.delitem(sys.modules, module, raising=False)

    import importlib

    for module in (
        "kekkai.domain.model",
        "kekkai.domain.policy",
        "kekkai.domain.audit",
        "kekkai.domain.prefilter",
        "kekkai.domain.rules",
        "kekkai.application.ports",
        "kekkai.application.questions",
        "kekkai.application.screen_tool_call",
    ):
        importlib.import_module(module)
