"""Destructive deletion, especially outside the working tree."""

from __future__ import annotations

import posixpath

from ..heuristics import DELETE_RE, extract_paths
from ..model import RuleVerdict, Score
from ..prefilter import Rule, RuleContext, register_rule


def _outside(path: str, root: str) -> bool:
    """True when a path is not demonstrably inside the workspace."""
    if path.startswith(("~", "$")) or path in ("/", "/*"):
        return True
    if not root:
        return path.startswith("/")
    return not posixpath.normpath(posixpath.join(root, path)).startswith(posixpath.normpath(root))


@register_rule
class MassDelete(Rule):
    name = "mass_delete"
    source = "agent-action-sentinel :: rule=mass_delete_outside_tree"
    rationale = (
        "Recursive force-deletion is the highest-regret action an agent can take, and unlike "
        "most damage it is not recoverable by re-running the agent. Targets outside the "
        "working tree are rated CRITICAL because no legitimate in-workspace task needs them, "
        "while in-tree deletion stays advisory because build-artifact cleanup is daily work."
    )

    def evaluate(self, ctx: RuleContext) -> RuleVerdict | None:
        text = ctx.text()
        if not DELETE_RE.search(text):
            return None
        paths = extract_paths(text)
        escaping = [p for p in paths if _outside(p, ctx.workspace_root)]
        if escaping:
            return self.verdict(
                Score.CRITICAL, f"recursive delete targeting {escaping[0]!r}, outside the working tree"
            )
        # LOW, not HIGH: `rm -rf build/` and `rm -rf node_modules` are routine, in-tree, and
        # recoverable from version control. Rating them binding would block ordinary work
        # every day, and a guardrail that does that gets switched off.
        return self.verdict(Score.LOW, "recursive delete within the working tree")
