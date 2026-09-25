"""Filesystem access reaching outside the working tree."""

from __future__ import annotations

import posixpath

from ..heuristics import extract_paths, is_write_intent
from ..model import RuleVerdict, Score
from ..prefilter import Rule, RuleContext, register_rule

_SYSTEM_PREFIXES = (
    "/etc",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/private",
    "/root",
    # Pseudo-filesystems expose process memory and the environment of any running process,
    # so reading them is a credential-disclosure path that looks like an ordinary file read.
    "/proc",
    "/sys",
    "/dev",
)


@register_rule
class PathEscape(Rule):
    name = "path_escape"
    source = "agent-action-sentinel :: SECRET_PATTERNS + workspace containment"
    rationale = (
        "An agent scoped to a project has no legitimate reason to reach into system directories "
        "or another user's home. Traversal sequences are called out separately because they "
        "indicate deliberate evasion rather than an over-broad but honest path. Writes outside "
        "the tree are rated above reads: reading a stray path is usually clumsiness, while "
        "writing to one is how an agent installs persistence it will still have tomorrow."
    )

    def evaluate(self, ctx: RuleContext) -> RuleVerdict | None:
        root = posixpath.normpath(ctx.workspace_root) if ctx.workspace_root else ""
        paths = tuple(set(extract_paths(ctx.text())) | set(ctx.envelope.resolved_paths))
        if not paths:
            return None

        for p in paths:
            if ".." in p.split("/"):
                return self.verdict(Score.HIGH, f"path traversal sequence in {p!r}")
        for p in paths:
            if p.startswith(_SYSTEM_PREFIXES):
                return self.verdict(Score.HIGH, f"access to system path {p!r}")
        writing = is_write_intent(ctx.envelope.tool_name, ctx.text())
        outside = [
            p
            for p in paths
            if p.startswith("~") or (p.startswith("/") and root and not posixpath.normpath(p).startswith(root))
        ]
        if outside:
            if writing:
                return self.verdict(Score.HIGH, f"write to {outside[0]!r}, outside the working tree")
            return self.verdict(Score.LOW, f"path {outside[0]!r} outside the working tree")
        return None
