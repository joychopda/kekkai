"""Deployment configuration.

Deliberately thin. Thresholds and deadlines are *domain* rules and live in `ScreeningPolicy`
(`kekkai.domain.policy`), not here -- this module's job is to build one from a file or the
environment, not to own it. That is why `domain/` never imports `config`, and why the literal
0.85 appears nowhere in this file.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from .domain.policy import ScreeningPolicy

#: The default backend, set by the Phase 3 benchmark.
#:
#: Promotion is gated on safety before speed, and no probabilistic backend passed its gate on
#: the measured hardware: the base Laya checkpoint scored AUC 0.497 on the ambiguous band --
#: indistinguishable from chance, so no threshold choice could rescue it -- with ECE 0.667 and
#: a 70% false-positive rate, and its p95 of ~293 ms on Apple Silicon cannot meet the
#: common-path deadline in any case. Jev is excluded from this slot by construction, its vendor
#: latency being above the same deadline.
#:
#: So nothing was promoted, and the default is rule-only enforcement. Point `backend` at
#: "laya" (or a fine-tuned checkpoint) to opt back in; see benchmarks/results/ for the run.
DEFAULT_BACKEND = "deterministic"

DEFAULT_LOG_DIR = Path(os.environ.get("KEKKAI_HOME", Path.home() / ".kekkai")) / "audit"


@dataclass(frozen=True)
class KekkaiConfig:
    backend: str = DEFAULT_BACKEND
    log_dir: Path = field(default_factory=lambda: DEFAULT_LOG_DIR)
    workspace_root: str = ""
    egress_allowlist: frozenset[str] = frozenset()
    fsync_policy: str = "interval"
    cache_size: int = 512
    policy: ScreeningPolicy = field(default_factory=ScreeningPolicy.default)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> KekkaiConfig:
        """Build a config from a TOML file, then let the environment override it."""
        config = cls(workspace_root=os.getcwd())
        if path:
            config = config._merge_file(Path(path))
        return config._merge_env()

    def _merge_file(self, path: Path) -> KekkaiConfig:
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        data = tomllib.loads(path.read_text(encoding="utf-8")).get("kekkai", {})
        policy_data = data.pop("policy", {})
        allowlist = data.pop("egress_allowlist", None)
        known = {f.name for f in self.__dataclass_fields__.values()}
        updates: dict = {k: v for k, v in data.items() if k in known}
        if "log_dir" in updates:
            updates["log_dir"] = Path(updates["log_dir"]).expanduser()
        if allowlist is not None:
            updates["egress_allowlist"] = frozenset(allowlist)
        if policy_data:
            updates["policy"] = replace(self.policy, **policy_data)
        return replace(self, **updates)

    def _merge_env(self) -> KekkaiConfig:
        updates: dict = {}
        if backend := os.environ.get("KEKKAI_BACKEND"):
            updates["backend"] = backend
        if log_dir := os.environ.get("KEKKAI_LOG_DIR"):
            updates["log_dir"] = Path(log_dir).expanduser()
        if root := os.environ.get("KEKKAI_WORKSPACE_ROOT"):
            updates["workspace_root"] = root
        if allowlist := os.environ.get("KEKKAI_EGRESS_ALLOWLIST"):
            updates["egress_allowlist"] = frozenset(h.strip() for h in allowlist.split(",") if h.strip())
        if policy := os.environ.get("KEKKAI_FSYNC_POLICY"):
            updates["fsync_policy"] = policy
        return replace(self, **updates) if updates else self
