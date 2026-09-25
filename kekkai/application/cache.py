"""A bounded decision cache.

Agents repeat identical tool calls constantly, and inference is the expensive part of
screening. The key includes the session fields that can change a verdict, because a cache keyed
on the envelope alone would happily serve an allow that was only correct before the agent read
a credential.
"""

from __future__ import annotations

from collections import OrderedDict

from ..domain.model import GuardrailResult
from ..domain.prefilter import SessionSnapshot


def cache_key(digest: str, session: SessionSnapshot) -> tuple:
    """Envelope identity plus everything about the session that could change the answer."""
    return (
        digest,
        bool(session.last_secret_access_ts),
        tuple(sorted(session.flagged_entities)),
    )


class DecisionCache:
    """Bounded LRU. No TTL: entries are scoped to a process, and the key carries the state."""

    def __init__(self, maxsize: int = 512):
        if maxsize < 1:
            raise ValueError("maxsize must be at least 1")
        self._maxsize = maxsize
        self._entries: OrderedDict[tuple, GuardrailResult] = OrderedDict()

    def get(self, key: tuple) -> GuardrailResult | None:
        if key not in self._entries:
            return None
        self._entries.move_to_end(key)
        return self._entries[key]

    def put(self, key: tuple, result: GuardrailResult) -> None:
        """Store a result.

        Two kinds are never cached:

        * **Deterministic blocks.** A block driven by a rule cost no inference, so caching it
          saves nothing, and keeping it out means a rule change takes effect on the next call
          rather than after an eviction. Advisory verdicts that did *not* decide the outcome
          are cached normally -- `shell_exec` raises a LOW on every shell call, and excluding
          those would disable the cache for the most common tool an agent uses.
        * **Fail-closed results.** These describe a backend outage, not the call. Caching one
          would keep blocking a legitimate call long after the backend recovered, turning a
          transient failure into a persistent one.
        """
        if result.failed_closed:
            return
        if result.blocked and result.rule_verdicts:
            return
        self._entries[key] = result
        self._entries.move_to_end(key)
        while len(self._entries) > self._maxsize:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)
