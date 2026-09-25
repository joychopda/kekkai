"""Translate a host's tool call into a host-neutral, trust-tagged envelope.

This is the Anti-Corruption Layer on the inbound side. It is shared by every host adapter so
the trust-tagging rules are applied identically no matter which framework is calling.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..domain.heuristics import extract_hosts, extract_paths, split_argv
from ..domain.model import ToolCallEnvelope, TrustTag

# Argument names that carry content the agent *fetched* rather than *composed*.
#
# The distinction is narrow and load-bearing in both directions. Fence too little and injected
# text reaches the classifier and moves its verdict. Fence too much and the classifier is
# blinded to the payload it is supposed to judge -- a bare `content` argument on a Write call
# is authored by the model and is the entire substance of the decision. An earlier, looser
# version of this list matched any name containing "content", which made a malicious git hook
# and a benign one score byte-identically because the classifier saw neither one's body.
#
# So: exact names and affixes that unambiguously mean "returned by something else", and
# nothing that merely might.
_UNTRUSTED_EXACT = frozenset(
    {
        "tool_output",
        "observation",
        "page_content",
        "response_body",
        "web_content",
        "http_response",
        "search_results",
        "retrieved_documents",
        "fetched_content",
    }
)
_UNTRUSTED_PREFIXES = ("fetched_", "retrieved_", "downloaded_", "scraped_", "web_", "remote_")
_UNTRUSTED_SUFFIXES = ("_output", "_observation", "_response", "_result", "_results")


def _looks_fetched(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _UNTRUSTED_EXACT
        or lowered.startswith(_UNTRUSTED_PREFIXES)
        or lowered.endswith(_UNTRUSTED_SUFFIXES)
    )


def infer_trust(args: Mapping[str, object], declared: Mapping[str, TrustTag] | None = None) -> dict[str, TrustTag]:
    """Tag each argument with its provenance.

    Explicit tags from the host always win. Otherwise a name-based heuristic marks
    fetched-content arguments as untrusted, and everything else defaults to MODEL -- the
    argument was composed by the model, which is exactly what is under assessment.

    Hosts that know the provenance of their arguments should pass `declared` rather than rely
    on the heuristic; naming conventions are a fallback, not a guarantee.
    """
    trust: dict[str, TrustTag] = {}
    for key in args:
        if declared and key in declared:
            trust[key] = declared[key]
            continue
        trust[key] = TrustTag.TOOL_OUTPUT if _looks_fetched(key) else TrustTag.MODEL
    return trust


def build_envelope(
    tool_name: str,
    args: Mapping[str, object],
    *,
    session_id: str = "",
    declared_trust: Mapping[str, TrustTag] | None = None,
    command_keys: tuple[str, ...] = ("command", "cmd", "script"),
) -> ToolCallEnvelope:
    """Build an envelope, parsing argv and extracting paths and egress hosts.

    Only trusted-side arguments are scanned for paths and hosts. Scanning fetched content would
    let an attacker inject a benign-looking path into the structured fields the rules read.
    """
    args = dict(args)
    trust = infer_trust(args, declared_trust)
    visible = {k: v for k, v in args.items() if trust[k] is not TrustTag.TOOL_OUTPUT}

    command = ""
    for key in command_keys:
        value = visible.get(key)
        if isinstance(value, str) and value:
            command = value
            break

    argv, parseable = split_argv(command) if command else ((), True)
    scan_text = "\n".join(str(v) for v in visible.values())

    return ToolCallEnvelope(
        tool_name=tool_name,
        args=args,
        trust=trust,
        resolved_paths=extract_paths(scan_text),
        egress_hosts=extract_hosts(scan_text),
        argv=argv,
        argv_parseable=parseable,
        session_id=session_id,
    )
