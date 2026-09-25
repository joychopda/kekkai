"""Network destinations outside the configured allowlist."""

from __future__ import annotations

from ..heuristics import NETWORK_RE, NETWORK_TOOLS, SECRET_RE, extract_hosts
from ..model import RuleVerdict, Score
from ..prefilter import Rule, RuleContext, register_rule


@register_rule
class EgressAllowlist(Rule):
    name = "egress_allowlist"
    source = "prompt_injection/seed_prompts.json :: category=data_exfiltration"
    rationale = (
        "Indirect prompt injection converts an agent into an exfiltration channel, and the "
        "destination is the part the attacker must control. An empty allowlist means egress is "
        "unrestricted and this rule only reports; that default is deliberate, because a "
        "guardrail that blocks all network access on install gets uninstalled."
    )

    def evaluate(self, ctx: RuleContext) -> RuleVerdict | None:
        text = ctx.text()
        hosts = tuple(sorted(set(ctx.envelope.egress_hosts) | set(extract_hosts(text))))
        networking = bool(NETWORK_RE.search(text)) or ctx.envelope.tool_name in NETWORK_TOOLS
        if not networking and not hosts:
            return None
        if not ctx.egress_allowlist:
            return self.verdict(Score.LOW, f"network egress to {list(hosts) or 'an unparsed destination'}")

        unlisted = [h for h in hosts if h not in ctx.egress_allowlist]
        if not unlisted:
            return None
        carrying_secret = bool(SECRET_RE.search(text))
        score = Score.CRITICAL if carrying_secret else Score.HIGH
        return self.verdict(score, f"egress to unlisted host {unlisted[0]!r}")
