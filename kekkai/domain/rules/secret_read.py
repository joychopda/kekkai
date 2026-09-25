"""Reads of credential-bearing paths, and the read-then-egress correlation."""

from __future__ import annotations

from ..heuristics import NETWORK_RE, NETWORK_TOOLS, SECRET_RE, is_write_intent, mentioned_sentinels
from ..model import RuleVerdict, Score
from ..prefilter import Rule, RuleContext, register_rule


@register_rule
class SecretRead(Rule):
    name = "secret_read"
    source = "prompt_injection/seed_prompts.json :: category=data_exfiltration"
    rationale = (
        "Reading a credential is not by itself an attack -- agents legitimately read .env files. "
        "It becomes one when paired with egress in the same call, or when it follows a recent "
        "secret access in the same session. Rating the bare read LOW rather than HIGH is what "
        "keeps this rule enabled in practice: a guardrail people disable protects nobody."
    )

    def evaluate(self, ctx: RuleContext) -> RuleVerdict | None:
        text = ctx.text()
        touches_secret = bool(SECRET_RE.search(text))
        strong, _weak = mentioned_sentinels(text)
        if not touches_secret and not strong:
            return None

        if is_write_intent(ctx.envelope.tool_name, text) and touches_secret:
            # Writing to a credential store is how an attacker grants themselves access that
            # outlives the session -- appending a key to authorized_keys being the canonical
            # case. It is a different act from reading one, and rated accordingly.
            return self.verdict(Score.HIGH, "writes to a credential-bearing path")

        egressing = bool(NETWORK_RE.search(text)) or ctx.envelope.tool_name in NETWORK_TOOLS
        if egressing:
            what = "credential path" if touches_secret else f"environment secret {sorted(strong)[0]}"
            return self.verdict(Score.CRITICAL, f"{what} read in the same call as a network egress")

        window = ctx.session.now - ctx.session.last_secret_access_ts
        if ctx.session.last_secret_access_ts and window <= ctx.secrets_network_window_s:
            return self.verdict(
                Score.HIGH,
                f"credential access {window:.0f}s after a prior secret read in this session",
            )
        return self.verdict(Score.LOW, "reads a credential-bearing path")
