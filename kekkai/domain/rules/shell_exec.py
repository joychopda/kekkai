"""Shell execution, privilege escalation, and input the parser could not read."""

from __future__ import annotations

from ..heuristics import DYNAMIC_EXEC_RE, PRIVILEGE_RE, split_argv
from ..model import RuleVerdict, Score
from ..prefilter import Rule, RuleContext, register_rule

_SHELL_TOOLS = frozenset({"Bash", "Shell", "Terminal", "run_command", "execute"})


@register_rule
class ShellExec(Rule):
    name = "shell_exec"
    source = "supply-chain-hunter :: SINK_CODE_EXEC / SINK_PROCESS"
    rationale = (
        "Shell execution is the capability every other capability can be reached through, and "
        "piping into an interpreter executes bytes this layer never saw. "
        "Unparseable input is rated HIGH on purpose: a command this layer cannot read is a "
        "command it cannot vet, and treating unreadable as safe would make the deterministic "
        "layer trivially bypassable by quoting tricks."
    )

    def evaluate(self, ctx: RuleContext) -> RuleVerdict | None:
        env = ctx.envelope
        text = ctx.text()
        is_shell = env.tool_name in _SHELL_TOOLS

        if is_shell:
            command = str(env.args.get("command", "")) or text
            _argv, parseable = split_argv(command)
            if not parseable or not env.argv_parseable:
                return self.verdict(Score.HIGH, "shell command could not be parsed; treating as unvetted")

        if DYNAMIC_EXEC_RE.search(text):
            return self.verdict(Score.HIGH, "pipes content into an interpreter; the payload is never inspected")
        if PRIVILEGE_RE.search(text):
            return self.verdict(Score.HIGH, "privilege escalation or dynamic evaluation in the command")
        if is_shell:
            return self.verdict(Score.LOW, "invokes a shell")
        return None
