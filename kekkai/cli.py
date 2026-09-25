"""Command line interface.

Exit codes follow the house convention used across this workspace:
  0 - clean (allowed, or verification passed)
  1 - a finding (the call was blocked, or the chain is broken)
  2 - usage error
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .adapters.audit_sink import verify_log_dir
from .adapters.envelope_builder import build_envelope
from .config import KekkaiConfig
from .domain.audit import ChainStatus
from .domain.model import GuardrailResult
from .domain.prefilter import SessionSnapshot

EXIT_CLEAN, EXIT_FINDING, EXIT_USAGE = 0, 1, 2


def _tty() -> bool:
    return sys.stdout.isatty()


def RED(s: str) -> str:
    return f"\033[31m{s}\033[0m" if _tty() else s


def YEL(s: str) -> str:
    return f"\033[33m{s}\033[0m" if _tty() else s


def GRN(s: str) -> str:
    return f"\033[32m{s}\033[0m" if _tty() else s


def DIM(s: str) -> str:
    return f"\033[2m{s}\033[0m" if _tty() else s


def BLD(s: str) -> str:
    return f"\033[1m{s}\033[0m" if _tty() else s


def render(result: GuardrailResult) -> str:
    colour = RED if result.blocked else GRN
    head = colour(BLD(f"{result.decision.value.upper()}")) + (
        f"  score={result.score.label.lower()}  choice={result.choice.value}  "
        f"p(malicious)={result.malice_probability:.3f}  backend={result.backend_used}  "
        f"{result.execution_latency_ms:.1f}ms"
    )
    lines = [head]
    if result.reason:
        lines.append(f"  {result.reason}")
    for verdict in result.rule_verdicts:
        mark = RED if verdict.score >= 2 else YEL
        lines.append(f"  {mark(verdict.rule)} [{verdict.score.label.lower()}] {verdict.message}")
        lines.append(DIM(f"      source: {verdict.source}"))
    if result.fenced_fields:
        lines.append(DIM(f"  fenced from the classifier: {', '.join(result.fenced_fields)}"))
    if result.failed_closed:
        lines.append(YEL("  failed closed: no usable classifier answer"))
    return "\n".join(lines)


def cmd_check(args: argparse.Namespace) -> int:
    from .composition import build_screener

    config = KekkaiConfig.load(args.config)
    if args.backend:
        config = type(config)(**{**config.__dict__, "backend": args.backend})

    try:
        parsed_args = json.loads(args.args) if args.args else {}
    except json.JSONDecodeError as exc:
        print(f"--args must be valid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.arg:
        parsed_args.setdefault("command", args.arg)
    if not parsed_args:
        print("provide --arg or --args", file=sys.stderr)
        return EXIT_USAGE

    screener = build_screener(config)
    envelope = build_envelope(args.tool, parsed_args, session_id="cli")

    async def run() -> GuardrailResult:
        screened = await screener.screen(envelope, SessionSnapshot(session_id="cli"))
        # A shadow check is scheduled off the hot path, so a one-shot process has to wait
        # for it or the disagreement it was asked to record never reaches the log.
        await screener.drain_shadows(timeout=config.policy.shadow_budget_ms / 1000.0)
        return screened

    result = asyncio.run(run())
    screener.sink.flush()

    print(json.dumps(result.to_dict(), indent=2) if args.json else render(result))
    return EXIT_FINDING if result.blocked else EXIT_CLEAN


def cmd_verify(args: argparse.Namespace) -> int:
    config = KekkaiConfig.load(args.config)
    log_dir = Path(args.log_dir) if args.log_dir else config.log_dir
    report = verify_log_dir(log_dir)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif report.status is ChainStatus.OK:
        print(GRN(f"chain intact — {report.checked} record(s) across {report.detail or 'the log'}"))
    elif report.status is ChainStatus.TRUNCATED_TAIL:
        print(YEL(f"truncated tail — {report.checked} record(s) verified. {report.detail}"))
    else:
        print(RED(f"CHAIN BROKEN at seq {report.broken_at_seq}: {report.detail}"))
    return EXIT_CLEAN if report.ok else EXIT_FINDING


def cmd_backends(args: argparse.Namespace) -> int:
    from .adapters.classifiers import all_backends

    config = KekkaiConfig.load(args.config)
    for name, cls in sorted(all_backends().items()):
        marker = GRN(" (default)") if name == config.backend else ""
        print(f"  {BLD(name):<24} tier={cls.tier.value:<10}{marker}")
    return EXIT_CLEAN


def cmd_serve(args: argparse.Namespace) -> int:
    from .dashboard.server import serve

    config = KekkaiConfig.load(args.config)
    log_dir = Path(args.log_dir) if args.log_dir else config.log_dir
    serve(log_dir, host=args.host, port=args.port)
    return EXIT_CLEAN


def cmd_bench(args: argparse.Namespace) -> int:
    from benchmarks.run_benchmarks import main as bench_main

    return bench_main(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kekkai", description=__doc__.splitlines()[0])
    parser.add_argument("--config", help="path to a TOML config file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="screen a single tool call")
    check.add_argument("--tool", required=True, help="tool name, e.g. Bash or Read")
    check.add_argument("--arg", help="shorthand for a single 'command' argument")
    check.add_argument("--args", help="tool arguments as a JSON object")
    check.add_argument("--backend", help="override the configured backend")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    verify = subparsers.add_parser("verify", help="verify the audit chain")
    verify.add_argument("--log-dir")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify)

    backends = subparsers.add_parser("backends", help="list available classifier backends")
    backends.set_defaults(func=cmd_backends)

    serve = subparsers.add_parser("serve", help="serve the telemetry dashboard")
    serve.add_argument("--log-dir")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.set_defaults(func=cmd_serve)

    bench = subparsers.add_parser("bench", help="run the benchmark suite")
    bench.add_argument("--backends", default="replay", help="comma-separated backend names")
    bench.add_argument("--dataset")
    bench.add_argument("--out", help="write the JSON report here")
    bench.add_argument("--replay", action="store_true", help="use recorded answers, never the live API")
    bench.add_argument("--limit", type=int, default=0, help="cap records, to bound spend on a paid API")
    bench.add_argument("--deadlines", default="95", help="comma-separated classifier deadlines in ms")
    bench.set_defaults(func=cmd_bench)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return EXIT_USAGE
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(f"{RED('error')}: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
