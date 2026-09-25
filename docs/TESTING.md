# Testing

## Test Strategy

Three tiers, split by directory as the project spec requires (a deliberate divergence from the
sibling repos, which encode tier in the filename).

| Tier | Location | Proves |
|---|---|---|
| Unit | `tests/unit/` | `Choice`/`Score` derivation, the 0.85 boundary, schema parsing, question-payload generation and its ordering stability, every fail-closed branch, chain verification including tamper and truncation |
| Integration | `tests/integration/` | Against a mocked LangChain pipeline: a Block decision **actually prevents the tool function from running**. Asserted on the tool's side effect, never merely on the returned `ToolMessage` |
| E2E | `tests/e2e/` | A scripted agent trace over `tests/fixtures/threat_dataset.json` through real `create_agent` middleware |

**The assertion that matters most** is negative: the tool's side effect must not have happened.
A test that only checks the returned message would pass even if the tool had already run.

**Never weaken an assertion to make a test pass.** If a test fails because the code is wrong,
fix the code or log it in the Debt Ledger.

## Safety Net Map

### Tracer bullet — the first CI gate

One thin, fully real vertical slice, kept as production code:

```
real create_agent + GuardrailMiddleware
  → a real Bash-shaped tool with an observable side effect
  → envelope: {"command": "rm -rf ~/.ssh"}
  → mass_delete rule fires CRITICAL
  → policy short-circuits: BLOCK without consulting any classifier
  → real JsonlAuditSink writes a real record
  → verify_chain() clean
  → assert the tool's side effect never happened
```

It touches every ring, needs no 1.7 GB model and no API key, runs in milliseconds, and proves
the single most important property of the system. A second slice adds the classifier path via
`ReplayAdapter`.

### Failure-injection cases (from the Phase 6 audit)

Each is a test, not a production experiment: forced timeout · forced 429 · forced 529 · forced
malformed response · absent API key · un-downloaded model · killed mid-write producing a torn
final line · saturated inference executor. Every one must resolve to **BLOCK + a critical
event**, and the truncated-tail case must report `truncated_tail`, never `broken_at_seq`.

### The fail-closed backstop

The middleware carries an outermost catch-all that converts *any* unexpected exception —
including a contract violation inside KekkAI itself — into BLOCK plus a critical event.
"Crash early" is right for a program; for a guardrail, a crash that lets the tool run is the
worst outcome. **A dead guardrail must not become an open gate.** This is its own test.

## CI Gates

House workflow, extended. Matrix 3.11 / 3.12 / 3.13, `fail-fast: false`.

| # | Gate | Command |
|---|---|---|
| 1 | Lint | `ruff check .` |
| 2 | Format | `ruff format --check .` |
| 3 | Types | `mypy` |
| 4 | Tests | `pytest tests/ -v` |

Two gates run inside step 4 as ordinary tests, so they cannot be skipped:

- **`tests/unit/test_dependency_rule.py` — the Dependency Rule, executable.** Walks the AST of
  every module under `domain/` and `application/` and fails on any `Import`/`ImportFrom` naming
  `langchain`, `laya`, `typesafe`, `httpx`, `kekkai.config`, or `kekkai.adapters`. This is
  what makes the ring layout a rule rather than a habit. A companion test blocks those modules
  in `sys.modules` and imports the core ring to prove it loads with none of them installed.
- **`tests/e2e/test_tracer_bullet.py`** — the slice above.

CI never calls the live Jev API: the `ReplayAdapter` serves recorded fixtures. Live-backend runs
are a separate, manually invoked benchmark.
