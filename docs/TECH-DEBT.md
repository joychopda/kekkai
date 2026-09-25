# Tech Debt

## Smell Inventory

Findings from the Phase 5 module-depth review, applied before implementation.

| # | Smell | Where | Resolution | Status |
|---|---|---|---|---|
| 1 | **Classitis** — four files holding tiny enums/dataclasses that all change together (adding a `Choice` member changes Score derivation *and* `GuardrailResult` validation) | planned `domain/{choice,score,result,envelope}.py` | Merged into one deep module `domain/model.py` — "the screening vocabulary: what goes in, what comes out, and the invariants binding them" | applied |
| 2 | **Ceremony package** — a directory per single implementation | planned `adapters/sinks/`, `adapters/hosts/` | Collapsed to `adapters/audit_sink.py` and `adapters/langchain_host.py`. `domain/rules/` and `adapters/classifiers/` keep their packages — 5 rules and 4 backends plus registry side-effect imports genuinely earn them | applied |
| 3 | **Information leakage — threshold** | `0.85` and the tier deadlines would otherwise appear in policy, config, `benchmarks/gates`, dashboard colouring, and tests | A frozen `ScreeningPolicy` owns `block_threshold`, tier deadlines, and the `Choice`→`Score` derivation table. Everything else *receives* it. The literal `0.85` appears exactly once in the codebase | applied |
| 4 | **Information leakage — taxonomy** | The `Choice` taxonomy would appear in the enum, both backends' criteria dicts, the ACL mapping, the dashboard legend, and the dataset schema | `questions.py` **generates** the vendor question payload from the `Choice` enum by sorted member iteration. Adding a member updates both backends automatically, and the Phase 2 option-ordering trap is fixed by construction rather than by a test | applied |
| 5 | **Back-door leakage — record format** | Audit record keys touched by the sink (write), dashboard (read), `verify` (parse), benchmarks (aggregate) | `domain/audit.py` owns `AuditRecord`, `to_json()`/`from_json()`, and `SCHEMA_VERSION`. No other module indexes its keys or calls `json.dumps` on one | applied |
| 6 | **Knowledge smeared by temporal decomposition** | Trust-fencing rules would spread across the interactor's sanitize → classify steps | `ToolCallEnvelope.classifier_prompt()` — the envelope produces its own fenced prompt, so the security-critical rule about which fields are trusted lives next to the data it governs | applied |

## Adopted Conventions

- **One sentence per module.** If a module's purpose needs two, it is doing two things.
- **Deep over many.** Boundaries at real volatility only. Four classifier backends earn a
  package; one audit sink does not.
- **A design decision lives in exactly one module.** If two modules must change in lockstep,
  that is the bug — merge them or extract what they share.
- **Interface comments state the abstraction and its invariants**, not the implementation.
  Every aggregate's invariants are written on the class, because they are enforced in
  `__post_init__` and a reader needs to know what is guaranteed.
- **The domain ring imports nothing outward** — not `config`, not `langchain`, not `laya`, not
  `typesafe`. A CI gate enforces this by walking module ASTs (Phase 7).
- **Refuse dangerous knobs.** Rule *severity* is tunable; the deterministic prefilter cannot be
  disabled. There is no `enable_prefilter` flag. A guardrail with a setting that silently
  switches off its uninjectable layer is a footgun, not a feature.
- **Vendor vocabulary stops at the adapter.** No `state`, `confidence`, or raw `score` inside
  `domain/` or `application/`.

## Debt Budget & Broken-Windows Policy

**Hard gates — build failures, not review comments.** Strict where the security property lives:

- The Dependency Rule import check fails the build. No exceptions, no `# noqa`.
- The fail-closed tests fail the build.
- The tracer-bullet slice fails the build.
- **No `# TODO` merges without a Debt Ledger row below.** A hack that must ship gets boarded up
  with a tracked entry, never left bare.
- **Never weaken an assertion to make a test pass.** Fix the code, or log it here.

**Debt budget:** 20% of each work session goes to repair before new feature work.

**Reversibility — the forking-road test**, all confirmed one-adapter changes:

| Swap | Touches |
|---|---|
| Jev → another hosted decision API | `adapters/classifiers/jev.py` |
| LangChain → another agent framework | one new file in `adapters/` |
| JSONL → SQLite audit sink | `adapters/audit_sink.py` |
| Laya PyTorch → ONNX or MLX runtime | a runtime parameter *inside* the Laya adapter |

**Orthogonality note.** `SessionState` has three consumers (cache key, interactor correlation,
temporal rules) — shared mutable state, the one global-state smell in the design. Contained by
invariant: **rules receive an immutable snapshot; only the interactor mutates, at one point,
after the decision is made.** A rule that could mutate session state could influence its own
future verdicts.

## Debt Ledger

Deliberately-taken debt from the Phase 8 scope cut. Each row carries the trigger that revisits it.

| # | Deferred | Why deferred | Trigger to revisit |
|---|---|---|---|
| D1 | `HybridAdapter` (Laya first-pass → Jev on Score ≥ 2) | Phase 6 already made Jev tier-2-only. The benchmark can *report* what hybrid would cost — escalation rate, added tail latency, added spend — without the adapter and its compounding failure modes (two backends, two breakers, two timeouts) | Measured ECE shows Laya materially worse in the Score ≥ 2 band **and** Jev materially better in that same band |
| D2 | Temperature calibration | Uncalibrated ECE is a fair comparison because both backends are measured identically. Calibration needs a third data split, a fitting procedure, and a re-derivation of what 0.85 means against calibrated probabilities | Measured ECE > 0.10 on either backend |
| D3 | Claude Code `PreToolUse` host adapter | `InterceptorPort` exists for it (Phase 1), so this is ~60 lines whenever wanted — not a refactor | Anyone asks to guard a Claude Code session |
| D4 | SIEM / syslog audit sink | `AuditSinkPort` exists; JSONL covers v1 | A deployment needs central log aggregation |
| D5 | Daemon / server mode | Phase 1 decision: IPC cost against a 100 ms deadline | Multiple agent processes need one shared model instance and the memory cost of N resident copies becomes the binding constraint |
| D6 | Threshold auto-tuning from production data | Would make the guardrail's own behaviour a moving target, and a poisoned feedback loop is an attack surface | Never, without an explicit adversarial-robustness design |
| D7 | PyPI publish | Not needed to prove the system | A consumer outside this workspace wants it |
| D8 | Jev measurement | No TypeSafe credential on the host. The adapter is built to the published contract and covered by tests, but no number is claimed for it | A credential is available; run `kekkai bench --backends jev --limit N` |
| D9 | Fine-tuned Laya checkpoint | The base checkpoint scores AUC 0.497 on this task — chance. Its own card reports 0.362 base vs 0.766 fine-tuned on typed decisions, so the gap is the checkpoint, not the approach | Anyone fine-tunes Laya on tool-call payloads; the adapter and question set already work unchanged |
| D10 | Rendered-DOM QA of the dashboard | The browser extension was not connected; static, header and API checks passed | A browser is attached; re-run the standard tier |

**Cut outright, not deferred:** `kekkai replay` as a user-facing subcommand — folded into
`bench --replay`.

### Rabbit holes (bounded before the build, not during)

| Rabbit hole | Bound |
|---|---|
| Laya runtime tuning — MPS vs ONNX vs CoreML vs quantization | Measure the three obvious runtimes **once**, take the fastest that passes correctness, stop. No quantization, no custom kernels |
| Threat dataset growth | ~120 records across the 8 seed categories, 60/40 split, versioned. Stop there |
| Shell command parsing | `shlex` + argv only. Subshells, `eval`, `$()` are a swamp — **anything unparseable escalates to the classifier or blocks. Unparseable is never treated as safe** |
| Dashboard features | Last N records + four aggregate tiles + chain status, 5 s poll. No websockets, no charting library |
| Prompt-injection detection inside the classifier prompt | Out of scope by design: we **fence**, we do not detect |

### Kept despite the pressure to cut

All five deterministic rules ship in v1. Phase 6 made them load-bearing rather than
nice-to-have: during a classifier outage they are the *entire* degradation path, and they are
the part of the system a classifier-injection cannot talk its way past.
