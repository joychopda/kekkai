# Design Code Architecture Plan

## Context

**Project:** KekkAI — a real-time pre-execution guardrail that intercepts AI agent tool calls
via LangChain middleware and blocks dangerous ones (shell execution, arbitrary file access,
network egress, exfiltration) before the tool function runs.

**Started:** 2026-09-23
**Approved plan of record:** `/Users/agent-j/.claude/plans/role-goal-act-magical-lagoon.md`

| Intake | Answer |
|---|---|
| What it does | Blocks dangerous agent tool calls in the window between the model proposing a call and the runtime executing it |
| Competitive advantage | A deterministic rule layer the classifier cannot overrule, untrusted content fenced out of classifier state, and *measured* calibration (ECE) across two interchangeable backends |
| Stack | Python ≥3.11 · setuptools · no web framework · no ORM · no database (append-only JSONL + SHA-256 hash chain) · stdlib `http.server` for the dashboard · LangChain 1.4.2 integration surface |
| Year-one load | Not DAU-shaped. Tool calls per agent session; the governing budget is **per-call latency ≤ 100 ms**, not QPS |
| Outbound dependencies | Jev hosted API (`api.typesafe.ai`), one-time HuggingFace model download for Laya. Laya inference itself is in-process, not a network call |
| System of record | The audit log (JSONL hash chain). The dashboard is a derived read path |
| Owning teams | One → `team-topologies` skipped |

**Phase dose:** Phases 3 and 4 run as a *light, reframed* pass — Phase 3 as a latency budget
rather than QPS/sharding, Phase 4 as durability and concurrent-append integrity rather than
storage-engine selection. There is no database and no scaling story; there is a hard real-time
deadline and a tamper-evident log.

## Phase Status
| Phase | Skill | Status | Artifact | Date |
|---|---|---|---|---|
| 1 — Draw the boundaries | clean-architecture | done | ARCHITECTURE.md | 2026-09-23 |
| 2 — Model the domain | domain-driven-design | done | ARCHITECTURE.md | 2026-09-23 |
| 3 — Size the system (latency budget) | system-design | done | ARCHITECTURE.md | 2026-09-23 |
| 4 — Make data decisions (durability) | ddia-systems | done | ARCHITECTURE.md | 2026-09-23 |
| 5 — Keep modules deep | software-design-philosophy | done | TECH-DEBT.md | 2026-09-23 |
| 6 — Design for failure | release-it | done | RELIABILITY.md | 2026-09-23 |
| 7 — Prove wiring, lock in habits | pragmatic-programmer | done | TESTING.md + TECH-DEBT.md | 2026-09-23 |
| 8 — Cut scope to essential | 37signals-way | done | ARCHITECTURE.md + TECH-DEBT.md | 2026-09-23 |
| Optional — Align teams to boundaries | team-topologies | skipped: single owner | OPERATIONS.md | 2026-09-23 |

Statuses: pending · in-progress · awaiting-evidence · done · deferred: <reason> · skipped: <reason>

## Key Decisions
| Date | Phase | Decision | Rationale |
|---|---|---|---|
| 2026-09-23 | Intake | **In-process library only** — no daemon | Zero IPC on a 100 ms hot path; the entire budget goes to inference. A daemon can be added later as another adapter behind the same port without disturbing the core |
| 2026-09-23 | Intake | **Async-native core, sync wrapper** | `awrap_tool_call` is primary so `asyncio.wait_for` provides a real fail-closed deadline; Laya's blocking inference runs in a thread executor. Matches the house `asyncio_mode = "auto"` convention |
| 2026-09-23 | Intake | Phases 3 + 4 run light and reframed | No database, no scaling story — but a hard latency deadline and concurrent-append durability are both real and unresolved |
| 2026-09-23 | Intake | `team-topologies` skipped | Single owner; no Conway constraint to satisfy |
| 2026-09-23 | 1 | **`InterceptorPort` as a full boundary at v1** | Keeps `langchain` out of ring 2; a Claude Code hook adapter becomes ~60 lines, and the core tests without LangChain installed |
| 2026-09-23 | 1 | **Explicit ring packages** `domain/` `application/` `adapters/` | Ring is visible in the import path, so violations are greppable by a CI gate. Diverges from sibling `core/` layout deliberately |
| 2026-09-23 | 1 | Prefilter, Presenter, Clock get **no port** | One implementation each, pure and I/O-free; ports there would be shallow pass-throughs (classitis) |
| 2026-09-23 | 2 | **Vendor vocabulary renamed at the ACL** (`state`→`ClassifierPrompt`) | Naming as a security control — the dangerous conflation becomes unsayable |
| 2026-09-23 | 2 | **Core domain = screening policy + trust-fencing** | Classification is commodity (two vendors, one port); depth goes where no vendor supplies the answer |
| 2026-09-23 | 2 | `Score` 0–3 kept; sibling `Severity` 0–4 not imported | Different scales — sharing the type would be a false shared kernel |
| 2026-09-23 | 3 | **Tiered deadline — 100 ms common, 500 ms escalated** | Hybrid is ~200 ms serially; one flat deadline would make it unusable |
| 2026-09-23 | 3 | **Prefilter short-circuits before inference** | ~2 ms for CRITICAL blocks and trivially-safe allows; the latency fix and the cost control at once |
| 2026-09-23 | 3 | **Bounded LRU decision cache, state-aware key** | Agents repeat calls; state in the key prevents a stale allow |
| 2026-09-23 | 4 | **Per-process audit segments chained via a registry** | Concurrent appends to one chain are write skew; per-process segments keep the hot path lock-free and still detect whole-file deletion |
| 2026-09-23 | 4 | **Interval fsync (1 s), not per record** | Threat model is tampering, not power loss; ≤1 s loss window documented |
| 2026-09-23 | 4 | `verify_chain()` separates `truncated_tail` from `broken_at_seq` | A crash must not look like an attack |
| 2026-09-23 | 5 | **Merge the tiny value-object files into `domain/model.py`** | They change together; four interfaces for one cohesive vocabulary was classitis |
| 2026-09-23 | 5 | **`ScreeningPolicy` owns the threshold and deadlines** | A domain rule, not deployment config — and `domain/` must not import `config` |
| 2026-09-23 | 5 | **`questions.py` generates backend payloads from the `Choice` enum** | Taxonomy lives once; also fixes the option-ordering trap by construction |
| 2026-09-23 | 5 | **No `enable_prefilter` flag, ever** | A switch that silently disables the uninjectable layer is a footgun |
| 2026-09-23 | 6 | **The prefilter is the degradation path** | A tripped breaker must not mean allow-everything; only the ambiguous middle fails closed |
| 2026-09-23 | 6 | **No retries on the hot path** | A retry cannot help inside a hard deadline — it doubles latency for the same outcome |
| 2026-09-23 | 6 | **Dedicated `max_workers=2` executor, no queue** | A timed-out forward pass cannot be cancelled; without a bound, slow inference leaks threads |
| 2026-09-23 | 6 | **Jev is tier-2 only, by construction** | Its vendor p50–p95 cannot fit a 100 ms tier-1 deadline, so promoting it as the common-path default is not an available benchmark outcome |
| 2026-09-23 | 7 | **Tracer bullet = prefilter block, no classifier** | Touches every ring, needs no model or API key, runs in ms, and proves the property that matters most |
| 2026-09-23 | 7 | **Dependency Rule enforced as an AST-walking test** | Makes the ring layout a build failure rather than a habit |
| 2026-09-23 | 7 | **Outermost catch-all → BLOCK** | A dead guardrail must not become an open gate; any unexpected exception fails closed |
| 2026-09-23 | 7 | Rules receive an **immutable** `SessionState` snapshot | A rule that could mutate session state could influence its own future verdicts |
| 2026-09-23 | 8 | **Hybrid adapter deferred** (trigger: ECE split by Score band) | Jev is already tier-2-only; the benchmark can report hybrid's cost without its failure modes |
| 2026-09-23 | 8 | **Temperature calibration deferred** (trigger: ECE > 0.10) | Uncalibrated ECE compares both backends fairly; calibration would change what 0.85 means |
| 2026-09-23 | 8 | **All five rules ship** | Phase 6 made prefilter coverage the entire outage degradation path |
| 2026-09-23 | 8 | **Unparseable shell input escalates or blocks** | Never treated as safe; full shell-grammar parsing is an unbounded rabbit hole |

## Post-journey outcomes (build phases)

| Date | Phase | Outcome |
|---|---|---|
| 2026-09-24 | Build | 159 tests green across unit / integration / e2e on Python 3.13; ruff, ruff-format and mypy clean |
| 2026-09-24 | Benchmark | No backend promoted. Laya AUC 0.497 / ECE 0.667 / 70% FPR / p95 293 ms; deterministic layer 100% block / 0% FPR at p95 0.14 ms on its band |
| 2026-09-24 | Benchmark | Two bugs found by the harness and fixed: a Metal concurrent-encoding crash in the inference bulkhead, and an over-broad trust heuristic that fenced model-authored `content` and blinded the classifier |
| 2026-09-24 | QA | Standard-tier pass on the dashboard; 6 findings fixed. Rendered-DOM checks unverified (no browser attached) and recorded as a gap rather than a pass |

## Next Actions
- [x] Phase 1 — layer map + boundary verdicts recorded (owner: agent-j)
- [x] Phase 2 — bounded contexts + ubiquitous language (owner: agent-j)
- [x] Phase 3 — latency budget (owner: agent-j)
- [x] Phase 4 — audit durability + concurrent append (owner: agent-j)
- [x] Phase 5 — module depth review (owner: agent-j)
- [x] Phase 6 — integration-point audit (owner: agent-j)
- [x] Phase 7 — tracer bullet + CI gates (owner: agent-j)
- [x] Phase 8 — cut v1 scope to an appetite (owner: agent-j)
- [x] **Journey closed.** Build, test, benchmark and QA phases complete (owner: agent-j)
- [ ] Re-run the dashboard's rendered-DOM QA once a browser is attached (owner: agent-j)
- [ ] Measure Jev when a TypeSafe credential is available (owner: agent-j)
- [ ] Benchmark must report Tier 1 and Tier 2 latency separately (owner: agent-j)
- [ ] Alert on a rising `PrefilterOverrodeClassifier` rate — the in-production injection signal (owner: agent-j)
- [ ] Phase 7 — add the CI import-gate test that enforces the ring invariant (owner: agent-j)
