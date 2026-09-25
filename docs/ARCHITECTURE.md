# Architecture

## System Context

KekkAI is an **in-process guardrail library**. It occupies the window between an agent's
model proposing a tool call and the runtime executing it, and returns Block or Allow before the
tool function runs.

It is not a monitor. `agent-action-sentinel` (sibling repo) verifies behaviour *after*
execution and deliberately does not block; `auth-auditor` and `supply-chain-hunter` scan
artifacts *before* deployment. KekkAI is the enforcement point in between.

**Integrations**

| Direction | Integration | Notes |
|---|---|---|
| Inbound (host) | LangChain 1.4.2 `AgentMiddleware.wrap_tool_call` / `awrap_tool_call` | v1 host adapter |
| Inbound (host) | Claude Code `PreToolUse` hook | anticipated second adapter; port exists for it |
| Outbound | Jev — `POST https://api.typesafe.ai/v1/systemone` | hosted, 70–500 ms, billed per input token |
| Outbound | Laya — `laya.load("convaiinnovations/laya")` | in-process inference, not a network call after first download |
| Outbound | HuggingFace Hub | one-time model download at install/first-run |
| Sink | Append-only JSONL audit log + SHA-256 hash chain | system of record |

**Load reality.** Not DAU-shaped. The governing constraint is a **per-call deadline of 100 ms**
on the hot path, applied per intercepted tool call. Throughput is bounded by the agent's own
tool-call rate (order of 1–10 calls/second/process), not by concurrent users. Detailed latency
budget is Phase 3.

### Latency budget (the sizing question for this system)

There is no QPS problem — this is an in-process library bounded by the agent's own tool-call
rate (order 1–10 calls/s/process). The governing constraint is a **per-call deadline**.

| Stage | Budget | Note |
|---|---|---|
| Envelope build, trust tagging, path resolution | ~0.5 ms | pure Python over a small mapping |
| Prefilter — 5 rules, `shlex` argv parse + regex | ~1–2 ms | |
| `policy.decide()` | <0.1 ms | |
| Audit append — JSONL + SHA-256 | ~0.05 ms (no fsync) / 1–10 ms (fsync) | resolved in Phase 4 |
| **Classifier** | **~85–95 ms** | the remainder |

**Tier 1 — common path: 100 ms.** **Tier 2 — escalated path: 500 ms.** Hybrid mode costs
Laya + Jev serially (~200 ms optimistic), which does not fit one 100 ms deadline. Rather than
weaken the deadline everywhere, the deadline is per-tier: escalation only happens for the
ambiguous minority, where being right beats being fast. Both tiers are reported separately in
the benchmark table.

**The prefilter short-circuit is a latency decision, not just a security one.** A CRITICAL rule
hit blocks at ~2 ms with no classifier call; a trivially-safe envelope (read-only tool,
allowlisted path) allows at ~2 ms. The classifier is consulted only for the ambiguous middle.
This is simultaneously the tail-latency fix, the Jev cost control, and what makes a slow local
model survivable.

**Model residency.** Laya's English checkpoint is 421M params — roughly 1.7 GB fp32 / 840 MB
fp16 resident in *every* agent process. The English root is chosen over multilingual: tool-call
payloads are ASCII shell commands and paths, and its 512-token context is ample for an envelope.
The model is **pre-warmed at the composition root**, because a first inference carrying lazy
graph compilation would otherwise charge a multi-second penalty to the first real tool call.

**Decision cache.** A bounded in-process LRU keyed on a canonical hash of the envelope **plus
the `SessionState` fields that can change a verdict** (recent secret access, flagged entities).
Agents repeat identical calls constantly, so this removes most classifier work and most Jev
spend. A CRITICAL prefilter hit is never served from cache, and the cache key including state
is what prevents a stale allow.

**Explicitly not built** — no load balancer, no CDN, no message queue, no read replicas, no
sharding, no autoscaling, no multi-region. None has a trigger this system can reach: it is one
library in one process. The only "scaling" lever that exists is the decision cache.


## Layer Map & Dependency Rule

Four concentric rings. **Source dependencies point inward only.**

| Ring | Package | Contents | May import |
|---|---|---|---|
| 1 — Entities | `kekkai/domain/` | `Choice`, `Score`, `GuardrailResult`, `ToolCallEnvelope`, `SessionState`, `policy.decide()`, `RuleEngine` + deterministic rules | stdlib only |
| 2 — Use Cases | `kekkai/application/` | `ScreenToolCall` interactor, `ScreenRequest` / `ScreenResponse`, and the port interfaces it **owns**: `ClassifierPort`, `AuditSinkPort`, `InterceptorPort` | ring 1 |
| 3 — Interface Adapters | `kekkai/adapters/` | `LayaAdapter`, `JevAdapter`, `HybridAdapter`, `ReplayAdapter`, `JsonlAuditSink`, `langchain/GuardrailMiddleware` | rings 1–2 |
| 4 — Frameworks & Drivers | `kekkai/cli.py`, `kekkai/dashboard/`, `kekkai/composition.py` | `langchain`, `laya`, `typesafe-sdk`, `http.server`, argparse, wiring | everything |

**The load-bearing invariant:** `langchain`, `laya`, and `typesafe` are imported in **ring 3
only**. The entire decision engine — policy, thresholds, rule engine, fail-closed behaviour —
is designed to be exercised with none of those three packages installed. This is enforced by a
CI test that walks the AST of every module under `domain/` and `application/` and asserts no
import names a forbidden package (Phase 7 pins it as a gate).

**Data crossing boundaries.** `ToolCallEnvelope` is the host-neutral inward form of a proposed
tool call: tool name, argument mapping, resolved filesystem paths, extracted egress hosts, and
a **trust tag per field**. LangChain's `ToolCallRequest` is translated into it by the adapter
and never travels inward. `GuardrailResult` travels outward and is rendered by the adapter into
a `ToolMessage(status="error")` or a pass-through to `handler(request)`.

### Boundary decisions — earned vs ceremony

| Boundary | Verdict | Reason |
|---|---|---|
| `ClassifierPort` | **Full boundary** | Four implementations at v1 (Laya, Jev, Hybrid, Replay). Textbook earned volatility |
| `AuditSinkPort` | **Full boundary** | JSONL in production, in-memory in tests, SIEM/syslog plausible later |
| `InterceptorPort` | **Full boundary** | LangChain's own API already churned (`on_tool_start` → `wrap_tool_call`); a Claude Code hook adapter becomes ~60 lines instead of a refactor, and integration tests run without LangChain installed |
| Prefilter | **Collapsed — no port** | One implementation, pure, no I/O, no vendor. The `Rule` ABC + registry *inside* it is already the plugin seam; a port around it would be a shallow pass-through |
| Presenter | **Collapsed** | One output shape. A presenter interface here is classitis |
| Clock | **Partial boundary** | `clock: Callable[[], float] = time.perf_counter` injected as a parameter, not a port — enough for deterministic latency tests |

| Violation | Location | Fix | Status |
|---|---|---|---|
| _(none yet — greenfield)_ | | | |

## Bounded Contexts & Context Map

| Context | Subdomain | Owns | Lives in |
|---|---|---|---|
| **Screening** | **CORE** | The decision: `ToolCallEnvelope`, `TrustTag`, `RuleVerdict`, `Choice`, `Score`, `GuardrailResult`, `policy.decide()`, `RuleEngine` | `domain/` + `application/` |
| **Classification** | Generic (bought) | Vendor decision models — Laya, Jev | `adapters/classifiers/` |
| **Audit** | Supporting | Tamper-evident append-only chain | `domain/audit.py` + `adapters/sinks/` |
| **Host Integration** | Generic (conformist) | LangChain, Claude Code hooks | `adapters/hosts/` |
| **Calibration** | Supporting (offline) | ECE, latency percentiles, promotion gates | `benchmarks/` |

**Context map**

- **Classification → Screening: Anti-Corruption Layer.** We are downstream and cannot change
  Laya's or Jev's vocabulary, so each adapter translates it. No vendor term crosses into
  `domain/`.
- **Host Integration → Screening: Conformist + ACL.** LangChain dictates `ToolCallRequest`'s
  shape; the adapter conforms outward and translates inward to `ToolCallEnvelope`.
- **Screening → Audit: Published Language.** The audit record is a versioned schema
  (`schema_version`), because the dashboard and any future SIEM read it.
- **Screening → Calibration: Customer/Supplier.** Benchmarks consume published `GuardrailResult`
  records; they never reach into screening internals.

**Core-domain investment.** Deep modeling goes to **screening policy and the trust-fencing
model** — precedence between deterministic verdict and probabilistic signal, and which fields
of an envelope are trusted. That is the part no vendor supplies. Classification is commodity
(two vendors behind one port). Audit is a known pattern lifted from `agent-action-sentinel`.
The rule corpus is supporting-but-owned: real work, but not where the depth goes.

## Domain Glossary (Ubiquitous Language)

Vendor terms are confined to `adapters/`. The renames are not cosmetic — see `state`.

| Term | Meaning | Code name |
|---|---|---|
| Tool call envelope | A proposed tool call in host-neutral form: name, args, resolved paths, egress hosts, and a trust tag per field | `ToolCallEnvelope` |
| Trust tag | Whether a field originated from the operator, the model, or prior tool output | `TrustTag.{OPERATOR,MODEL,TOOL_OUTPUT}` |
| Session state | Agent history correlated across calls within one session | `SessionState` |
| **Classifier prompt** | The document handed to a classifier backend. **Deliberately not called "state"** — the vendors call it `state`, and conflating it with `SessionState` is precisely how untrusted tool output reaches the classifier and moves its verdict | `ClassifierPrompt` |
| Malice probability | Calibrated P(payload is malicious) ∈ [0,1]. The **only** input to the 0.85 threshold | `malice_probability` |
| Vendor confidence | A backend's self-reported certainty. Explicitly **not** a label probability; telemetry only, never thresholded | `vendor_confidence` |
| Rubric score | A backend's raw ordinal float over its criteria list. Translated by the ACL into `Score` | `rubric_score` |
| Score | KekkAI's ordinal risk 0–3 (Safe → Critical) | `Score(IntEnum)` |
| Choice | Exactly one of `safe_read_only`, `state_modification`, `privileged_system_call`, `external_exfiltration` | `Choice(StrEnum)` |
| Rule verdict | A deterministic rule's finding. **Binding** — a CRITICAL verdict cannot be downgraded by any probability | `RuleVerdict` |
| Screening decision | The immutable outcome of screening one tool call | `GuardrailResult` |
| Fail closed | Any classifier timeout, error, or unparseable response resolves to BLOCK plus a critical event | `ClassifierFailedClosed` |

**Divergence noted:** sibling repos use `Severity(IntEnum)` 0–4. KekkAI's `Score` is 0–3 as
specified. We do not import theirs; the ranges are different scales and unifying them would be
a false shared kernel.

### Aggregates and invariants

| Aggregate | Root | Invariants |
|---|---|---|
| Screening decision | `GuardrailResult` (frozen) | A CRITICAL `RuleVerdict` forces `decision=BLOCK` — no probability downgrades it · a BLOCK carries a non-empty reason citing a rule or the threshold · `malice_probability ∈ [0,1]` · `backend_used` and `execution_latency_ms` populated even when failing closed |
| Audit chain | the log | `seq` strictly monotonic from genesis (64 zeros) · each `prev_hash` equals the prior record's `hash` · append-only, never rewritten |
| Session state | `session_id` | Bounded memory — capped sets and a ring buffer, so a long-running session cannot grow without limit · referenced by ID from a decision, never embedded |

**Domain events** (past tense, immutable): `ToolCallScreened` (every decision — this *is* the
audit record), `ToolCallBlocked`, `ClassifierFailedClosed`, and `PrefilterOverrodeClassifier`.
The last one is the production signal that a classifier is being injected: it fires whenever
the deterministic layer blocks something the classifier rated safe, and a rising rate is the
symptom to alert on.

## Data & Storage Decisions

There is no database. The system of record is an **append-only JSONL audit log with a SHA-256
hash chain**; everything else (the dashboard, benchmark reports) is derived and rebuildable.

**The concurrency problem, named precisely.** A hash chain is a read-modify-write:
`hash_n = H(record_n ‖ hash_{n-1})`. Two agent processes that both read tail `hash_k` and both
append with `prev_hash = hash_k` **fork the chain**, and verification fails. This is write skew —
two transactions read the same state, decide, and write different records; no row lock prevents
it. `O_APPEND` makes the *bytes* land un-interleaved but says nothing about read-modify-write
atomicity, so it is necessary and not sufficient.

**Resolution — per-process segments, chained.**

| Concern | Decision |
|---|---|
| Hot-path writes | Each process owns its segment file and its own chain. **No lock on the hot path.** |
| Cross-segment integrity | A new segment's genesis record embeds the previous segment's final hash, recorded in an append-only registry. One locked append per *segment*, not per tool call |
| Deleting a whole segment | Breaks a registry link — detectable |
| Rotation | Segments are the rotation unit: roll at 64 MB or process restart |
| Retention | Configurable; default keep 30 days or 1 GB, whichever is hit first |
| Durability | No fsync on the hot path. Flush on a 1 s timer and at clean shutdown. `fsync_policy: never \| interval \| always` is configurable |
| Loss window | Process crash loses nothing — the kernel holds the bytes. Power loss or kernel panic costs ≤ 1 s of records. Documented, not hidden |

**Crash is not tampering.** A crash mid-write can leave a malformed trailing line.
`verify_chain()` classifies that as `truncated_tail` — expected and recoverable — and reserves
`broken_at_seq` for a record whose hash does not match its content. Conflating the two would
make every crash look like an intrusion and render the signal useless.

**Derived data.** The dashboard is a pure reader (stream-table duality: the log is the
changelog, the dashboard's in-memory aggregate is the materialized view). It reads up to the
last complete newline, never writes, and never holds the file exclusively. It can be deleted
and rebuilt from the log at any time.

**Not applicable, deliberately:** replication, partitioning, isolation levels, leader election,
CDC. There is one writer per file and no network-visible datastore.

## Decision Log

| Date | Decision | Why | Alternatives rejected |
|---|---|---|---|
| 2026-09-23 | **In-process library; no daemon** | The 100 ms deadline is the whole budget — an IPC round-trip per tool call spends it on transport instead of inference. A daemon can later be another `ClassifierPort` adapter without touching the core | Loopback HTTP daemon (agent-action-sentinel's shape) — rejected for hot-path cost; library+daemon both — rejected as two integration paths to test at v1 |
| 2026-09-23 | **Async-native core with sync wrapper** | `asyncio.wait_for` is a real deadline primitive; Laya's blocking inference runs in a thread executor. Most LangChain agents are async, and a sync-only guardrail would block their event loop | Sync-only — rejected; async agents are the majority case |
| 2026-09-23 | **`InterceptorPort` at v1, not extracted later** | Keeps `langchain` out of the application ring, which is the one boundary the Dependency Rule most wants held; a second host (Claude Code hooks) is demonstrated by a sibling repo, not hypothetical | LangChain-only with later extraction — rejected: langchain types would reach ring 2 and the core could no longer be tested without it |
| 2026-09-23 | **Explicit ring packages** `domain/application/adapters` | The ring is visible in the import path, so a violation is obvious in review and mechanically greppable by a CI gate | House `core/` + seams layout (auth-auditor, supply-chain-hunter, StateFuzz) — rejected: the Dependency Rule would be convention-only. README documents the divergence |
| 2026-09-23 | **Modular monolith — one Python package** | Single deployable library; there is no second deployment unit to justify | Services — not applicable to an in-process library |
| 2026-09-23 | **Vendor vocabulary renamed at the ACL** — `state`→`ClassifierPrompt`, `score`→`rubric_score`, `confidence`→`vendor_confidence` | Makes the dangerous conflation unsayable: "put session history into state" cannot be written, because the domain has no term called state. Naming discipline used as a security control | Keeping vendor names for 1:1 doc alignment — rejected: that exact ambiguity is the documented injection vector |
| 2026-09-23 | **Core domain = screening policy + trust-fencing**; classification is Generic | Depth goes where no vendor supplies the answer — verdict precedence and which envelope fields are trusted. Two vendors behind one port is commodity by definition | Rule corpus as core — rejected, it is supporting-but-owned; calibration as core — rejected, it is offline tooling, not the hot path |
| 2026-09-23 | **`Score` stays 0–3; sibling `Severity` 0–4 not imported** | Different scales; sharing the type would be a false shared kernel coupling two repos that disagree | Adopting the sibling `Severity` — rejected on range mismatch |
| 2026-09-23 | **Tiered deadline: 100 ms common / 500 ms escalated** | Hybrid costs ~200 ms serially and cannot fit one 100 ms budget. Escalation is the ambiguous minority where correctness outranks speed | One 100 ms deadline everywhere — rejected, it would make hybrid unusable; raising the deadline globally — rejected, it would slow the common path for the rare case |
| 2026-09-23 | **Prefilter short-circuits before the classifier** | CRITICAL blocks and trivially-safe allows resolve in ~2 ms without inference. Simultaneously the tail-latency fix, the Jev cost control, and what makes a slow local model survivable | Always consulting the classifier — rejected on latency, cost, and injectability grounds |
| 2026-09-23 | **Bounded LRU decision cache keyed on envelope + verdict-relevant SessionState** | Agents repeat identical calls constantly; this removes most classifier work. Including state in the key is what prevents a stale allow | No cache — rejected, it pays full inference cost on repeats; caching prefilter-allows only — rejected, it saves least where cost is highest |
| 2026-09-23 | **Laya English checkpoint, pre-warmed at composition root** | Tool-call payloads are ASCII shell and paths; 512-token context is ample and the model is smaller. Pre-warming keeps lazy graph compilation off the first real tool call | Multilingual checkpoint — rejected as unnecessary weight for ASCII payloads |
| 2026-09-23 | **Per-process audit segments, chained via a registry** | A shared chain would need a lock on every tool call against a hard deadline; per-process segments keep the hot path lock-free while segment-to-segment hash linking still makes whole-file deletion detectable | One shared file with `flock` per append — rejected, it serializes a deadline-bound hot path; fully independent per-process chains — rejected, deleting a segment would leave no trace |
| 2026-09-23 | **Interval fsync (1 s) + fsync on clean shutdown** | The threat model is tampering, not power loss; process crashes lose nothing because the kernel holds the bytes. Spending up to 10% of the deadline on every call to defend against an attacker who can already power-cycle the host is a bad trade | fsync per record — rejected on hot-path cost; never fsync — rejected, an unbounded loss window is indefensible |
| 2026-09-23 | **`verify_chain()` distinguishes `truncated_tail` from `broken_at_seq`** | A crash mid-write must not present as an attack, or the tamper signal becomes noise nobody acts on | A single "invalid" result — rejected as unactionable |
| 2026-09-23 | **v1 does NOT build: hybrid adapter, temperature calibration, Claude Code host adapter, SIEM sink, daemon mode, threshold auto-tuning, PyPI publish** | Each is either speculative or already superseded by an earlier decision. All seven carry a revisit trigger in TECH-DEBT.md's Debt Ledger, so none is silently dropped | Building hybrid in v1 — rejected: Jev is already tier-2-only, so the benchmark can report hybrid's cost without paying for its failure modes. Calibration in v1 — rejected: uncalibrated ECE compares both backends fairly, and calibration would change what 0.85 means |
| 2026-09-23 | **All five deterministic rules ship in v1** | Phase 6 made prefilter coverage the entire degradation path during a classifier outage — these are load-bearing, not nice-to-have | Shipping three — rejected: a thinner degradation path is the wrong economy in a fail-closed control |
| 2026-09-23 | **Unparseable shell input is never treated as safe** | A guardrail that silently allows what it cannot parse is worse than no guardrail; `shlex` covers the common case and everything else escalates or blocks | Attempting full shell-grammar parsing — rejected as an unbounded rabbit hole |
| 2026-09-24 | **No classifier backend promoted; `DEFAULT_BACKEND = "deterministic"`** | Measured on the target host: the base Laya checkpoint scored **AUC 0.497** on the ambiguous band — indistinguishable from chance, so no threshold could rescue it — with ECE 0.667 and a 70% false-positive rate, and its p95 of ~293 ms cannot meet the common-path deadline regardless. Adding it *degraded* the deterministic band from 100%/0.0% FPR to 100%/65.3% FPR. Promotion is safety-gated, so nothing was promoted | Promoting Laya at a 400 ms deadline — rejected: a 70% FPR gets the guardrail switched off; lowering the gate to let a backend through — rejected, that is the gate doing its job |
| 2026-09-24 | **Jev measured as unavailable, not estimated** | No TypeSafe credential was present on the host. Its adapter is built to the published contract and exercised in tests, but no latency, ECE, or gate number is claimed for it. Vendor figures are cited as vendor figures | Publishing vendor-quoted numbers in the benchmark table — rejected: a measured column and a quoted column side by side reads as a measurement |
| 2026-09-24 | **Deterministic-only allows the ambiguous middle rather than failing closed** | A *configured* backend that stops answering means something broke, so KekkAI blocks. Choosing rule-only enforcement is an operator deciding which risks to accept, so KekkAI enforces what it knows and records the rest. A mode that blocked every unfamiliar call would be switched off within a day | Fail-closed in deterministic-only mode — rejected as unusable; silently allowing without recording — rejected, the audit trail is the point |

