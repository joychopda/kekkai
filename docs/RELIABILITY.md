# Reliability

KekkAI is a fail-closed security control on an agent's hot path. That inverts several
standard resilience assumptions, and the inversions are the point of this document.

## Integration-Point Audit

| Dependency | Timeout | Circuit breaker | Bulkhead | Retry policy | Status |
|---|---|---|---|---|---|
| **Jev** — `POST api.typesafe.ai/v1/systemone` | connect 150 ms · read 350 ms · outer `asyncio.wait_for` 500 ms (tier 2) | Opens after 5 consecutive failures or >50% failures in 30 s · half-open after 30 s with a single probe | Own `httpx` client + connection pool; shares nothing with inference | **None on the hot path.** 429/529 fail closed immediately and let the breaker absorb the pattern | designed |
| **Laya** — in-process PyTorch/ONNX | `asyncio.wait_for` 95 ms (tier 1), leaving ~5 ms for envelope + policy + audit | Consecutive-timeout counter marks the backend unhealthy and stops attempting — same fail-fast benefit without pretending it is a remote call | **Dedicated executor, `max_workers=2`**, isolated from every other pool | None | designed |
| **HuggingFace Hub** — one-time model download | 300 s, at composition-root warm-up only | n/a | n/a | 3 attempts, exponential backoff — this is the one place retries make sense | designed |
| **Audit log** — local filesystem | none (local append, no fsync on hot path) | n/a | n/a | n/a | designed |

### Three inversions worth stating explicitly

**1. A tripped breaker must not mean allow-everything.** For a fail-closed control, "classifier
unavailable" means block — so a naive breaker is a self-inflicted denial of service on the
agent. The resolution is that **the prefilter is the degradation path**. With the breaker open:

| Envelope | Behaviour with classifier down |
|---|---|
| CRITICAL / HIGH deterministic rule hit | BLOCK — unchanged, local, ~2 ms |
| Trivially safe (read-only tool, allowlisted path) | ALLOW — unchanged, local, ~2 ms |
| **Ambiguous middle** | **BLOCK + `ClassifierFailedClosed`** |

So the breaker's value here is **latency, not availability**: it stops paying a 500 ms timeout
on every call during an outage. Fail-fast becomes fail-closed-fast. A direct consequence:
prefilter coverage determines how usable KekkAI is during a classifier outage, which is the
operational argument for investing in the rule corpus.

**2. No retries on the hot path.** A retry cannot help inside a hard deadline — it doubles
latency and reaches the same fail-closed outcome. Deliberate departure from backoff-and-jitter;
retries exist only for the one-time model download.

**3. A timed-out forward pass cannot be cancelled.** `asyncio.wait_for` returns control to us,
but the PyTorch thread keeps computing. Without a bound, slow inference accumulates threads —
the blocked-threads anti-pattern arriving through a *local* dependency. Hence the dedicated
`max_workers=2` executor with **no queue**: when both workers are busy with timed-out
inferences, the next call fails closed at ~2 ms rather than piling up. Slow inference degrades
into deterministic-only mode instead of degrading the host process.

### Policy constraint derived from this audit

**Jev is tier-2 only, by construction.** Its vendor p50–p95 (70–500 ms) cannot fit a 100 ms
tier-1 deadline. "Promote Jev as the tier-1 default" is therefore not an available outcome of
the Phase 3 benchmark; Jev is reachable on the escalated path or as an out-of-band second
opinion. The benchmark still measures it fully and publishes its numbers.

## Query & Resource Findings

| Finding | Bound |
|---|---|
| `SessionState` growth over a long agent session | Capped sets + ring buffer; bounded by construction |
| Decision cache | Bounded LRU; state-aware key |
| Audit log growth | Segment rotation at 64 MB or process restart; retention 30 days / 1 GB |
| Classifier prompt size | Envelope is truncated to the checkpoint's 512-token context before the call; truncation is recorded on the result so it is never silent |
| Inference thread pool | `max_workers=2`, no queue |

Nothing here paginates a list endpoint because there are no list endpoints — the dashboard
reads a bounded tail of the log.

## Health Checks & Metrics

**`kekkai health` — deep check.** Backend constructed and model loaded (or Jev reachable with
a real credential), audit log writable, `verify_chain()` clean, policy parses. Intended to run
before an agent session, not per call.

**RED metrics**, emitted as audit events and aggregated by the dashboard:

- **Rate** — screenings/s, split by decision and by tier
- **Errors** — `ClassifierFailedClosed` rate (this is the user-pain signal: agents being blocked)
- **Duration** — p50/p95/p99 per backend and per tier, plus the prefilter-only path separately

**Domain-specific signal:** `PrefilterOverrodeClassifier` rate — the deterministic layer
blocking something the classifier rated safe. A rising rate is the in-production symptom of a
classifier-injection campaign.

This is measured by a **shadow check**: a binding rule still short-circuits, so the decision
costs no inference, and the classifier is asked afterwards, off the hot path, with the verdict
already fixed. Its budget (`shadow_budget_ms`, default 30 s) deliberately covers a cold model
load, because in a one-shot process the shadow is often the first thing to need the model at
all — a tight budget there protects nobody and silently loses the signal, which is how an
earlier version of this was found to be emitting nothing. Only disagreement is recorded;
logging every concurrence would bury the case worth alerting on. Backends that abstain (the
rule-only default) are never shadow-checked, since there is no opinion to disagree with.

**Alert on symptoms, not causes:** rising fail-closed rate (agents blocked), rising
prefilter-override rate (possible injection), breaker *staying* open. A breaker opening once is
expected output, not an incident.

## Deploy vs Release

KekkAI is a library, so "deploy" means a version bump in a consuming project.

- **Expand-contract applies to the audit record schema.** `SCHEMA_VERSION` is carried on every
  record; readers tolerate unknown fields, writers add fields and never remove or repurpose
  them. The dashboard and `verify` must keep reading records written by older versions.
- **Policy is data, not code.** A threshold or rule-severity change is a `ScreeningPolicy`
  change, not a release — the feature-flag equivalent, with no deploy required.
- **Rollback** is a version pin. The audit log written by a newer version stays readable by the
  older one, which is the constraint that makes rollback safe.
- **Chaos/failure injection** is designed as test cases, not production experiments: forced
  timeout, forced 429/529, forced malformed response, forced OOM, killed mid-write (torn line),
  and a saturated executor. These are Phase 7 test obligations.
