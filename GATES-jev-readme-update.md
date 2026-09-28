# Gates: update README with the latest Jev benchmarks and conclusion

OWNS: README.md

Scope: update README.md's Benchmarks section, Scope & honesty section, and
Roadmap so they report the two real Jev measurements now on disk
(`benchmarks/results/enterprise-jev.json` — native Jev, real TypeSafe
credential — and `benchmarks/results/openrouter.json` — OpenRouter's
`jev-router` proxy) with accurate figures and an honest conclusion, replacing
the current "Jev was never measured" claim.

- [x] G1: README states native Jev's measured figures from
      `benchmarks/results/enterprise-jev.json`, independently re-derived from
      that file at check time (p50 132.0ms, p95 280.7ms, p99 335.8ms, ECE
      0.193, AUC 0.813, block 0.0%, FPR 1.3%)
  CHECK: node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync('benchmarks/results/enterprise-jev.json','utf8'));const b=j.backends.find(x=>x.backend==='jev');const l=b.classifier_latency;const amb=b.gates.ambiguous_band;const need=[l.p50_ms.toFixed(1),l.p95_ms.toFixed(1),l.p99_ms.toFixed(1),b.calibration.ece.toFixed(3),b.discrimination_auc.toFixed(3),(amb.block_rate*100).toFixed(1),(amb.false_positive_rate*100).toFixed(1)];const readme=fs.readFileSync('README.md','utf8');const missing=need.filter(n=>!readme.includes(n));if(missing.length){console.log('MISSING:'+missing.join(','));process.exit(1);}console.log('JEV_NUMBERS_OK');"
  EXPECT: JEV_NUMBERS_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=7aee5b26c3fce128236d18d4a6a9614b9701277e83f99fef0fadeb0d88a5e313; exit=0; EXPECT=matched; output-sha256=9e21c15ff1d41cf42cc4b343fb3dbccffd73cc464010ac98a586a7876040c8f5; output-bytes=15; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G2: README states the OpenRouter `jev-router` proxy's measured figures
      from `benchmarks/results/openrouter.json`, independently re-derived at
      check time (p50 502.3ms, p95 645.7ms, p99 646.6ms, ECE 0.784, AUC
      0.500, block 100.0%, FPR 100.0%), and characterizes it as a
      latency/infra failure distinct from native Jev
  CHECK: node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync('benchmarks/results/openrouter.json','utf8'));const b=j.backends.find(x=>x.backend==='openrouter');const l=b.classifier_latency;const amb=b.gates.ambiguous_band;const need=[l.p50_ms.toFixed(1),l.p95_ms.toFixed(1),l.p99_ms.toFixed(1),b.calibration.ece.toFixed(3),b.discrimination_auc.toFixed(3),(amb.block_rate*100).toFixed(1),(amb.false_positive_rate*100).toFixed(1)];const readme=fs.readFileSync('README.md','utf8');const missing=need.filter(n=>!readme.includes(n));if(missing.length){console.log('MISSING:'+missing.join(','));process.exit(1);}if(!/jev-router/.test(readme)){console.log('MISSING_LABEL');process.exit(1);}console.log('OPENROUTER_NUMBERS_OK');"
  EXPECT: OPENROUTER_NUMBERS_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=e6b97efc97ab5f11220c61810c0a6a32c6513ddd44de1907c35fd3cb11988fe2; exit=0; EXPECT=matched; output-sha256=7fb57d0ce7738a6fd550f82e07c6a710d4c412e2d44f8e867d393c9c050f9970; output-bytes=22; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G3: the stale "Jev was never measured" / "not measured" claims are gone
      from README.md
  CHECK: node -e "const fs=require('fs');const readme=fs.readFileSync('README.md','utf8');const bad=[/Jev was never measured/,/\*not measured\*/];const hit=bad.filter(r=>r.test(readme));if(hit.length){console.log('STALE_CLAIM_PRESENT');process.exit(1);}console.log('STALE_CLAIM_GONE');"
  EXPECT: STALE_CLAIM_GONE
  EVIDENCE: automatic-evidence=v1; definition-sha256=5683cc21210783be02cff95fc94906d606e1b482de281ec2f17d588abcb12950; exit=0; EXPECT=matched; output-sha256=a688e9a7e1e9875a163080ac89387f946dc2148371e9d0c8696767b7f86bec5f; output-bytes=17; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G4: the roadmap no longer lists "measure Jev" as outstanding work
  CHECK: node -e "const fs=require('fs');const readme=fs.readFileSync('README.md','utf8');const m=readme.match(/## Roadmap\n([\s\S]*?)\n## /);const section=m?m[1]:'';if(/measure jev/i.test(section)){console.log('ROADMAP_STALE');process.exit(1);}console.log('ROADMAP_OK');"
  EXPECT: ROADMAP_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=7302b5ea423b2d3a6572925688764e142082e62a6b266522b77499aa626a3ae9; exit=0; EXPECT=matched; output-sha256=189e179576e4f769a29a21dbaf66df0480b5f2c91d5c60912a1b1815870ec489; output-bytes=11; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G5: the written conclusion is honest and consistent with the source
      data — both runs still show `"passed": false` on every gate, so the
      README must not claim Jev was promoted or that any threshold cleared
      the gate; it must state the actual reason (compressed/miscalibrated
      probability scale despite real discrimination) rather than a vaguer or
      more favorable gloss — manual re-read against
      `benchmarks/results/enterprise-jev.json` and
      `benchmarks/results/openrouter.json`, no command can judge prose
      honesty
  EVIDENCE: manual-review-v1; re-read the full "## Benchmarks" section
    (main table + new "### Jev, measured directly" subsection) and the
    updated "Scope & honesty" bullet and "## Roadmap" against both
    benchmarks/results/enterprise-jev.json and
    benchmarks/results/openrouter.json line by line. Confirmed: (1) both
    files' ambiguous_band.passed is false and the README states "FAIL" for
    both rows and says "none promoted" / never claims promotion or a
    cleared gate; (2) jev's tp=0/fn=75/fp=1/tn=74 matches "blocked zero of
    75 malicious records" and FPR 1.3%; (3) calibration bins 0.2-0.3=65.22%,
    0.3-0.4=75%, 0.6-0.7=85.71%, 0.7-0.8=90% malicious support the written
    "malicious rates of 65-90% in score ranges as low as 0.2-0.8"; (4) the
    reconstructed Youden's-J sweep (threshold ~0.2 -> 62/75 block=82.7%,
    23/75 fpr=30.7%) matches the written "82.7% block rate at 30.7% false
    positives", and no threshold in the sweep clears 98%/2%, matching "no
    cutpoint rescues it"; (5) openrouter's classifier_calls=195 and
    deadline_exceeded_calls=195 matches "195 of 195 calls exceeded the 500
    ms escalated deadline"; (6) the "Scope & honesty" bullet and Roadmap no
    longer assert Jev is unmeasured and correctly flag the two runs as
    non-comparable to each other and to the 213-record table. No
    overclaiming (nothing promoted, no threshold declared to clear the
    gate) and no underclaiming (Jev's real AUC 0.813 discrimination is
    stated, not hidden) found.

<!--
Definition of done: every runnable gate exits 0 with its EXPECT token, and G5
is reviewed by re-reading the final README section against both JSON files
before reporting completion.
-->
