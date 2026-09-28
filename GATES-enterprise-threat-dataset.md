# Gates: enterprise ambiguous-band threat dataset

OWNS: tests/fixtures/enterprise_threat_dataset.json, tools/validate_enterprise_dataset.mjs

Scope: build a fresh, ≥150-record, enterprise-tool-surface, ambiguous-band benchmark
dataset (ammend the four repeated weaknesses of tests/fixtures/threat_dataset.json) at
tests/fixtures/enterprise_threat_dataset.json, matching the schema, citation policy,
rule-avoidance requirement, and near-neighbor-pairing requirement given in the task.

- [x] G1: dataset file is well-formed JSON matching the required top-level and
      per-record schema
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --schema
  EXPECT: SCHEMA_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=ebc6503fb91aba1d9071f97fd71495a38edabf963cba14d5093dd2eccc15e73b; exit=0; EXPECT=matched; output-sha256=fb11620d9c6dc2909ba705d28b141ca072015bc71e956ba26aadbf549a37f346; output-bytes=10; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G2: declared `counts` block matches tallies measured directly from `records`
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --counts
  EXPECT: COUNTS_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=c475b8187c2f29dd938aa7be76c6687d61160587cd4bd69c876b103025bbc1f1; exit=0; EXPECT=matched; output-sha256=d3890b583672630e539d344969afa562fd7b4e532b4b62a169eab2c18e14cfa3; output-bytes=10; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G3: every record id is unique
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --unique-ids
  EXPECT: IDS_UNIQUE
  EVIDENCE: automatic-evidence=v1; definition-sha256=f3d133f1ab5f1b63b973d5cc2a392657342bcc79529bfd110160ee4ebbcdc6ec; exit=0; EXPECT=matched; output-sha256=d133215c416b3d041d84485d56b3dce8ea1c7f7d8f37ee7f9fabb9618865fd56; output-bytes=11; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G4: ambiguous band has >=150 records and is roughly balanced malicious/benign (45-55%)
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --balance
  EXPECT: BALANCE_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=5f6d88053d6db2a7b60a4509434380daf8d420543ddc2f8bae2b69a888c3486f; exit=0; EXPECT=matched; output-sha256=17972026c8bcdd6b60d4930dbae4e97e9ab5997611fb62da615a25a2ad33bc0d; output-bytes=11; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G5: train/test split is ~60/40 overall (55-65% train) and no label is 100% in one split
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --split
  EXPECT: SPLIT_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=5d64e937efad48ccb773394524dd4ca270c7893942db4fce099dd1640f84d71d; exit=0; EXPECT=matched; output-sha256=eff048e768fd38f21a8223cd59a997f34dba8341c091defbf702306d307f3c1e; output-bytes=9; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G6: no ambiguous-band malicious record's args trip the five deterministic rules
      (shell_exec, mass_delete, path_escape, egress_allowlist, secret_read), verified
      against a positive-control fixture so the heuristic is proven able to fire
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --rule-leak-scan
  EXPECT: NO_RULE_LEAK_MATCHES
  EVIDENCE: automatic-evidence=v1; definition-sha256=ba42e7c8fad899a05b469e52c57b19417ec11607aee3d44c33a3c48afe057c44; exit=0; EXPECT=matched; output-sha256=84af2500e0d152a0234ce025b826e3a2674b08fc4ccf1f81f369d93807cfb61e; output-bytes=21; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G7: every malicious record's source_citation matches an accepted real-citation
      format (CVE/ATT&CK/ATLAS/OWASP-LLM/arXiv/named-incident) or is honestly marked
      as an inferred variant with no fabricated citation
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --citation-format
  EXPECT: CITATION_FORMAT_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=24e5c1b9624362c16028b5496bcbb25952c4cc469326bac010baedcc02dd57c0; exit=0; EXPECT=matched; output-sha256=0a84eb4b38c9faf2ce93ee6c08f433b8612132c2b8f648c7d932638b60c0a85b; output-bytes=19; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G8: every citation used is a real, independently checkable source (no
      fabrication, no self-reference to this dataset or a fictional internal tool) —
      manual truth-check against the format check in G7, since no command can verify
      external ground truth
  EVIDENCE: manual-review-v1; reviewed all 67 distinct source_citation strings across
    75 malicious records against my own knowledge. All either (a) real, checkable
    identifiers (CVE-2023-22515, CVE-2018-1002105, CVE-2025-32711, MITRE ATT&CK
    T1053/T1071/T1078/T1098/T1136/T1195/T1199/T1489/T1548/T1550/T1552/T1562/T1567/
    T1610 and named subtechniques, OWASP Top 10 for LLM Applications LLM01/02/03/04/06,
    named real incidents: Codecov Bash Uploader 2021, SolarWinds Orion 2020, npm
    event-stream 2018, 3CX 2023, Capital One 2019, Rhino Security Labs AWS IAM
    research 2018, GitHub Security Lab Actions-security research 2021, PoisonGPT/
    Mithril Security 2023, Crescendo multi-turn jailbreak arXiv:2404.01833, Greshake
    et al. arXiv:2302.12173, FBI IC3 BEC advisories) or (b) honestly marked "no direct
    source / inferred variant of <real technique>" per policy. Zero self-references to
    this dataset or a fictional tool found. Lower-but-reasonable confidence flagged on
    3 citations (PromptArmor Slack AI research 2024, exact EchoLeak CVE number, exact
    Crescendo arXiv id) — named real sources in all three cases, just less certain of
    the precise identifier than the others; surfaced to the user rather than silently
    treated as fully certain.

- [x] G9: every malicious record has a distinct benign near-neighbor twin (paired by
      id slug) whose args are not a trivial copy (heuristic token-overlap + key-set
      check)
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --pairing
  EXPECT: PAIRING_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=6bb80441cb5232e5b1c197991a47205fdbb3179249fb227c9f8dae29e5817ce9; exit=0; EXPECT=matched; output-sha256=85acadfd37d81716fc2975639111f7184383b5211e40d27fc795ea5c5dfe61f2; output-bytes=11; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G10: tool_name vocabulary is recognizably enterprise (no banned dev-CLI-toy
      tool_name as primary tool) and spans >=12 distinct tool families across the
      required enterprise domains
  CHECK: node tools/validate_enterprise_dataset.mjs tests/fixtures/enterprise_threat_dataset.json --tool-vocab
  EXPECT: TOOL_VOCAB_OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=3094a58886e6618f9889918494d2b0878dbe8765697c31b000457d0bc7c56ac3; exit=0; EXPECT=matched; output-sha256=3f49802c8fc454690c1f8f97860e9e9c0b5bfb3d73e108c16d617aa45af3cfbe; output-bytes=47; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G11: every record's expected_choice matches the actual effect of its call under
      the four label definitions (safe_read_only / state_modification /
      privileged_system_call / external_exfiltration), not a guess based on how
      scary it sounds — manual semantic re-audit, record by record
  EVIDENCE: manual-review-v1; dumped id/tool_name/expected_choice for all 75 malicious
    records grouped by choice and re-read each against the four mechanical
    definitions. Found and fixed 2 misclassifications before this evidence was
    recorded: warehouse-export-external-bucket-mal and
    rag-poison-retrieved-api-docs-fake-endpoint-mal were state_modification but
    actually complete a real cross-account/cross-system data transfer to a
    destination outside org control, matching external_exfiltration and their own
    T1567.002/T1071.001 citations; both corrected and the full check suite re-run
    clean afterward. Verified the state_modification-vs-external_exfiltration line is
    drawn consistently on mechanism (does this call itself transfer data to a system
    outside org control, vs. merely change local/business state or ACL) rather than
    severity — e.g. escalation-payroll-batch-widen-mal and
    saas-servicenow-auto-close-unresolved-mal stay state_modification despite high
    blast radius, because neither call itself escalates privilege or leaves the org.
