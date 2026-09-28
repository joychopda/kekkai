# Gates: remove the OpenRouter classifier wiring

OWNS: kekkai/adapters/classifiers/__init__.py, kekkai/adapters/classifiers/openrouter.py, pyproject.toml, .env, .env.example, README.md, GATES.md, benchmarks/results/openrouter.json

Scope: fully remove the OpenRouter backend (`kekkai/adapters/classifiers/openrouter.py`,
its registration, its `pyproject.toml` extra, its env-var scaffolding, and its
now-orphaned benchmark artifact) since it never worked (timed out on every
call), update README.md so it no longer documents a backend that no longer
exists in the codebase, and confirm nothing else in the repo broke.

- [x] G1: the openrouter adapter file and its import/registration are gone
  CHECK: node -e "const fs=require('fs');if(fs.existsSync('kekkai/adapters/classifiers/openrouter.py')){console.log('FILE_STILL_PRESENT');process.exit(1);}const init=fs.readFileSync('kekkai/adapters/classifiers/__init__.py','utf8');if(/openrouter/i.test(init)){console.log('INIT_STILL_REFERENCES');process.exit(1);}console.log('ADAPTER_REMOVED');"
  EXPECT: ADAPTER_REMOVED
  EVIDENCE: automatic-evidence=v1; definition-sha256=822ab04424eedab12f23a53900a3a07da3c1bd7ec82fc7d39c3b95efc8383f86; exit=0; EXPECT=matched; output-sha256=ce7c26460ebb37850519c672368653d2a6a61fbbb99c52757f0c84b86cbe898a; output-bytes=16; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G2: `openrouter` is gone from `pyproject.toml`'s optional-dependencies,
      and the package still declares valid TOML
  CHECK: .venv/bin/python -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb')); deps=d['project']['optional-dependencies']; import sys; sys.exit(1) if 'openrouter' in deps else print('PYPROJECT_CLEAN')"
  EXPECT: PYPROJECT_CLEAN
  EVIDENCE: automatic-evidence=v1; definition-sha256=aa86d9443096b0c2715944cb53aab441d8d69a6ad4b69f0962946c51048669c6; exit=0; EXPECT=matched; output-sha256=2ee07391517693a2b0528b0a4288cc2facc59bc4bcfda4a1867506c962fc1d36; output-bytes=16; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G3: the full test suite still passes with the adapter removed (no
      import errors, no test that assumed the backend existed)
  CHECK: .venv/bin/python -m pytest -q && echo TESTS_ALL_PASSED
  EXPECT: TESTS_ALL_PASSED
  EVIDENCE: automatic-evidence=v1; definition-sha256=caa65946688f21c0095ac9fcea891efb57a9fd89618f2065fa17fa9ba4b35f4a; exit=0; EXPECT=matched; output-sha256=05afe51538aaab2d041b49003ad41e1de5bfcd6298cf2dee9df3002f0c7f3067; output-bytes=277; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G4: `kekkai backends` still lists every remaining backend and does not
      list `openrouter`, proving the registry import chain still works
      end-to-end after the removal
  CHECK: .venv/bin/python -m kekkai.cli backends
  EXPECT: deterministic
  EVIDENCE: automatic-evidence=v1; definition-sha256=d56e7545d5ae786a899e09a8049b2dfc6096c774db1879ca4f3e621f920930c1; exit=0; EXPECT=matched; output-sha256=f43d33af382db8b841b9b6199256bd0fddef8cfa4b6571391e016d3cd0feae24; output-bytes=225; shell=/bin/sh; cwd=/Users/agent-j/the-future/kekkai; path=e9f4c0da82be/15 entries

- [x] G5: README.md no longer references the removed `openrouter` backend or
      `jev-router` as a currently-wired path (only, if at all, as clearly
      past-tense history of a removed attempt) — manual re-read, since a
      keyword grep can't distinguish "this exists" from "this was tried and
      removed"
  EVIDENCE: manual-review-v1; grep for jev-router/OpenRouter in README.md
    after all edits finds exactly two remaining mentions, both in clearly
    past-tense framing: (1) the "Jev, measured directly" conclusion
    paragraph — "A third path was tried and removed: routing Jev through
    OpenRouter's jev-router listing... so that path was pulled from the
    codebase rather than kept as dead weight"; (2) the "Scope & honesty"
    bullet — "An OpenRouter proxy path was also tried and measured...and has
    since been removed from the codebase". Confirmed no remaining Reproduce
    block, table row, or command references `--backends openrouter` or
    `benchmarks/results/openrouter.json` (grep for both strings: zero
    matches). No mention reads as though the backend is still callable.

<!--
Definition of done: G1-G4 exit 0 with their EXPECT token, and G5 is reviewed
by re-reading every remaining OpenRouter/jev-router mention in README.md to
confirm each is unambiguously past tense before reporting completion.
-->
