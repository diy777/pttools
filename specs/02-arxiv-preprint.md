# Spec 02: arXiv preprint — pentest-tools architecture and benchmarks

**Status:** deferred
**Effort:** 20-30 hours of writing
**Revenue impact:** medium (citability, conference talk material)

## Goal

A 6-8 page preprint posted to arXiv (cs.CR) describing the architecture
and design decisions behind pentest-tools. Citable by future researchers,
basis for conference talk submissions, signal of engineering rigor that
matters for enterprise sales.

CAI's 9 papers are a structural moat we don't currently have. One
preprint won't close the gap, but it makes us citable and unblocks
conference submissions (DEF CON, Black Hat, USENIX, IEEE S&P).

## Outline

### Title
"pentest-tools: A Composable Open-Source Framework for Agentic Penetration
Testing with Reproducible Benchmarks"

### Abstract (200 words)
- Problem: agentic security frameworks claim large performance gains
  (3,600x human, 98.7% detection) but rarely publish reproducible
  benchmark methodology.
- Approach: pentest-tools ships a structurally-novel orchestration model
  with explicit scope enforcement, evidence contracts, SARIF output,
  and a public benchmark harness in `benchmarks/`.
- Contributions: (1) the AP framework as an open architecture pattern,
  (2) a reproducible benchmark suite anyone can run against any LLM,
  (3) integration of 200+ tool wrappers via a stable plugin API.
- Results: solve rates on 10 standard CTF-equivalent challenges across
  Anthropic, OpenAI, and local models. Cost vs success curves.

### 1. Introduction
- LLM-driven pentesting trajectory (cite PentestGPT 2308.06782, CAI
  2504.06017)
- Reproducibility gap in current claims
- Our contribution

### 2. Related Work
- PentestGPT (Deng et al., 2023)
- CAI (Mayoral-Vilches et al., 2024)
- Hexstrike-AI
- Traditional non-AI: OpenVAS, Nessus, BurpSuite

### 3. Architecture
- 3.1 Agent specialization model (12 specialist agents, BaseAgent
  ReAct loop)
- 3.2 Orchestration: scope enforcement (engine/scope.py), evidence
  contract (engine/evidence.py), tool registry (200+ wrappers)
- 3.3 Output formats: SARIF 2.1.0, JUnit XML, CVSS v3.1, MITRE ATT&CK
  mapping, compliance frame
- 3.4 Multi-LLM support via LiteLLM (300+ models)
- 3.5 Defensive perspective: every offensive technique paired with
  detection rules (Sigma, SPL, KQL)

### 4. Safety design
- Tier 1 / Tier 2 authorization model
- Scope guard at engine level
- Rate limiter for non-DoS guarantee
- Evidence handling (no exfiltration of finding bodies through
  telemetry; explicit blocklist of sensitive field names in
  engine/telemetry.py)

### 5. Benchmark methodology
- Reproducible spec format (`benchmarks/challenges/<name>/SPEC.md`)
- Per-run JSON output committed to git
- 10 initial challenges: DVWA-sqli, Juice Shop variants, OverTheWire
  bandit, vulnyx easy, AD lab, K8s misconfig
- Token cost reporting per run
- Comparison rubric vs human baseline (median time, false-positive rate)

### 6. Results
- Solve rates per challenge per model
- Time-to-first-finding distribution
- Cost analysis ($/successful solve)
- Failure mode taxonomy (timeout, scope misjudgment, false positive)

### 7. Limitations
- Current LLM autonomy ceiling (acknowledge HITL is necessary)
- Tool-installation prerequisites
- Scope enforcement requires honest user authorization claim
- Test set is small (10 challenges)

### 8. Future work
- Browser automation agent integration (cite our 2026-04-28 commit)
- OpenTelemetry tracing for execution-level observability
- On-prem desktop tier
- More benchmark challenges + community contributions

### 9. Conclusion
- pentest-tools is open, reproducible, and structurally distinct from
  existing closed-source claims
- Invitation to contribute benchmarks

### References
- ~25 entries spanning the academic LLM-security literature, the
  open-source frameworks we reference, and our own benchmarks repo

## Inputs (what already exists)

- 200+ tool wrappers in `tools/registry.py`
- 12 agent classes in `agents/`
- `engine/scope.py`, `engine/evidence.py`, `engine/sarif.py`,
  `engine/cvss.py`, `engine/compliance.py`, `engine/dedup.py`
- `benchmarks/` harness with first DVWA challenge
- 65 unit tests across LLM providers, dashboard, agents, hitl, mcp
  client, browser agent, tracing, telemetry
- `engine/llm/factory.py` with Anthropic/OpenAI/Ollama/LiteLLM providers
- `engine/hitl.py` for the HITL acknowledgement
- `engine/telemetry.py` opt-in
- `engine/tracing.py` OTel primitive

## Steps

### Phase 1: Run the benchmarks (1 week)

1. Set up local instances of all 10 challenges
2. Run each through pentest-tools with each of 4 model configs:
   - Anthropic Claude
   - OpenAI GPT-4o
   - DeepSeek (via LiteLLM)
   - Ollama local Llama 3.1 70B
3. Each run produces a JSON in `benchmarks/results/`
4. Auto-generate `benchmarks/results/RESULTS.md` table
5. Cherry-pick interesting runs for narrative

### Phase 2: Outline → first draft (1 week)

1. Use the outline above as a writing skeleton
2. Section 3 (architecture) draws from the existing engine docs
3. Section 5-6 (methodology + results) write from the benchmark JSONs
4. Aim for 6-8 pages two-column ACM style. Tighten section 1-2 to
   leave room for results.

### Phase 3: Review → revise (3 days)

1. Self-review for clarity and overclaiming
2. Send to 2-3 reviewers familiar with the field
3. Revise based on feedback

### Phase 4: arXiv submit (1 day)

1. Compile to PDF (LaTeX, acmart.cls)
2. Pre-flight via the arXiv check tool
3. Submit to cs.CR with the abstract above
4. Receive arXiv ID, link from README and pentest-tools.local

## Validation

- arXiv ID assigned and paper visible at arxiv.org/abs/<id>
- README has a "Citation" section with the bibtex
- pentest-tools.local adds a "Read the paper" link in the hero
- Conference talk submissions reference the paper

## Out of scope

- Peer-reviewed conference submission (separate, longer process)
- Funding acknowledgements (until we have grant funding to acknowledge)
- Comparison study claiming superiority over CAI/hexstrike (we don't
  have running access to either's full benchmark setups, and a poorly-
  scoped comparison would invite a justified rebuttal)

## How to resume

Paste this spec as the next-session prompt. Start with Phase 1 (run
the benchmarks) — that requires `pttools start` against each challenge
target, so it's hands-on and produces the data the paper needs.
