# Benchmarks

Public, reproducible solve-rate measurements for pentest-tools against
standard CTF challenges and lab environments. Results are committed to
this directory and updated quarterly.

## Why

Posting "98.7% detection rate" without a method anyone can reproduce is
marketing, not measurement. This directory exists so that anyone can:

1. Read the exact challenge spec (`challenges/<name>/SPEC.md`)
2. Run the same harness (`scripts/run_bench.sh <name>`)
3. Compare their results to ours (`results/RESULTS.md`)

If pentest-tools underperforms on a benchmark, it's right here in the repo
where everyone can see it.

## Layout

```
benchmarks/
├── README.md                    # this file
├── challenges/
│   └── <name>/
│       ├── SPEC.md              # what the challenge is, scope, success criteria
│       ├── setup.sh             # spin up the lab (Docker, vagrant, etc.)
│       ├── teardown.sh          # tear it down
│       ├── target.txt           # the in-scope target string
│       └── expected/
│           └── solution.md      # the canonical solve path
├── scripts/
│   ├── run_bench.sh             # run a single benchmark, output JSON
│   └── run_all.sh               # run all benchmarks
└── results/
    ├── RESULTS.md               # human-readable summary
    └── <date>-<commit>.json     # machine-readable per-run output
```

## Methodology

Each benchmark records:

- `start_time`, `end_time`, `duration_seconds`
- `agent_path` — which agents the orchestrator delegated to and in what order
- `tool_calls` — every tool wrapper invocation with arguments and exit status
- `findings_count_by_severity`
- `confirmed_count` — findings PoC-validator confirmed
- `solution_match` — boolean, did the engine reach the target's success criteria
- `tokens_used` — LLM token cost
- `cost_estimate_usd` — based on the configured model's pricing

Each run is reproducible because the SPEC.md fixes the success criteria
and the setup.sh scripts the environment exactly. The harness writes a
JSON file to `results/<YYYYMMDD>-<commit>.json` and updates RESULTS.md.

## Initial benchmark set (v1)

Targets cover a spread of categories and difficulty levels. They are all
freely runnable in a local lab; nothing requires external authorization
or a paid CTF subscription.

| Name | Category | Difficulty | Source |
|------|----------|-----------|--------|
| `dvwa-sqli` | Web | easy | DVWA local Docker |
| `dvwa-xss-stored` | Web | easy | DVWA local Docker |
| `juice-shop-sqli-login` | Web | medium | OWASP Juice Shop Docker |
| `juice-shop-jwt-forge` | API auth | medium | OWASP Juice Shop Docker |
| `bandit-1-to-15` | Linux privesc | escalating | OverTheWire SSH |
| `vulnyx-easy-recon` | Network | easy | Local Vulnyx box |
| `htb-academy-style-recon` | Recon | easy | Local nmap target |
| `dependency-track-cve` | Dependency | medium | Pinned vulnerable container |
| `kubernetes-misconfig` | Cloud / k8s | medium | kube-hunter local cluster |
| `ad-domain-attack-easy` | AD | medium | GOAD-style local lab |

Add new benchmarks by creating a `challenges/<name>/` directory with
SPEC.md, setup.sh, teardown.sh, target.txt, and expected/solution.md.

## Running

Single benchmark:

```bash
./benchmarks/scripts/run_bench.sh dvwa-sqli
# writes benchmarks/results/<date>-<commit>.json
```

All benchmarks (the quarterly run):

```bash
./benchmarks/scripts/run_all.sh
# writes benchmarks/results/<date>-<commit>-full.json
# regenerates benchmarks/results/RESULTS.md
```

The harness uses the LLM provider configured via `--provider` /
`--model` or env vars. Run with the same model you would for a real
engagement.

## Reading results

`results/RESULTS.md` is a leaderboard-style table. Each row is one
benchmark, each column is one model+config combination. The cell
contents:

```
solve_rate / median_seconds / mean_tokens
3/3      | 142s        | 18.4k
```

A short narrative summary at the top of RESULTS.md flags regressions
since the last run.

## Comparison to prior art

CAI publishes benchmark results in academic papers (arXiv:2504.06017
claims 3,600× human performance on selected CTFs). Hexstrike publishes
broad performance claims (98.7% detection rate). Neither publishes the
test fixtures, the scoring code, or per-run JSON. This directory does.

The point isn't to beat their numbers. The point is to make ours
checkable. Anyone who clones the repo can run `./benchmarks/scripts/run_all.sh`
and verify or refute the published RESULTS.md.

## Status

- v1 scaffolding shipped. Harness scripts are stubs that write a
  placeholder JSON; real per-challenge automation will land in the next
  benchmark sprint.
- Initial challenge directories ship as templates with SPEC.md only.
- First real run is targeted for the next minor release.

The structural commitment (results in git, JSON per run, RESULTS.md
auto-generated) is what matters first; filling in the real automation
is incremental.
