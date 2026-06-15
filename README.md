# VAPT Orchestrator Safe Lab

An offensive research scaffold for a **multi-agent web security orchestration system**.

This repository is designed for an academic project on **multi-agent orchestration and management for web application penetration testing**. It mirrors the high-level role separation used in MAPTA-style systems—**Coordinator / Sandbox / Validation**—but keeps execution in a **local offline lab** using recorded fixtures and source snapshots instead of probing real targets.

## What this project includes

- Multi-agent pipeline:
  - Intake Agent
  - Recon Agent
  - Signature/RAG Agent
  - Analyst Agent
  - Exploit Candidate Agent
  - Independent Validation Agent
  - Report Agent
- Shared memory with:
  - evidence store
  - task graph
  - artifact log
  - budget ledger
- Compressed RAG over local JSONL knowledge documents
- Model routing scaffold for per-skill model assignment
- Offline benchmark harness for comparing profile sets such as `gamma4_4b`, `gamma4_8b`, `gamma4_27b`
- Sample challenge fixtures for:
  - IDOR/BOLA-style authorization flaw
  - SSRF-style server-side fetch misuse
  - SQLi-style unsafe query construction

## What this project does **not** do

- It does not probe public IPs or public domains.
- It does not ship real exploitation tooling.
- It does not perform destructive actions.
- It does not include a weaponized exploit engine.

The default runner is intentionally restricted to **local fixture inputs** and **source snapshots** for safe research and benchmarking.

## Architecture

```text
Input (fixture or local source)
 -> Intake Agent
 -> Recon Agent
 -> Signature/RAG Agent
 -> Analyst Agent
 -> Exploit Candidate Agent
 -> Validation Agent
 -> Report Agent
```

The orchestration layer keeps shared state in a structured memory object:

- `task_graph`: status of agent tasks
- `evidence`: observations and compressed evidence cards
- `artifacts`: candidate PoCs and report files
- `budget`: tool calls, simulated tokens, elapsed time, simulated cost

## Install

```bash
cd vapt_orchestrator_safe
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick start

Run a single local fixture:

```bash
vapt-safe run --fixture data/fixtures/challenge_idor_01 --profile-set mixed_default
```

Run all fixtures with all configured profile sets:

```bash
vapt-safe benchmark --fixtures-dir data/fixtures --profiles configs/model_profiles.json --out outputs/benchmark_results.json
```

List profile sets:

```bash
vapt-safe profiles --profiles configs/model_profiles.json
```

## Example output

Each run produces an output directory under `outputs/`:

- `memory.json`
- `report.md`
- `report.json`
- `run_summary.json`

## Model routing

Model routing is implemented as a **profile abstraction**, not a vendor-specific dependency. A profile defines approximate per-skill strengths and simulated cost. You can use it to compare:

- all-small profile sets
- mixed routing by skill
- all-large profile sets

The sample config includes:

- `all_4b`
- `all_8b`
- `all_27b`
- `mixed_default`

## Extending the scaffold

Safe extension points:

- add more offline fixtures
- add more KB documents for RAG
- add more heuristics to recon/signature/validation
- add more model profile sets
- add visualizations for benchmark output

## Project layout

```text
configs/
  model_profiles.json
  system_skills.json
data/
  kb/
  fixtures/
src/vapt_orchestrator_safe/
  agents/
  engine/
  llm/
  memory/
  sandbox/
  utils/
tests/
```

## Research notes

This scaffold is aligned with the literature direction that separates **orchestration**, **tool execution**, and **proof-of-concept validation** for improved reliability and lower false positives. The uploaded MAPTA paper describes a Coordinator/Sandbox/Validation pattern, per-job isolation, and budget-aware orchestration, which motivated the structure used here.

## Suggested thesis experiments

1. Single-agent vs multi-agent
2. No-RAG vs compressed-RAG
3. No-validator vs independent-validator
4. Shared memory off vs on
5. `all_4b` vs `all_8b` vs `all_27b` vs mixed routing
6. Cost-aware early stopping on/off

## Limitations

- Benchmark results are only meaningful for the included offline fixtures unless you add your own lab data.
- The included model comparison is a **research scaffold** for orchestration experiments, not a claim about real-world model rankings.
- The PoC validator only checks against local fixture ground truth.

