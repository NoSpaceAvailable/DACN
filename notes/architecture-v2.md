# DACN architecture v2 (post-advisor-meeting 2026-04-18)

**Status:** DRAFT — supersedes `architecture-v1.md`. Synthesises 9 directives + 4-layer diagram + "Claude-CLI single-supervisor" insight from thầy Khoa.

**Working name:** placeholder (thầy chốt sau).

---

## 1. Top-line claim (revised)

DACN proposes a **4-layer multi-agent web pentest framework** centred on a **single LLM-driven Dispatcher** (analogous to Claude Code's main loop) coordinating specialised worker agents over a thread-safe Blackboard. Two contributions push beyond Red-MIRROR / MAPTA / PentestGPT:

- **C1 — Mid-thinking intervention**: ability to inject hints / corrections / forced pivots **while the LLM is still streaming its reasoning**, rather than waiting for the full response. Existing systems all wait for `eos`.
- **C2 — Anti-loop guard**: signature-based loop detector on (action, target, payload) triples; on N repeats forces a strategy pivot via the Dispatcher.

Plus 1 cost-reduction lever:
- **C3 — Knowledge-graph RAG** built from input + corpus, replaces raw-text retrieval to cut tokens per query.

All wrapped in a **LangChain backend abstraction** so any of {Ollama, OpenRouter, OpenAI, Anthropic} swaps without code change.

Benchmark target: **≥80%** of `gpt-5-mini` and `claude-sonnet` on our HTB-derived benchmark, using a smaller / cheaper backbone.

---

## 2. Layered architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ INPUT: IP / source-tree path / CVE ID                            │
└─────────────────────────┬────────────────────────────────────────┘
                          │
┌─────────────────────────▼─────── ORCHESTRATION LAYER ───────────┐
│                                                                  │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │ Dispatcher  │◄──│  Blackboard  │──►│  Model Selector      │  │
│  │ (LLM agent, │   │ - shared mem │   │ - per-task routing   │  │
│  │  Claude-CLI │   │ - thread-safe│   │ - cost/latency budget│  │
│  │  style)     │   │ - phase      │   │ - fallback chain     │  │
│  │             │   │   contexts   │   │   (claude-s ⇒ gpt5m  │  │
│  │             │   │ - KG handle  │   │    ⇒ gemma27b ⇒ 4b)  │  │
│  └─────┬───────┘   └──────────────┘   └──────────────────────┘  │
└────────┼─────────────────────────────────────────────────────────┘
         │ supervisor decides: which agent?  which tool?  pivot?
         ▼
┌─────────────────────────────────── AGENT LAYER ────────────────┐
│                                                                  │
│  ┌──────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐      │
│  │ Recon    │ │ Analyst   │ │ Exploit   │ │ Report       │      │
│  │ nmap+    │ │ CVE match │ │ PoC gen + │ │ aggregate +  │      │
│  │ whois +  │ │ + RAG     │ │ tool exec │ │ severity     │      │
│  │ ports    │ │ + KG hop  │ │ + validate│ │ score        │      │
│  │ default: │ │ default:  │ │ default:  │ │ default:     │      │
│  │ claude-s │ │ gemma-27b │ │ claude-s  │ │ gemma-4b     │      │
│  └──────────┘ └───────────┘ └───────────┘ └──────────────┘      │
│  All agents subclass BaseAgent (LangChain ChatModel + tools).   │
└──────────────────┬───────────────────────────────────────────────┘
                   │ each agent uses Tool & RAG layer
        ┌──────────┴───────────┐
        ▼                      ▼
┌─── TOOL LAYER ──────┐  ┌─── RAG LAYER ───────────────────────────┐
│ Security tools      │  │ Knowledge base                          │
│  nmap / sqlmap /    │  │  - CVE docs (NVD)                       │
│  burpsuite-cli /    │  │  - Researcher writeups                  │
│  curl / ffuf        │  │  - Public PoCs (Exploit-DB, GitHub)     │
│ Sandbox             │  │  - Semantic chunks (LlamaIndex)         │
│  - Docker isolated  │  │ Vector store                            │
│  - Vulhub targets   │  │  - LlamaIndex / top-k retrieval         │
│  - net=none         │  │  - CVE filtering, framework-aware       │
│  - ephemeral        │  │ Knowledge graph (NEW per thầy)          │
│ All tools subclass  │  │  - Entities: CVE, payload, oracle,      │
│ BaseTool (sync       │  │    framework, sink, source             │
│  invoke + result)   │  │  - Edges: exploits, fingerprints,       │
│                     │  │    bypassed-by, evidence-of             │
│                     │  │  - Built once per run from input,       │
│                     │  │    queried by agents in O(hop) tokens   │
└─────────────────────┘  └─────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│ OUTPUT: bug report (markdown) + PoC artefacts + CVSS/severity    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Component spec

### 3.1 Orchestration Layer

#### 3.1.1 Dispatcher (the "Claude-CLI agent")

LangChain `AgentExecutor` (or LangGraph supervisor) backed by an LLM. **NOT** a state machine. Each turn it observes the Blackboard, calls one tool *(invoke sub-agent)* or *(invoke security tool)* or *(query KG/RAG)* or *(stop and report)*. System prompt encodes the engagement goal + safety rules. Supports `stream=true` so the model selector can intervene mid-thinking (see §3.4).

Tool list exposed to Dispatcher:
- `invoke_recon(targets) → Blackboard delta`
- `invoke_analyst(evidence) → hypotheses`
- `invoke_exploit(hypothesis) → PoC + verdict`
- `invoke_report() → markdown`
- `query_kg(question) → triples`
- `query_rag(query, k) → chunks`
- `pivot(reason)` → reset short-term plan, used by anti-loop guard

#### 3.1.2 Blackboard

Thread-safe singleton-per-run. Sections:
- `evidence` — raw + summarised observations (existing)
- `task_graph` — DAG of attempted/succeeded tasks (existing)
- `artifacts` — PoC scripts, captured responses (existing)
- `events` — append-only audit log (existing)
- `budget` — token + wall-clock + tool-call counters (existing)
- `kg_handle` — pointer to knowledge graph instance (NEW)
- `phase_context` — per-phase sub-blackboard (recon / analyst / exploit / report) for phase-scoped scratchpads (NEW)
- `loop_signatures` — circular buffer of `hash(action,target,payload)` for anti-loop (NEW)

Concurrency: stdlib `threading.RLock`; agents may run in parallel sandbox jobs.

#### 3.1.3 Model Selector

Maps `(agent_role, task_difficulty, remaining_budget)` → backend choice. Uses the existing `ModelRouter` capability table but extended with **fallback chain**:
```
claude-sonnet ($)  →  gpt-5-mini ($)  →  gemma-27b (local)  →  gemma-4b (local)
```
On `RateLimitError`, `Timeout`, or budget breach → degrade one step.

### 3.2 Agent Layer

Single `BaseAgent` (LangChain `Runnable`):
- Accepts a LangChain `BaseChatModel` (Ollama / OpenAI / Anthropic / OpenRouter) — backend swap is just config.
- Has system prompt loaded from `prompts/<role>.md` (the loader from D3 is reused).
- Bound tools from the Tool Layer.
- Reads/writes Blackboard via dependency injection.
- Implements `__call__(blackboard) → blackboard_delta`.

Concrete agents:
- **Recon** — tools: `nmap`, `whois`, `httpx`, `dirsearch`. Prompt focuses on attack surface enumeration. Default model: claude-sonnet for quality, fallback gemma-8B.
- **Analyst** — tools: `query_kg`, `query_rag`, `lookup_cve`. Generates ranked hypotheses with rationale. Default: gemma-27B (if avail) or claude-sonnet, fallback gemma-8B.
- **Exploit** — tools: `run_python_in_sandbox`, `curl`, `sqlmap`, `burpsuite-cli`, `validate_oracle`. Default: claude-sonnet (best at code), fallback gemma-8B.
- **Report** — tools: none, just LLM. Aggregates Blackboard into markdown + CVSS. Default: gemma-4B (cheap, format-stable).

### 3.3 Tool Layer

Single `BaseTool` (subclass LangChain `BaseTool`):
- `name`, `description`, `args_schema` (pydantic).
- `_run(...)` synchronous; `_arun(...)` async.
- Wraps subprocess / HTTP calls.
- Returns `ToolResult` dataclass with `stdout`, `stderr`, `exit_code`, `duration_ms`, `truncated`.
- Auto-truncates large output; pushes full output to Blackboard `artifacts` and feeds the LLM only a compressed summary (token saver).

Concrete tools (Sprint 3 onward):
- `NmapTool`, `WhoisTool`, `HttpProbeTool`, `CurlTool`, `SqlmapTool`, `BurpSuiteCliTool`, `FfufTool`
- `RunPythonInSandboxTool` (Docker per-job)
- Specialised (Sprint 5+, was "B-Tools" in v1): `BlindTimingSamplerTool`, `BooleanBlindOracleTool`, `Z3SolveTool`, `HashcatTool`, `JwtAlgConfusionTool`

Sandbox: per-job Docker container as in MAPTA (`network=none` static, `bridge` dynamic, `egress=metadata` for SSRF tests).

### 3.4 Novel mechanisms

#### C1 — Mid-thinking intervention

Standard LangChain agents wait for the full LLM response, then react. Our Dispatcher uses **streaming + watchdog**:

```
stream = chat_model.astream(prompt, ...)
buffer = []
async for chunk in stream:
    buffer.append(chunk)
    text = ''.join(buffer)

    # Watchdog 1 — anti-loop: same proposed action sequence as before?
    if loop_detector.matches(extract_proposed_action(text)):
        await stream.cancel()
        inject_pivot_directive_and_restart(text, reason="loop")
        break

    # Watchdog 2 — out-of-scope: model heading toward forbidden target / payload?
    if scope_guard.violated(text):
        await stream.cancel()
        inject_correction("stay within scope")
        break

    # Watchdog 3 — going wrong direction (e.g., 1500 tokens of CoT without
    # mentioning the actual target)?
    if drift_detector.score(text) > threshold:
        await stream.cancel()
        inject_focus_directive(text)
        break
```

This is *new* w.r.t. PentestGPT/Red-MIRROR/MAPTA — they all run synchronous "complete → react".

#### C2 — Anti-loop guard

`loop_signatures` is a circular buffer (size 32) of `hash(action_kind, target, payload_first_64_bytes)`. When the same hash appears `≥ 3` times within the buffer, the guard:

1. Cancels current stream / aborts current sub-agent.
2. Logs the loop pattern to the Blackboard.
3. Forces the Dispatcher to call `pivot(reason="loop on X")`, which:
   - Trims the recent context aggressively
   - Selects a different attack family from Analyst's hypothesis ranked list
   - Starts a fresh sub-agent invocation with the pivot directive in the system prompt

Existing systems either retry blindly (VulnBot, AutoPT) or rely on Inter-reflection vote (Red-MIRROR) which still loops within the same family.

#### C3 — Knowledge-graph RAG (token-efficient)

**Stack**: **Neo4j 5.x trong Docker container** (per advisor decision 2026-04-18). Driver: `neo4j` Python package (official). Schema bootstrapped via Cypher migration files (`infra/neo4j/init/*.cypher`).

**Build phase** (once per run):
- Parse input (HTTP transcript, source files, CVE ID) → extract entities (`Endpoint`, `Parameter`, `Sink`, `Source`, `Framework`, `CVE`, `Payload`).
- LLM-assisted entity-relation extraction (cheap small-model pass).
- Materialise vào Neo4j qua Cypher `MERGE` statements. Blackboard giữ `kg_handle` = Neo4j driver session.

**Query phase** (per agent need):
- Agents call `query_kg(question)` → LLM-translated to Cypher → execute → return triples.
- Returns a small set of triples (e.g., 5-20 facts) instead of dumping the raw transcript.
- For analyst: `MATCH (c:CVE)-[:EXPLOITS]->(s:Sink) WHERE s.framework="Spring" RETURN c.id, c.payload, c.oracle` returns ~50 tokens vs ~5000 tokens of raw RAG chunks.

**Hybrid fallback**: if KG miss → fall through to vector RAG (LlamaIndex) for unstructured chunks.

**Why Neo4j in Docker not networkx**: per directive — easier reset / persistence between runs / Neo4j Browser for visual debug khi dataset lớn / scale qua nhiều run mà vẫn share cumulative knowledge.

### 3.5 Dataset (per directive #9)

Two corpora:

**A. Evaluation tasks** — start with HTB lab + Vulhub (per Red-MIRROR), grow to XBOW (per MAPTA). Each task: `manifest.json + ground_truth.json + (optional) source/`.

**B. Knowledge corpus** — token-efficient entries built from:
- **NVD CVE JSON** → distilled to: `{cve_id, cwe, vuln_class, framework, attack_vector, affected_versions, condensed_description (≤80 tokens)}`.
- **Researcher writeups** (HackerOne disclosed, Exploit-DB, ProjectDiscovery PDResearch, PortSwigger blog) → extracted to: `{cve_or_class, target_stack, payload_template, placement, oracle, references}` (≤200 tokens each).
- Total budget per entry: ≤300 tokens. Aim for ~5,000 entries → ~1.5M tokens of corpus.

Indexed twice:
- Vector index (LlamaIndex + bge-m3 embeddings) for free-text queries.
- Knowledge graph (neo4j or networkx) for structured queries.

---

## 4. LangChain backend matrix

| Backend | LangChain class | Use case |
|---|---|---|
| Ollama (VPS gemma4:e2b) | `ChatOllama` | Dev + cheap local fallback |
| OpenAI gpt-5-mini | `ChatOpenAI` | Benchmark baseline + cost-optimised production |
| Anthropic claude-sonnet | `ChatAnthropic` | High-reasoning agents (Recon, Exploit) per diagram |
| OpenRouter (any) | `ChatOpenAI(base_url=openrouter)` | Cheap access to gemma-27B etc. without GPU |

Backend chosen at Model Selector level, not hard-coded per agent. Single env var `LLM_BACKEND_<role>=anthropic:claude-sonnet|openai:gpt-5-mini|ollama:gemma4:e2b|openrouter:google/gemma-3-27b`.

**API budget (confirmed 2026-04-18)**: tự bỏ tiền — Sprint 2 chỉ build wrapper, chưa cần test gọi API thật. Test phase chỉ activate khi pipeline đã hoàn chỉnh và sẵn sàng benchmark. Default dev backend vẫn là Ollama VPS để khỏi tiêu credit khi smoke test.

**Switch via single env var**: user đổi backend chỉ bằng 1 env var (theo directive). Đề xuất:
```
LLM_BACKEND_DEFAULT=ollama:gemma4:e2b
LLM_BACKEND_RECON=anthropic:claude-sonnet      # override per role nếu muốn
LLM_BACKEND_EXPLOIT=openai:gpt-5-mini
# hoặc cùng URL khác:
LLM_BACKEND_DEFAULT=openrouter:google/gemma-3-27b   # OpenAI-compatible URL
```
Tất cả backend OpenAI-compatible (OpenRouter, vLLM, LM Studio) đi qua `ChatOpenAI(base_url=...)` của LangChain — chỉ thay URL, không cần thay code.

---

## 5. Migration from D2-D3 code

| Existing | Status | Action |
|---|---|---|
| `OllamaModel` adapter | ✅ works | Wrap with `ChatOllama` adapter shim or deprecate. Logic about timeout/error handling is reusable. |
| `prompts/` template loader (`string.Template`) | ✅ works | Keep as-is; system prompts for new BaseAgent live here. |
| `utils/llm_json.py` | ✅ works | Keep; Tool layer also needs this for parsing tool-output JSON. |
| `agents/recon.py` LLM-driven path | ✅ works (with fallback) | Refactor as LangChain agent with bound `NmapTool` etc. instead of single-shot generate. Heuristic fallback can stay as `BaseAgent.fallback()` hook. |
| `engine/orchestrator.py` linear flow | ✅ works | Replace with Dispatcher (LangGraph supervisor). Linear orchestrator stays as `LegacyOrchestrator` for regression. |
| `memory/shared_memory.py` | ✅ works | Upgrade in-place: add `RLock`, `phase_context`, `kg_handle`, `loop_signatures`. |
| `engine/router.py` capability table | ✅ works | Becomes the input to Model Selector with fallback chain. |
| `tests/*` 36 passing | ✅ works | Keep; new tests added per new component (BaseAgent, BaseTool, Blackboard, KG, anti-loop, mid-thinking). |
| `infra/vps-setup.sh` | ✅ works | Unchanged; Ollama still primary local dev backend. |

**Zero throwaway** — every D2-D3 file maps cleanly into v2.

---

## 6. Roadmap (revised)

| Sprint | Tuần | Focus | Deliverable |
|---|---|---|---|
| Sprint 1 (DONE) | W1-2 | Ollama integration, recon LLM-driven | 36 tests pass, end-to-end pipeline through gemma4 |
| **Sprint 2** | W3 | LangChain migration foundation | `BaseAgent`, `BaseTool`, `Blackboard` (refactor), backend factory for ollama/openai/anthropic/openrouter; smoke test 1 backend swap |
| **Sprint 3** | W4 | Dispatcher (Claude-CLI style) | LangGraph supervisor; replaces linear orchestrator; existing 4 agents wired as supervisor tools |
| **Sprint 4** | W5 | Tool layer + Docker sandbox | `NmapTool`, `CurlTool`, `SqlmapTool`, `RunPythonInSandboxTool`; per-job Docker isolation |
| **Sprint 5** | W6 | RAG + Knowledge Graph | LlamaIndex KB, KG entity-relation extraction, `query_kg` / `query_rag` tools |
| **Sprint 6** | W7 | C1 + C2 (novel) | Streaming watchdog (drift/scope/loop), anti-loop guard, `pivot` mechanism |
| **Sprint 7** | W8 | Specialised tools (was "B-Tools") | `BlindTimingSamplerTool`, `Z3SolveTool`, `HashcatTool`, `JwtAlgConfusionTool` |
| **Sprint 8** | W9 | Dataset (per directive #9) | Distill ~5k CVE+writeup entries, build KG + vector index |
| **Sprint 9** | W10-11 | Eval matrix | Pipeline × backend × ablation (no-KG / no-anti-loop / no-mid-think); compare vs gpt-5-mini & claude-sonnet on HTB benchmark; target ≥80% |
| **Sprint 10** | W12-14 | Thesis writeup | Bản nháp các chương |

---

## 7. Decisions confirmed (2026-04-18, sau lần họp thầy thứ 2)

1. **API budget**: tự bỏ tiền test (self-funded). Sprint 2 chỉ build wrapper, **không gọi API thật** trong giai đoạn này.
2. **Knowledge graph framework**: **Neo4j chạy Docker container riêng** (không networkx in-process). Thuận tiện reset, scale, và visualisation qua Neo4j Browser.
3. **Mid-thinking intervention scope**: **cả 4 backend** (ollama / openrouter / openai / anthropic). Bất kỳ backend nào cung cấp streaming chunks đều phải hỗ trợ watchdog. User switch backend chỉ cần đổi API URL (single env var).
4. **HTB lab access**: **defer** — quyết định sau, khả năng dùng snapshot offline.
5. **CVE corpus license**: **OK** với plan extract structured data only, không redistribute raw text.

---

## 8. Files to delete / mark obsolete

- `notes/architecture-v1.md` → keep but add header `OBSOLETE — see architecture-v2.md`
- `notes/sprint-01.md` → finished, archive header
- `notes/vps-plan.md` → still valid for dev mode, no change
- `reports/progress-report-01.md` → already obsolete (says so)
- `reports/progress-report-02.md` → still valid as record of what was done; need v3 after Sprint 2 to match v2 architecture
