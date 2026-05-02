# DACN Tracking

**Đề tài:** Nghiên cứu cơ chế điều phối và quản lý đa tác tử trong kiểm thử xâm nhập ứng dụng web
**Bắt đầu:** 2026-04-18
**Cách tiếp cận:** Research-first (option 2) — đọc & phê bình paper trước, design sau, code sau cùng

---

## Status overview

| Sprint | Mô tả | Trạng thái |
|---|---|---|
| **0** | Research & paper critique (6 paper, critique, arch v1) | 🟢 done |
| **1** | Ollama integration (D1 VPS / D2 adapter / D3 LLM-recon) | 🟢 done — 36 tests pass, end-to-end qua gemma4 |
| **— ARCHITECTURE PIVOT 2026-04-18 (sau họp thầy) —** | 4-layer + Dispatcher-as-LLM-agent + LangChain abstraction. Xem `notes/architecture-v2.md`. | |
| **2** | LangChain foundation: BaseAgent / BaseTool / Blackboard refactor + backend factory (ollama/openai/anthropic/openrouter) | 🟢 done — 91/91 tests pass, Neo4j compose ready |
| **3** | Dispatcher (LLM-driven supervisor, Claude-CLI style) replaces linear orchestrator | 🟢 done — 115/115 tests pass |
| **4** | Tool layer + per-job Docker sandbox (Nmap/Curl/HttpProbe/Python tools) | 🟢 done — 148/148 tests, docker smoke ✓ |
| **5** | RAG + Knowledge Graph (InMemoryKG + Neo4j opt-in, query_kg/query_rag tools) | 🟢 done — 173/173 tests |
| **6a** | **C2 anti-loop guard** (NOVEL — signature-based structural loop break) | 🟢 done — 158/158 tests |
| **6b** | **C1 mid-thinking intervention** (NOVEL — streaming watchdog) | 🟢 done — 187/187 tests |
| **7** | Specialised tools (blind timing sampler, Z3 solver, hashcat) | 🟢 done — 246/246 tests pass |
| **8** | Dataset distillation (40-entry seed corpus + Distiller pipeline + KG population + CLI ingest) | 🟢 done — 246/246 tests pass |
| **9** | Eval matrix vs gpt-5-mini / claude-sonnet (target ≥80%) | 🟡 scripted ablation done; real-LLM sub-Sprint pending |
| **10** | Thesis writeup | 🟡 5 chapter skeletons drafted |

Legend: 🟢 done · 🟡 in progress · 🔴 blocked · ⚪ pending

---

## Phase 0 — Research & Paper Critique

**Mục tiêu:** Hiểu state-of-the-art, ghi nhận điểm yếu, từ đó đề xuất enhancement (đúng yêu cầu thầy ở advice #3 — "chỉ ra nhược điểm của các phương pháp trong paper và tìm cách enhance nó").

### 0.1 Reading list

| # | Paper | Link | Trạng thái | Note file |
|---|---|---|---|---|
| 1 | **PentestGPT** (Deng et al., USENIX Security 2024) | https://www.usenix.org/system/files/usenixsecurity24-deng.pdf | 🟢 đọc xong | `notes/papers/01_pentestgpt.md` |
| 2 | **Red-MIRROR** (Tran/**Phan The Duy** et al., arXiv 2603.27127, Mar 2026) — *paper từ lab UIT, có khả năng cao là của thầy hướng dẫn* | https://arxiv.org/pdf/2603.27127 | 🟢 đọc xong | `notes/papers/02_red_mirror.md` |
| 3 | **MAPTA** (David & Gervais, UCL, arXiv 2508.20816, Aug 2025) | https://arxiv.org/pdf/2508.20816 | 🟢 đọc xong | `notes/papers/03_mapta.md` |
| 4 | Prompting Guide overview (chỉ skim phần liên quan agent / RAG) | https://www.promptingguide.ai | ⚪ chưa đọc | `notes/refs/prompting_guide.md` |
| 5 | LlamaIndex agentic patterns docs | https://docs.llamaindex.ai | ⚪ chưa đọc | `notes/refs/llamaindex_patterns.md` |
| 6 | Background paper VulnBot (cited baseline trong Red-MIRROR, 6% XBOW) | (lookup khi cần) | ⚪ chưa đọc | `notes/papers/04_vulnbot.md` |
| 7 | Background paper PentestAgent (cited baseline, 50% XBOW) | (lookup khi cần) | ⚪ chưa đọc | `notes/papers/05_pentestagent.md` |
| 8 | Background paper AutoPT (cited baseline, 46% XBOW) | (lookup khi cần) | ⚪ chưa đọc | `notes/papers/06_autopt.md` |

### 0.2 Mỗi paper note theo template

```markdown
# <paper title>
## Bối cảnh & đóng góp chính
## Kiến trúc / phương pháp
## Dataset & metric
## Kết quả nổi bật
## Điểm yếu / hạn chế (quan trọng nhất với DACN)
## Idea enhancement (mình có thể làm gì khác)
```

### 0.3 Deliverables Phase 0

- [x] `notes/papers/01_pentestgpt.md`
- [x] `notes/papers/02_red_mirror.md`
- [x] `notes/papers/03_mapta.md`
- [x] `notes/papers/04_vulnbot.md`
- [x] `notes/papers/05_autopt.md`
- [x] `notes/papers/06_pentestagent.md`
- [x] `notes/critique.md` — synthesis 6 paper, bảng common weakness, design axes
- [x] `notes/architecture-v1.md` — kiến trúc đề xuất 4 component mới (SW-Mem, B-Tools, FA-RAG, DO-Val), roadmap M1-M8
- [x] ~~Confirm với thầy~~ → User xác nhận thầy = Nghi Hoang Khoa (Red-MIRROR co-author).
- [x] ~~Quyết định LLM stack~~ → Ollama trên VPS 157.245.195.74.
- [ ] **Cần thầy duyệt `architecture-v1.md`** — đặc biệt scope (4 component có quá nhiều cho 1 DACN không?) và priority (G1/G3/G7/G12 đúng hướng không?)
- [ ] Decision còn lại: agent framework (LangGraph theo Red-MIRROR vs custom), có fine-tune LoRA mới không, XBOW Docker fix có dùng PR của MAPTA không.

---

## Phase 1 — Real LLM integration (M1)

**Khởi động khi:** Phase 0 done, kiến trúc v1 đã được thầy duyệt sơ bộ.

Sketch:
- Thêm `OllamaModel` / `AnthropicModel` cạnh `RuleBasedModel`, giữ chung interface.
- Per-role prompt template trong `src/.../prompts/`.
- Replace logic cứng trong `agents/recon.py`, `agents/signature.py`, `agents/analyst.py`, `agents/exploit.py`, `agents/validator.py`, `agents/report.py` bằng LLM call.
- Tool-calling abstraction (vẫn chưa có tool thật ở phase này).
- Cost & token tracking thật (thay cho `simulated_cost`).

Acceptance: `vapt-safe run --llm ollama:gemma2:9b` ra report do LLM viết.

---

## Phase 2 — Tool layer + Docker sandbox (M2)

Sketch:
- `src/.../tools/`: `nmap_scan`, `http_probe`, `static_grep`, `run_python_in_sandbox`, mỗi tool có JSON schema cho function-calling.
- `sandbox/docker_lab.py`: container ephemeral, `network=none` mặc định, opt-in bridge cho dynamic challenge.
- Recon agent đổi từ regex → LLM gọi nmap rồi phân tích.
- Validator agent thực sự chạy PoC trong sandbox và đọc oracle thật.

Acceptance: 1 fixture dynamic mới (vd DVWA SQLi container) chạy E2E, validator pass.

---

## Phase 3 — Real RAG (M3)

Sketch:
- Corpus: NVD CVE JSON, ExploitDB writeups, HackerOne disclosed reports, PortSwigger Academy notes.
- LlamaIndex pipeline: chunking → embedding (bge-m3 hoặc e5) → Chroma/Qdrant.
- Compression layer: filter + summarize chunk trước khi đưa vào prompt (đúng ý "RAG đọc fast" của thầy).
- Reranking (cross-encoder) trước khi feed top-k vào LLM.
- A/B: keyword RAG cũ vs semantic RAG mới.

Acceptance: signature agent ra ranked attack family hợp lý cho fixture lạ (chưa có trong KB).

---

## Phase 4 — Evaluation & writeup (M4)

Sketch:
- Mở rộng fixture corpus: 15-20 challenges (DVWA, Juice Shop, WebGoat snapshots, real CVE PoC).
- Matrix: `models × pipelines` — `{gemma2:2b, gemma2:9b, gemma2:27b, llama3.1:8b, qwen2.5:14b}` × `{single-agent, multi, multi+RAG, multi+RAG+validator}`.
- Metrics: `bug_found`, `false_positive_rate`, `usd_real`, `wall_clock`, `tool_calls`, `validator_agreement`.
- Ablation: shared memory off/on, cost-aware early stop off/on.
- Thesis chương: introduction, related work (papers từ Phase 0), method (architecture-v1), evaluation, limitation, conclusion.

---

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-04-18 | Approach = research-first (option 2), không gấp | User đồng ý, tránh rework architecture sau khi đọc paper |
| 2026-04-18 | Inherited scaffold (`vapt_orchestrator_safe`) — giữ kiến trúc 7-agent, SharedMemory, BudgetTracker, benchmark harness; thay LLM/recon/RAG/sandbox | Scaffold đúng pattern MAPTA, nhưng mọi tầng intelligence là mock |

---

## Open questions (cần thầy / mình quyết)

- [x] ~~DACN có phải tiếp nối Red-MIRROR không?~~ → **User xác nhận thầy = Nghi Hoang Khoa** (khoanh@uit.edu.vn), co-author #3 của Red-MIRROR. Cùng UIT InSec Lab. Vậy DACN là tiếp nối Red-MIRROR.
- [x] ~~Output quality vs cost/energy/lateral?~~ → **User xác nhận: pentest output quality TRƯỚC**, mấy cái khác sau. Drop cost/energy/multi-target khỏi roadmap chính.
- [x] ~~LLM stack?~~ → **User: dùng Ollama trên VPS 157.245.195.74** (DigitalOcean). Self-host. Có thể có 1 baseline API (DeepSeek hoặc Anthropic) sau khi confirm budget.
- [ ] VPS spec: GPU? RAM? Disk? Model size có thể chạy được? (Gemma 27B Q4 cần ~16GB RAM/VRAM; Qwen2.5-14B Q4 cần ~9GB.)
- [ ] Agent framework: theo Red-MIRROR dùng **LangGraph** (cho consistency với lab), hay tự code trên scaffold hiện tại?
- [ ] Phạm vi vuln focus: pick top-3 weakness chung của Red-MIRROR + MAPTA: (a) blind SQLi/cmd inj, (b) crypto, (c) framework-specific payload placement. Chốt 1-2 cho DACN.
- [ ] Có cần fine-tune LoRA dataset như Red-MIRROR (1644 sample) không, hay leverage trực tiếp Qwen2.5-14B-LoRA Red-MIRROR đã release?
- [ ] Fixture corpus: XBOW (105 challenge, đã có Docker fixes từ MAPTA) + Vulhub (8 CVE giống Red-MIRROR) — hay tạo subset riêng?

---

## Session log

### 2026-05-02 (Sprint 7 + 8 done — Specialised tools + Dataset pipeline)

**Sprint 7 — Specialised tools:**
- **`tools/security/timing.py`** — `BlindTimingSampler` (`blind_timing`): pure-Python timing side-channel detector for blind SQL injection. Sends baseline vs payload HTTP requests, compares response time delta. Scope-gated. Addresses the **#1 gap** across all 6 papers (0% blind SQLi success rate).
  - Input: url, param_name, baseline_value, payload_value, inject_in (query/body/json), sleep_seconds, samples, threshold.
  - Output: JSON with baseline_avg_ms, payload_avg_ms, delta_ms, is_vulnerable, confidence stats.
- **`tools/security/z3_solver.py`** — `Z3ConstraintSolver` (`z3_solve`): structured SMT constraint solver for crypto/token/nonce puzzles. Accepts variables (int/bitvec) and constraints (==, !=, >, <, %%, &, |). No eval/exec — safe DSL translated to Z3 assertions. Graceful degradation when z3-solver not installed.
- **`tools/security/hashcat.py`** — `HashcatTool` (`hashcat_crack`): ShellTool subclass wrapping hashcat binary. Dictionary + combinator modes. Runtime capped at 120s. No scope needed (local computation).
- **Dispatcher wiring**: `enable_specialized_tools=True` flag in DispatcherRunner. BlindTimingSampler only attached when fixture declares scope; Z3 + hashcat always available.
- **Prompt update**: `prompts/dispatcher.md` describes all 3 new tools.
- **Dependency**: `z3-solver>=4.12` added to `requirements.txt`.
- **Tests**: +37 (10 timing, 14 Z3, 13 hashcat).

**Sprint 8 — Dataset distillation pipeline:**
- **`dataset/cve_entry.py`** — `CveEntry` dataclass: cve_id, cwe_id, title, vuln_class, severity, description, affected_frameworks, sinks, sources, payload_templates, oracle_hints, remediation, tags, references. Methods: `to_dict()`, `from_dict()`, `to_kg_text()` (compact ~50-150 token representation), `approx_tokens`.
- **`dataset/seed.py`** — 40 curated entries covering 8 vulnerability classes: SQLi (8, including blind/boolean/second-order/error-based), IDOR (6), SSRF (6), XSS (5), RCE (7), AuthBypass (4), PathTraversal (3), DoS (1). Each entry has real CVE IDs or DACN-prefixed synthetic entries with payload templates and oracle hints.
- **`dataset/distiller.py`** — `Distiller` pipeline: `from_seed()`, `from_jsonl(path)`, `to_jsonl(path)`, `filter_by_class()`, `filter_by_severity()`, `merge()`, `populate_kg(kg)` (creates CVE/CWE/Framework/Sink/Payload nodes + edges), `stats()`.
- **KG population**: `Distiller.from_seed().populate_kg(kg)` auto-runs in DispatcherRunner alongside `build_default_kg()`. Result: 188 nodes / 318 edges out-of-the-box.
- **CLI**: `vapt-safe ingest [--input FILE.jsonl] [--export OUT.jsonl] [--populate-kg]` — stats + optional KG population + JSONL export.
- **Tests**: +17 (CveEntry model, seed corpus validation, Distiller pipeline, KG population, token-efficiency assertion).
- Total test suite: **246 passed, 1 skipped** (192 prior + 54 new).

### 2026-04-21 (Sprint 8 done — Ablation matrix + thesis skeletons)

- **`engine/ablation.py`** — `run_ablation(fixtures, chat_model_factory, configs, outputs_root)` runs each (fixture × config) combination. 5 default configs: `baseline`, `C2_only`, `C3_only`, `C1_only`, `all`. Emits `AblationReport` with `.to_dict()` (JSON) + `.to_markdown()` (summary table + per-fixture detail table).
- **Metric columns**: status, steps, tool_calls, loop_detected (from memory.json events), watchdog_trips (from run_summary), approx_kg_tokens + approx_rag_tokens (from tool artifact metadata), wall_ms.
- **`cli.py`** — `vapt-safe ablation --fixtures-dir ... --outputs-root ...` runs offline with a built-in scripted chat model per fixture; output: `ablation_report.json` + `ablation_report.md`.
- **Thesis**: 5 chapter skeletons written in `thesis/01..05_*.md` — introduction (problem + C1/C2/C3 framing), related work (PentestGPT / Red-MIRROR / MAPTA + gap table), method (4-layer arch + algo sketches), evaluation (ablation placeholder + real-LLM plan), conclusion (limitations + Sprint 9 roadmap).
- **Tests**: +5 (ablation matrix coverage, KG token accumulation by config, markdown rendering, config completeness). Total **192 passed, 1 skipped**.
- Verified: `vapt-safe ablation` produces 15 runs × 8 metric columns end-to-end on the 3 scaffold fixtures, each config writes its own run directory.

### 2026-04-21 (C1 mid-thinking intervention done — NOVEL contribution #3, headline)

- **`engine/watchdogs.py`**:
  - `DriftWatchdog(focus_keywords, max_drift_chars, min_buffer_chars)` — fires when the streamed buffer grows past the drift budget without mentioning any focus keyword (manifest id / title / skills / allowed hosts).
  - `ScopeWatchdog(scope_guard)` — regex-scans the buffer for URLs; trips on the first out-of-scope hit; dedupes so a repeated URL doesn't refire.
  - `LoopWatchdog(blackboard, threshold)` — pattern-matches a "name/args" tool-call JSON in the stream; trips when the proposed tool name is already at the loop-signature threshold.
- **`engine/dispatcher.py`** — `Dispatcher.watchdogs` + `Dispatcher._call_llm`. When watchdogs are configured AND the chat model has `.stream()`, streams the response, runs watchdogs after every chunk. On trip → log event, queue `correction_for_next_turn`, return partial `AIMessage(content="[intervened:…]")` + `intervened=True`. Dispatcher advances to the next step, `before_step` injects the correction, LLM sees it immediately.
- **`engine/dispatcher_runner.py`** — `enable_mid_thinking=False` default (needs a streaming model). `mid_thinking_focus` defaults to `manifest.id + manifest.title + skills + allow_hosts`. Watchdog trips surfaced in `run_summary.json["watchdog_trips"]` for eval.
- **Why this is the headline**: PentestGPT / Red-MIRROR / MAPTA all wait for EOS before reacting. DACN cancels mid-stream the moment the model drifts / goes out of scope / is about to loop. Cost of being wrong = one partial chunk instead of 1000+ CoT tokens.
- **Tests**: +14 (4 drift, 3 scope, 2 loop, 5 dispatcher streaming integration). Total **187 passed, 1 skipped**.

### 2026-04-21 (C3 Knowledge-graph RAG done — NOVEL contribution #2)

- **`kg/` package**:
  - `knowledge_graph.py` — `KG` Protocol + `KGFact` triple + `build_default_kg()` seeds IDOR/SSRF/SQLi payloads, sinks, frameworks, CWEs.
  - `in_memory.py` — `InMemoryKG` dict-of-dict graph. Thread-safe (RLock), supports `query_by_family` / `query_by_framework` / `query_triples` / `neighbours`. Used by default in tests and local dev.
  - `neo4j_kg.py` — `Neo4jKG` wraps the official driver, parameterised Cypher, label-name validation. Activated when `NEO4J_PASSWORD` env is set; otherwise `InMemoryKG` stays the default.
- **`tools/kg_tools.py`** — `QueryKGTool` (subject/attack_family/framework lookup → compact triples) and `QueryRAGTool` (fallback over the compressed cards). Both record `approx_tokens` in metadata — headline metric for C3.
- **Test `test_kg_is_cheaper_than_rag_for_same_question`** asserts the KG query returns materially fewer tokens than the equivalent RAG lookup for the same intent.
- **`engine/dispatcher_runner.py`** — KG auto-built + written to `blackboard.kg_handle` before dispatch; `query_kg` + `query_rag` tools attached when `enable_kg=True` (default). Real Neo4j is opt-in via `kg=Neo4jKG(...)` override.
- **Prompt update** — dispatcher.md now advertises `query_kg` as preferred over `query_rag` for payload/sink/framework questions.
- **Tests**: +15 (5 InMemoryKG, 5 Neo4jKG mocked, 3 QueryKGTool, 1 QueryRAGTool, 1 KG-vs-RAG token comparison). Total **173 passed, 1 skipped**.

### 2026-04-21 (C2 anti-loop guard done — NOVEL contribution #1)

- **`engine/anti_loop.py`**:
  - `LoopGuard` — pure detection. Inspects `Blackboard.loop_signatures` (already pushed by `BaseTool._record()` as `hash(tool_name, kwargs)`). Threshold default 3; fires once per unique signature then arms after `reset()`.
  - `AntiLoopHook(DispatcherHook)` — on detection, logs `loop_detected` event, resets signatures, injects a synthetic `HumanMessage` into the NEXT dispatcher turn telling the LLM to call `pivot(reason=...)` and pick a different attack family. `max_trips=4` guardrail prevents wedge on broken runs.
- **`engine/dispatcher.py`** — `DispatcherHook.before_step` now receives the live `messages: List[BaseMessage]` (not Sequence) so hooks can append mid-run. Clean seam for C1 streaming watchdog later.
- **`engine/dispatcher_runner.py`** — `enable_anti_loop=True` default, `anti_loop_threshold=3` exposed. Sprint 8 ablation (`enable_anti_loop=False`) will compare with/without C2 on the same fixtures.
- Why this matters: PentestGPT / VulnBot / AutoPT retry blindly; Red-MIRROR's Inter-reflection still loops within the same family. Structural signature check works regardless of model reasoning — same on gemma-4B or claude-sonnet.
- **Tests**: +10 tests (5 LoopGuard, 3 AntiLoopHook integration, 2 DispatcherRunner wiring). Total **158 passed, 1 skipped**.

### 2026-04-21 (Sprint 4 done — Tool layer + Docker sandbox)

- **`utils/scope.py`** — `Scope` + `ScopeGuard`. Deny-by-default target allowlist derived from `manifest["scope"]`. Checks hosts, CIDRs, ports, full URLs. Default = loopback-only + common web ports — this is how we honour the README's "no public probing" guarantee while running real binaries.
- **`tools/shell.py`** — `ShellTool` base wrapping `subprocess.run` with timeout/kill, clean exit-code mapping (124 on timeout), and binary-missing check. Subclasses only implement `build_argv` + call scope guard.
- **`tools/security/`** — three concrete tools:
  - `NmapTool` (`nmap_scan`) — `-Pn -T4 -oX -` with top-100 ports or explicit list, optional `-sV`.
  - `CurlTool` (`curl_request`) — raw curl when the LLM needs specific flags; max-redirs=3, per-call scope check.
  - `HttpProbeTool` (`http_probe`) — pure-python `requests` preferred path; redirects DISABLED so scope stays in control; response returned as structured JSON (status / headers / truncated body).
- **`sandbox/docker_sandbox.py`** — `DockerSandbox` shells out to docker CLI (swappable via `DOCKER_BIN=podman`). Flags: `--rm --network=none --read-only --tmpfs /tmp --cpus 0.5 --memory 256m --pids-limit 64 --security-opt no-new-privileges:true`. Ephemeral tmpdir-bind-mount passes the script in; timeout auto-kills the container.
- **`tools/sandbox_exec.py`** — `RunPythonInSandboxTool` (`run_python_sandbox`). Size-capped (20k chars), returns full sandbox payload as JSON.
- **`engine/dispatcher_runner.py`** — auto-wires security tools ONLY when fixture declares a `scope` block, so existing source-only fixtures keep working unchanged. Sandbox tool attached unconditionally (it has no network by default).
- **`prompts/dispatcher.md`** — updated to describe new tools, scope contract, and the "stay on declared target, don't fight the guard" rule.
- **Tests**: +33 tests across scope / security / sandbox. Docker smoke (`test_sandbox_real_docker_hello_world`) passes end-to-end with real docker after pre-pulling `python:3.11-slim`. Total **148 passed, 1 skipped (docker opt-in)**.

### 2026-04-21 (Sprint 3 done — Dispatcher skeleton)

- **`engine/dispatcher.py`** — minimal tool-use loop (Claude-CLI style, NOT LangGraph — simpler, less deps, same semantics). Supports `DispatcherHook.before_step/after_step` so Sprint 6 (C1) can plug in streaming watchdog without refactor.
- **`tools/agent_tools.py`** — 6 tool wrappers: `invoke_recon`, `invoke_signature`, `invoke_analyst`, `invoke_exploit` (pairs exploit+validator in one call), `invoke_report`, and `pivot` (sentinel stub; full anti-loop wiring in Sprint 6). Tools read/write `Blackboard.phase_context` so sub-agent state is persistent across dispatcher turns.
- **`engine/dispatcher_runner.py`** — end-to-end wiring. Intake still runs procedurally (just file I/O, no LLM). Dispatcher LLM resolved via `build_for_role("dispatcher")` so `LLM_BACKEND_DISPATCHER` env var is the single switch between ollama/openai/anthropic/openrouter.
- **`prompts/dispatcher.md`** — supervisor system prompt: pipeline order, stop-when-verified rule, pivot protocol, budget awareness.
- **`cli.py`** — `vapt-safe dispatch --fixture ... --goal "..."` subcommand, reuses legacy `--llm` flag for sub-agents.
- **`memory/shared_memory.py`** — `Blackboard.snapshot()` now flattens dataclasses in `phase_context` via new `_jsonable()` helper so `Hypothesis` / `CandidatePoC` / `ValidationResult` serialise cleanly.
- **Tests**: 24 new tests (10 dispatcher, 11 agent_tools, 3 dispatcher_runner). Total **115/115 pass** (91 prior + 24).
- Legacy `engine/orchestrator.py` + `vapt-safe run` kept intact as regression baseline. Both pipelines produce comparable `run_summary.json` (field `pipeline` tags which one).

### 2026-04-18 (Sprint 2 done — LangChain foundation)

- 5 wrapper mới (production-grade, tất cả test mock-based, không gọi API thật):
  - `llm/backend_factory.py` — `parse_spec` / `resolve_spec` / `build_chat_model` / `build_for_role`. Hỗ trợ `ollama|openai|anthropic|openrouter|custom`. Per-role override: `LLM_BACKEND_<ROLE>` → `LLM_BACKEND_DEFAULT` → built-in default `ollama:gemma4:e2b`.
  - `tools/base.py` — `BaseTool` (subclass LangChain `BaseTool`) + `ToolResult` dataclass. Auto-truncation, exception-to-ToolResult envelope, Blackboard artifact write, loop-signature push (chuẩn bị cho C2 anti-loop ở Sprint 6). `EchoTool` ship làm reference + test fixture.
  - `memory/shared_memory.py` — refactor `SharedMemory` → `Blackboard` (alias giữ backward compat). Thêm `RLock`, `phase_context`, `kg_handle`, `loop_signatures` (deque maxlen=32). Snapshot loại trừ `kg_handle` để JSON serialise không vỡ.
  - `agents/base.py` — thêm `LangChainAgent` + `LangChainAgentSpec` cohabit với `BaseAgent` Sprint 1. Tự bind tools, inject blackboard vào tools, load system prompt từ `prompts/<role>.md`.
  - `infra/neo4j/{docker-compose.yml, init/001_schema.cypher, README.md}` — Neo4j 5-community trong Docker, bind `127.0.0.1` only, schema constraints cho CVE/Endpoint/Framework/Sink/Source/Parameter/Payload/CWE.
- 55 test mới (mock-based, không cần network): backend_factory (22), blackboard (10), base_tool (13), langchain_agent (10).
- Tổng test: **91/91 pass** (36 Sprint 1 + 55 Sprint 2).
- Dependencies thêm: `langchain==1.2.x`, `langchain-core==1.3.x`, `langchain-ollama`, `langchain-openai`, `langchain-anthropic`, `pydantic>=2.7`, `neo4j>=5.20`.
- Existing code 100% giữ nguyên — Sprint 1 tests vẫn pass nhờ alias `SharedMemory = Blackboard`.

### 2026-04-18 (sau họp thầy — ARCHITECTURE PIVOT)

- Họp thầy Khoa, nhận 9 directive + 4-layer diagram. Insight quan trọng: "1 agent điều khiển tất cả như Claude CLI" — Dispatcher là LLM-driven supervisor, không phải state machine.
- Architecture v1 (extend Red-MIRROR với 4 specialized component) → **OBSOLETE**.
- Architecture v2 published tại `notes/architecture-v2.md`:
  - 4 layer: Orchestration (Dispatcher / Blackboard / Model Selector) — Agent (Recon/Analyst/Exploit/Report) — Tool (security tools + Docker sandbox) — RAG (KB + vector store + **Knowledge Graph**)
  - LangChain backend abstraction: ollama / openai / anthropic / openrouter swap free
  - 2 novel contribution: **C1 mid-thinking intervention** (streaming watchdog: drift / scope / loop), **C2 anti-loop guard** (signature buffer + forced pivot)
  - 1 token-efficiency lever: **C3 Knowledge Graph RAG** (entity-relation extraction → networkx, query_kg vs query_rag)
  - Benchmark target: ≥80% vs gpt-5-mini & claude-sonnet
- D2-D3 code 100% reusable trong v2 (chỉ refactor wrap LangChain, không throwaway).

### 2026-04-18 (chiều — Sprint 1 D3 done)

- D3 done: prompts/recon.md + utils/llm_json.py + agents/recon.py LLM-driven với heuristic fallback. OllamaModel.generate() thêm `think` flag.
- 36/36 test pass (18 cũ + 18 D3 mới: 11 llm_json, 5 recon, 3 think, etc.).
- Live test trên VPS: gemma4:e2b CPU = ~3 tok/s; recon prompt cần 3-10 phút → vượt timeout (180s, sau lên 600s vẫn 502 từ Caddy). Fallback safety net work đúng — pipeline vẫn hoàn thành.
- Update `infra/vps-setup.sh` với Caddy timeout 600s.
- Viết `reports/progress-report-02.md` — báo cáo chi tiết Phase 0 + Sprint 1 D1-D3 cho thầy.

### 2026-04-18 (cuối ngày — Sprint 1 D1+D2 done)

- **VPS info from user**: 4 vCPU Xeon 8168, 7.8 GiB RAM, no GPU, no swap. Ollama installed, `gemma4:e2b` 7.2 GB pulled. → **Chỉ chạy được model ≤ 8B**, không đủ cho 14B+ (Red-MIRROR backbone).
- User confirmed: **không có API budget** → Strategy A (self-host all). DACN reposition thành "small model + specialized components".
- `gemma4:e2b` từ Ollama registry: 5.1B Q4_K_M, **131k context**, có **tools + thinking + vision** capability (architecture `gemma4`, requires Ollama ≥ 0.20.0).
- Viết `notes/vps-plan.md`, `reports/progress-report-01.md`, `notes/sprint-01.md`.
- **D1 done**: `infra/vps-setup.sh` (Ollama bind localhost + Caddy bearer-token + ufw) + `infra/README.md`.
- **D2 done**: `OllamaModel` adapter (summarize/generate/chat/list_tags), `--llm` CLI flag, `llm-test` subcommand, `.env` loader. 16 unit test mới (mock requests). All 18 test pass. Smoke run `--llm rule` vẫn `validated`. `--llm ollama:*` fail clean nếu thiếu env.

### 2026-04-18 (sáng)

- Audit scaffold (`vapt_orchestrator_safe`) inherited từ bạn. 1 commit `init project, from yuugay project`. Pipeline chạy được, test pass, benchmark output OK nhưng mọi tầng intelligence là mock (RuleBasedModel, regex recon, keyword RAG, fixture-only sandbox).
- Đồng ý với user dùng option 2 (research-first).
- Tạo file tracking này. Bắt đầu Phase 0.
- **Decision (2026-04-18, user confirmed):**
  - Thầy hướng dẫn = **Nghi Hoang Khoa** (khoanh@uit.edu.vn), co-author #3 của Red-MIRROR. DACN = tiếp nối hướng lab.
  - Priority: pentest output quality TRƯỚC; drop cost/energy/multi-target khỏi roadmap chính.
  - LLM stack: Ollama self-host trên VPS **157.245.195.74**.
  - Cần đọc thêm 3 baseline paper: VulnBot, AutoPT, PentestAgent (đều cited trong Red-MIRROR).
- Đọc xong 3 paper chính:
  - **PentestGPT** (USENIX24): 3-module Reasoning/Generation/Parsing + PTT, human-in-the-loop, không thực sự autonomous, hallucination + context loss còn nặng. Vector DB từng thử nhưng confused.
  - **Red-MIRROR** (UIT lab, Mar 2026, **corresponding author = Phan The Duy = nhiều khả năng thầy hướng dẫn**): Planner/Collector/Exploiter/Summarizer + SRMM (formal append-only shared memory) + Dual-Phase Reflection (Intra trong Exploiter, Inter trong Planner với 3-vote majority) + LangGraph + LoRA Qwen2.5-14B. XBOW 86%, fail blind SQLi/crypto/framework-specific.
  - **MAPTA** (UCL Aug 2025): Coordinator/Sandbox(N)/Validation + per-job Docker + cost accounting chi tiết + GPT-5. XBOW 76.9%, fail blind SQLi 0%, real-world: 19 vuln, 14 high/critical, $3.67/app.
- **Common weakness 3 paper**: blind/low-signal vuln, framework-specific exploitation, business logic, không có WAF trong eval, single-target (chưa lateral movement).
- **Common strength**: tool grounding + reflection + memory mechanism là 3 trục design space.
- Tổ chức `notes/papers/` + `notes/refs/`, save raw extracted text vào `notes/_*.txt`.
