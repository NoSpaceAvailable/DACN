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
| **2** | LangChain foundation: BaseAgent / BaseTool / Blackboard refactor + backend factory (ollama/openai/anthropic/openrouter) | ⚪ pending |
| **3** | Dispatcher (LangGraph supervisor, Claude-CLI style) replaces linear orchestrator | ⚪ pending |
| **4** | Tool layer + per-job Docker sandbox (Nmap/Curl/Sqlmap/Python tools) | ⚪ pending |
| **5** | RAG + Knowledge Graph (LlamaIndex KB + networkx KG, query_kg/query_rag tools) | ⚪ pending |
| **6** | C1 mid-thinking intervention + C2 anti-loop guard (NOVEL contributions) | ⚪ pending |
| **7** | Specialised tools (blind timing sampler, Z3, hashcat) | ⚪ pending |
| **8** | Dataset distillation (~5k CVE+writeup token-efficient entries) | ⚪ pending |
| **9** | Eval matrix vs gpt-5-mini / claude-sonnet (target ≥80%) | ⚪ pending |
| **10** | Thesis writeup | ⚪ pending |

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
