# Báo cáo tiến độ DACN — Lần 2 (chi tiết)

**Sinh viên:** [Tên SV]
**GVHD:** TS. Nghi Hoang Khoa
**Đề tài:** Nghiên cứu cơ chế điều phối và quản lý đa tác tử trong kiểm thử xâm nhập ứng dụng web
**Kỳ báo cáo:** 2026-04-18 (cộng dồn từ lần nhận project)
**Phase:** Phase 0 ✅ done — Phase 1 Sprint 1 (D1+D2+D3) ✅ done

---

## TL;DR

1. **Đọc 6 paper related work** (gồm Red-MIRROR của lab thầy) → viết note + critique cross-paper + đề xuất kiến trúc DACN-X gồm 4 component bổ sung (B-Tools / FA-RAG / DO-Val / SW-Mem) targeting đúng các weakness mà Red-MIRROR & MAPTA tự thừa nhận.
2. **Setup VPS Ollama** (4 vCPU / 7.8 GiB / `gemma4:e2b`), security hoá bằng Caddy + bearer token + ufw qua script idempotent.
3. **Tích hợp Ollama vào scaffold** thật sự — `OllamaModel` adapter, `--llm` CLI, `llm-test` subcommand, env loader.
4. **Chuyển Recon agent từ regex sang LLM-driven** với heuristic fallback — agent đầu tiên thực sự gọi LLM trong pipeline.
5. **36 unit test pass** (18 mới ở D2 + 18 mới ở D3 + 2 cũ giữ nguyên).
6. **Constraint phát hiện:** VPS chỉ chạy được model ≤ 8B Q4, no API budget → DACN reposition thành "small-model + specialized components" thay vì cố match SOTA Red-MIRROR.

---

## 1. Phase 0 — Research & Architecture (đã xong)

### 1.1 Tiếp nhận project từ thành viên trước

Repo `vapt_orchestrator_safe` (1 commit `init project, from yuugay project`). Audit đã ghi nhận:

- ✅ **Có**: kiến trúc 7-agent (Intake → Recon → Signature → Analyst → Exploit → Validator → Report), SharedMemory với evidence/task_graph/artifacts/events/budget, ModelRouter + profile sets, BudgetTracker, benchmark harness, CLI, 3 toy fixture (IDOR/SSRF/SQLi), 2 pytest pass.
- ❌ **Chưa thật**: LLM = string template (`RuleBasedModel`), recon = regex, RAG = keyword overlap (5 docs), sandbox = đọc file JSON, capability scores của Gamma4 = số hard-code.

→ Kết luận: **scaffold đúng pattern MAPTA-style nhưng mọi tầng intelligence là mock**. Khung tốt để build, không cần viết lại từ đầu.

### 1.2 Đọc & critique 6 paper related work

| # | Paper | Năm | XBOW SR | Note |
|---|---|---|---|---|
| 1 | **PentestGPT** (Deng, USENIX Security 2024) | 2024 | — (HTB) | Pioneer; 3-module Reasoning/Generation/Parsing + PTT; HITL không thực sự autonomous |
| 2 | **Red-MIRROR** (Tran/**Khoa**/Phan The Duy, UIT lab, arXiv 2603.27127) | Mar 2026 | **86.0%** | SOTA; SRMM (formal append-only memory) + Dual-Phase Reflection; 12+ specialized tools |
| 3 | **MAPTA** (David & Gervais, UCL, arXiv 2508.20816) | Aug 2025 | 76.9% | Per-job Docker sandbox + cost-aware early stopping + GPT-5 |
| 4 | **VulnBot** (Kong, CAS Beijing, arXiv 2501.13411) | Jan 2025 | 6.0% | Tri-phase + PTG DAG; baseline yếu nhất Red-MIRROR so |
| 5 | **AutoPT** (Wu, USTC, arXiv 2411.01236) | Nov 2024 | (41% bench riêng) | FSM-based PSM, LangChain |
| 6 | **PentestAgent** (Shen, Northwestern, ACM ASIA CCS 2025 Hà Nội) | Nov 2024 | 50.0% | RAG-heavy + online search augmentation |

Mỗi paper có note tại `notes/papers/0X_*.md` theo template thống nhất: bối cảnh & đóng góp / kiến trúc / dataset & metric / kết quả / **limitations** / idea enhancement.

### 1.3 Cross-paper synthesis (`notes/critique.md`)

**Phát hiện 12 common gap**, rank theo priority "output quality" mà thầy đã chốt:

| Gap | Mô tả | Paper thừa nhận |
|---|---|---|
| **G1** ⭐⭐⭐ | Blind / low-signal vuln (time-based, boolean blind) | Red-MIRROR + MAPTA cùng **0% blind SQLi** |
| **G3** ⭐⭐⭐ | Framework-specific payload placement (custom HTTP header, routing field) | Red-MIRROR Sec 5.2 |
| **G7** ⭐⭐⭐ | Validator chính LLM-based → có thể tự hallucinate | MAPTA + PentestAgent C3 |
| G2 ⭐⭐ | Cryptographic challenge (LLM yếu numerical) | Red-MIRROR Sec 5.2 |
| G4 ⭐⭐ | Limited / outdated CVE knowledge | PentestAgent C1 |
| G12 ⭐⭐ | SRMM recency-only, mất salient info cũ ở session dài | Implicit Red-MIRROR |
| G5, G6, G8 ⭐ | Session context loss / hallucinated commands / business logic | Mọi paper cũ; phần lớn đã được Red-MIRROR fix |
| G9, G10, G11 | WAF eval / multi-target / cost & energy | (Drop theo priority "output quality first") |

**3 design axes** rút ra:
- **Memory**: text history → per-phase summarizer → per-agent context + shared FS → formal append-only segregated R/W (SRMM)
- **Reflection**: none → check & retry → FSM transitions → validation gate → dual-phase intra+inter với vote
- **Tool/sandbox**: HITL → LangChain agents → custom integration → 12 specialized tools → generic + per-job Docker

### 1.4 Architecture v1 (`notes/architecture-v1.md`)

Đề xuất **DACN-X**: extension của Red-MIRROR với 4 component mới đánh đúng gap top-priority:

| Component | Đánh gap | Spec ngắn |
|---|---|---|
| **B-Tools** | G1 (blind), G2 (crypto) | Statistical inference suite: `blind_timing_sampler`, `boolean_blind_oracle`, `binary_search_extractor`, `z3_solve`, `hashcat_crack`, `jwt_alg_confusion` |
| **FA-RAG** | G3 (framework-specific) | LlamaIndex + bge-m3 + cross-encoder reranker; corpus theo (framework, vuln_class, payload, placement) |
| **DO-Val** | G7 (validator FP) | Dual-oracle: LLM-judge + concrete side-effect probe (re-query DB, network capture, process check) |
| **SW-Mem** | G12 (memory recency) | Salience score = LLM-judge × recency; compaction khi |Mtext| > N |

**Roadmap**: M1 (Ollama wire) → M2 (Docker sandbox + tool registry) → M3 (FA-RAG) → M4 (SW-Mem) → M5 (B-Tools) → M6 (DO-Val) → M7 (full eval matrix) → M8 (writeup).
**Cắt scope nếu thiếu thời gian**: drop SW-Mem trước, sau đó DO-Val, giữ B-Tools + FA-RAG là 2 mảng đánh trực tiếp output quality.

### 1.5 VPS strategy (`notes/vps-plan.md`)

Sau khi user confirm **không có API budget**, chốt **chiến lược A** (self-host all):

- VPS DigitalOcean Premium Intel 8GB / 4 vCPU / no GPU @ `157.245.195.74`
- Model: `gemma4:e2b` (5.1B, Q4_K_M, 131k context, capabilities: tools + thinking + vision; từ Ollama registry)
- Realistic max: 8B Q4 — **không thể chạy Qwen2.5-14B-LoRA của Red-MIRROR** (cần 9 GB Q4)

**Reposition đề xuất:** thay vì cố match Red-MIRROR 86% SR, DACN claim:

> "Với model nhỏ open-source (≤8B) và compute hạn chế, DACN-X chứng minh các specialized components (B-Tools / FA-RAG / DO-Val) có thể thu hẹp khoảng cách với SOTA, đặc biệt trên các vuln class mà SOTA cũng yếu (blind, framework-specific). Đây là extension của thesis Red-MIRROR ('mid-scale OSS đua được commercial') xuống một bậc nữa."

---

## 2. Phase 1 Sprint 1 — Ollama integration (đã xong D1+D2+D3)

### 2.1 D1 — Security setup VPS (`infra/vps-setup.sh`)

Script idempotent, ~120 dòng bash:
1. Pin Ollama bind `127.0.0.1:11434` qua systemd override (không expose trực tiếp)
2. Cài Caddy reverse proxy với bearer-token auth, timeout 600s cho long generation
3. ufw firewall: allow SSH + 80, deny 11434
4. JSON logging vào `/var/log/caddy/ollama-access.log` (rotate 10MB × 5)
5. Smoke test 3 layer: direct loopback, via Caddy without token (401), via Caddy with token (200)

User chạy script: `OLLAMA_TOKEN=$(openssl rand -hex 32) bash infra/vps-setup.sh`. Đã verify trên VPS thật: `curl http://157.245.195.74/api/tags` không token → 401, có token → 200.

### 2.2 D2 — `OllamaModel` adapter + CLI (`src/.../llm/ollama_model.py`)

**Adapter API:**
```python
class OllamaModel(BaseModel):
    summarize(prompt, metadata)          # BaseModel contract — dùng RuleBasedModel-style
    generate(prompt, system, options, think)  # structured: returns OllamaResponse
    chat(messages, options)              # multi-turn
    list_tags()                          # cho llm-test subcommand
```

`OllamaResponse` mang theo `prompt_tokens`, `completion_tokens`, `total_duration_ns` để sau này tích hợp BudgetTracker thực.

**Error handling rõ ràng:**
- 401 → `OllamaError("401 Unauthorized — check OLLAMA_TOKEN")`
- 404 → `OllamaError(... model 'X' may not be pulled, run 'ollama pull X' on the VPS)`
- 5xx → `OllamaError(... HTTP {status}: {body[:300]})`
- Timeout → `OllamaError(... consider raising OLLAMA_TIMEOUT or switching to smaller model)`
- Non-JSON → `OllamaError(... Non-JSON response from {url})`

**Registry refactor (`registry.py`):** factory `parse_backend()` split-on-first-colon (giải quyết `gemma4:e2b` có dấu `:` trong tên), `OllamaConfig` dataclass, validation errors rõ ràng.

**CLI (`cli.py`):** thêm `--llm rule | ollama:<tag>` flag cho `run` và `benchmark`, thêm `llm-test` subcommand riêng để probe VPS.

**Env (`config.py`):** lightweight `.env` / `.env.local` loader (không thêm dep `python-dotenv`).

### 2.3 D3 — Recon agent LLM-driven (`src/.../agents/recon.py`)

**Kiến trúc 2-path với fallback:**

```
recon.run(transcript, source_files):
  if model.has(generate):
    try:
      result = LLM.generate(prompt(transcript, sources),
                            options={temp:0.1, num_ctx:8192},
                            think=False)   # disable CoT để giảm CPU time
      parsed = extract_json(result.text)
      return normalise(parsed)             # convert rich JSON → legacy dict
    except (timeout | parse error | network error):
      log fallback reason
      → fallthrough to heuristic
  return heuristic(transcript, source_files)  # original regex logic, unchanged
```

**Tại sao fallback:**
- Pipeline luôn hoàn thành dù VPS down hoặc model trả garbage
- Existing pytest fixture vẫn pass (heuristic giữ nguyên hành vi cũ)
- Khi đo benchmark có thể isolate đóng góp của LLM bằng cách so sánh `_recon_source = "llm"` vs `"heuristic"` trong evidence tag

**Component mới hỗ trợ:**

| File | Mục đích |
|---|---|
| `prompts/__init__.py` + `prompts/recon.md` | Template loader dùng `string.Template` (`${var}`) tránh xung đột với JSON braces; cache load |
| `utils/llm_json.py` | `extract_json()` xử lý: markdown fence ```json...```, prose trước/sau, thinking-token prefix `<think>...</think>`, brace matching nested + braces inside string literals |

**Output JSON schema cho recon:**
```json
{
  "endpoints": [{"method": "...", "path": "...", "params": [...]}],
  "auth_surface": "session|bearer|basic|oauth|none|unknown",
  "stack_fingerprint": "...",
  "suspicious_patterns": [{"id": "...", "evidence": "...", "confidence": 0.0}],
  "next_recon_actions": [...]
}
```
Sau đó `_normalise()` convert thành dict legacy `{route_map, parameters, auth_surface, source_indicators, _llm_raw}` để Signature/Analyst agent (chưa thay) consume bình thường.

### 2.4 Test coverage — 36/36 pass

| File test | Số test | Cover |
|---|---|---|
| `test_pipeline.py` (cũ) | 1 | Full pipeline qua rule backend, IDOR fixture validates |
| `test_benchmark.py` (cũ) | 1 | Benchmark 2 fixtures × 2 profile sets ra aggregates |
| `test_ollama_model.py` (D2) | 16 | parse_backend, registry, generate happy path, summarize wrap, headers, 401/404/5xx/timeout/non-JSON, list_tags, chat |
| `test_ollama_model_think.py` (D3) | 3 | `think` flag omit / false / true, top-level placement |
| `test_llm_json.py` (D3) | 10 | Empty, pure JSON, markdown fence, prose-around, nested, braces-in-string, unclosed, thinking-prefix |
| `test_recon_agent.py` (D3) | 5 | Heuristic path, LLM happy path (verify normalise + think=False sent), fallback on garbage, fallback on exception, fallback on non-object JSON |

Tất cả test mới dùng `unittest.mock` cho HTTP requests — chạy được offline, không cần VPS hay Docker.

### 2.5 Live test trên VPS thật

| Test | Kết quả |
|---|---|
| `make llm-test` | OK — list 1 model (`gemma4:e2b`), generate "OK" trong 31.6s (95 tokens, ≈3 tok/s) |
| `make run-ollama` (lần 1, OLLAMA_TIMEOUT=180) | Pipeline hoàn thành; recon LLM call timeout → safety net fallback sang heuristic → `validated` |
| `make run-ollama` (lần 2, OLLAMA_TIMEOUT=600) | Pipeline hoàn thành; recon LLM call → Caddy 502 (timeout-side khác) → fallback → `no_validated_findings` (budget chính của fixture = 300s đã exhaust trên LLM call) |

**Insight quan trọng**: trên CPU 4 vCPU, một recon prompt (~2KB input, ~500 token output) cần **3-10 phút**. Điều này:
- Khẳng định `architecture-v1` ghi nhận đúng: VPS hiện tại không đủ cho benchmark final
- Validate giá trị của fallback design — pipeline không crash dù LLM fail
- Sau D3 đã update Caddy timeout 600s + client timeout 600s. Khả năng chạy thông LLM path trong vài phút sau nếu thử lại trên fixture nhỏ hơn

---

## 3. Files & code mới (cộng dồn)

```
D:/CourseUIT/DACN/
├── README.md, LICENSE, pyproject.toml      (kế thừa)
├── TRACKING.md                             ← progress + decision log + sprint plan
├── Makefile                                ← thêm: run-ollama, llm-test
├── requirements.txt                        ← thêm: requests
├── .env.example                            ← OLLAMA_BASE_URL/TOKEN/TIMEOUT
├── .gitignore                              ← thêm: .env.local, notes/_*.{txt,pdf}
├── infra/                                  ← MỚI
│   ├── vps-setup.sh                        idempotent, ~120 dòng
│   └── README.md
├── src/vapt_orchestrator_safe/
│   ├── llm/
│   │   ├── ollama_model.py                 ← MỚI ~170 dòng
│   │   ├── registry.py                     ← refactored, factory backend
│   │   ├── base.py, fake_models.py         (kế thừa)
│   ├── prompts/                            ← MỚI
│   │   ├── __init__.py                     loader với string.Template
│   │   └── recon.md                        template recon
│   ├── utils/
│   │   ├── llm_json.py                     ← MỚI ~80 dòng, robust JSON extraction
│   │   ├── io.py, safety.py, text.py       (kế thừa)
│   ├── agents/
│   │   ├── recon.py                        ← REFACTOR LLM-driven + heuristic fallback
│   │   ├── intake.py, signature.py, analyst.py, exploit.py, validator.py, report.py
│   │   └── base.py                         (kế thừa, sẽ thay máu Sprint 2)
│   ├── engine/orchestrator.py              ← thread backend, label trong run summary
│   ├── cli.py                              ← --llm flag + llm-test subcommand
│   ├── config.py                           ← .env loader
│   └── (memory/, sandbox/)                 (kế thừa)
├── tests/
│   ├── test_pipeline.py, test_benchmark.py (kế thừa, vẫn pass)
│   ├── test_ollama_model.py                ← MỚI 16 test
│   ├── test_ollama_model_think.py          ← MỚI 3 test
│   ├── test_llm_json.py                    ← MỚI 10 test
│   └── test_recon_agent.py                 ← MỚI 5 test
├── data/fixtures/                          (3 toy, Sprint 2 sẽ thêm XBOW)
├── notes/
│   ├── papers/0[1-6]_*.md                  6 paper note chi tiết
│   ├── critique.md                         synthesis cross-paper, 12 gap, 3 axes
│   ├── architecture-v1.md                  DACN-X 4 component, roadmap M1-M8
│   ├── vps-plan.md                         3 strategy + security setup
│   ├── sprint-01.md                        sprint plan + progress log
│   └── _*.txt, _*.pdf                      (raw paper extract, gitignored)
├── outputs/                                run output từ smoke test
└── reports/
    ├── progress-report-01.md               (sau D2, đã obsolete)
    └── progress-report-02.md               ← FILE NÀY
```

**Loc tổng thêm vào**:
- Code production: ~600 dòng (adapter, registry, CLI, prompts loader, JSON util, recon refactor, config loader)
- Test: ~400 dòng (34 test mới)
- Docs/notes: ~3000 dòng (paper note, critique, architecture, plan, report)
- Infra: ~170 dòng (script + README)

---

## 4. Demo cho thầy

```bash
cd D:/CourseUIT/DACN

# 1. Tổng quan
cat TRACKING.md
ls notes/papers/

# 2. Run pipeline mode offline (rule, default) — 18/18 test pass + 1 pentest validated
make test
make run

# 3. Probe VPS Ollama (sau khi đã chạy infra/vps-setup.sh + tạo .env.local)
make llm-test
# kỳ vọng: list model, generate "OK", duration ~30s

# 4. Run pipeline qua Ollama — recon agent thực sự gọi LLM, nếu fail thì fallback
make run-ollama
# kỳ vọng: status ∈ {validated, no_validated_findings}, backend=ollama:gemma4:e2b
# Xem outputs/.../memory.json → events recon: hoặc "LLM recon" hoặc "falling back"
```

---

## 5. Decision đã đề xuất, chờ thầy duyệt

### 5.1 Reposition DACN scope (quan trọng nhất)

Vì VPS chỉ chạy ≤8B + no API budget → không thể reproduce SOTA. Đề xuất reposition:

> "Với small model open-source (≤8B), DACN-X chứng minh specialized components (B-Tools / FA-RAG / DO-Val) có thể thu hẹp khoảng cách với SOTA, đặc biệt trên vuln class mà cả SOTA cũng yếu (blind / framework-specific). Đây là extension hợp lý của thesis Red-MIRROR ('mid-scale OSS đua được commercial')."

**Câu hỏi:** thầy có đồng ý hướng reposition này không? Hay muốn em tìm cách scale lên 14B+ (cần Kaggle / GPU server lab cấp)?

### 5.2 Scope priority — chốt 2 hay 4 component?

| Option | Component | ETA (sau Phase 1) | Risk |
|---|---|---|---|
| Full | B-Tools + FA-RAG + DO-Val + SW-Mem | 8-10 tuần | Có thể trượt deadline |
| Trimmed (recommend) | **B-Tools + FA-RAG** | 5-6 tuần | Đánh trực tiếp G1 + G3 — output-quality gain rõ nhất |
| Minimum viable | FA-RAG only | 3-4 tuần | Có demo, có ablation |

### 5.3 Backbone fine-tune

Red-MIRROR đã release Qwen2.5-14B-LoRA dataset (1644 prompts CVE+CAPEC+ATT&CK).
- Option A: dùng base model nhỏ (gemma4:e2b) trực tiếp + leverage RAG — nhanh, không cần fine-tune
- Option B: tự fine-tune nhỏ hơn (ví dụ gemma 2B với LoRA dataset của Red-MIRROR) — nếu lab có Kaggle T4 access

### 5.4 Tên project — để thầy đặt

---

## 6. Roadmap tiếp theo

| Tuần | Sprint | Output |
|---|---|---|
| 3-4 | **Sprint 2** | Replace Analyst + Exploit + Validator agents với LLM (3 prompt + 3 normaliser); pull 3-5 XBOW Docker fixture; baseline measure SR/SCR cho LLM-pipeline (chưa có FA-RAG / B-Tools) |
| 5-6 | Sprint 3 | M2 — Tool registry + per-job Docker sandbox |
| 7-8 | Sprint 4 | M3 — FA-RAG (LlamaIndex + framework-aware corpus) |
| 9-10 | Sprint 5 | M5 — B-Tools (blind_timing_sampler, z3, hashcat) |
| 11 | Sprint 6 | M6 — DO-Val (chỉ nếu còn thời gian) |
| 12-13 | Sprint 7 | Full eval matrix: pipeline cũ vs +FA-RAG vs +B-Tools vs full; subset blind/framework-specific |
| 14-15 | Writeup | Bản nháp các chương thesis |

---

## 7. Câu hỏi cho thầy

1. **Reposition scope (5.1)**: đồng ý positioning "small-model + specialized components" không?
2. **Component priority (5.2)**: full 4 hay trim còn 2 (B-Tools + FA-RAG)?
3. **Compute lab**: có thể xin Kaggle account hoặc 1 server có GPU không? Sẽ giúp benchmark trên model lớn hơn (Qwen2.5-14B Red-MIRROR baseline) để comparison fair hơn.
4. **Fine-tune (5.3)**: dùng Red-MIRROR LoRA dataset có sẵn (nếu được release public) hay tự build?
5. **Tên project**: thầy đặt theo lineage Red-MIRROR hay tên độc lập?
6. **Demo style**: muốn em show terminal trực tiếp, hay làm slide + screenshot? Hay viết notebook?
