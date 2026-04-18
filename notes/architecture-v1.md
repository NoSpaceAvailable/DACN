# DACN architecture v1 (proposal, draft 2026-04-18)

**Status:** DRAFT — chờ thầy duyệt và chốt scope.
**Positioning:** Extension của Red-MIRROR (lab UIT InSec), focus vào **pentest output quality** trước (theo priority user).

---

## 1. Top-line claim

> Red-MIRROR đạt SOTA 86% XBOW nhưng tự nhận 3 weakness: blind vuln, crypto, framework-specific payload. DACN đề xuất **DACN-Pentest** (tên placeholder), thêm 4 component vào Red-MIRROR để đánh trực tiếp 3 weakness đó + 1 weakness ngầm (memory recency-only):
>
> 1. **Specialized Blind/Crypto Tool Suite** (B-Tools) — đánh G1, G2.
> 2. **Framework-Aware RAG** (FA-RAG) — đánh G3.
> 3. **Dual-Oracle Validator** (DO-Val) — đánh G7 (false positive).
> 4. **Salience-Weighted Memory** (SW-Mem) — đánh G12 (long session).

## 2. Architecture diagram (text)

```
                     ┌────────────────────────────────────┐
                     │      Planner Agent (LLM)           │
                     │   - DAG path planning              │
                     │   - Inter-reflection (3-vote)      │
                     │   - Cost-conditioned pivot (NEW)   │
                     └────┬───────────────┬───────────────┘
                          │read           │write-plan
                  ┌───────▼────────┐      │
                  │  SW-Mem (NEW)  │      │
                  │ - per-agent    │      │
                  │ - salience+    │      │
                  │   recency      │      │
                  │ - LLM Σ        │      │
                  └───────▲────────┘      │
                          │write          │
        ┌─────────────────┼───────────────┼────────────────┐
        │                 │               │                │
   ┌────▼─────┐    ┌──────▼─────┐   ┌────▼─────┐    ┌─────▼────┐
   │Collector │    │ Exploiter  │   │  B-Tools │    │ DO-Val   │
   │ Agent    │    │ Agent      │   │ Agent    │    │ Agent    │
   │          │    │ (Intra-    │   │ (NEW)    │    │ (NEW)    │
   │WhatWeb,  │    │  reflect)  │   │statistical│   │LLM-judge │
   │curl,     │    │XSS/JWT/    │   │inference, │   │+ side-   │
   │dirsearch,│    │IDOR/...    │   │z3, SymPy, │   │effect    │
   │brute     │    │            │   │Hashcat    │   │check     │
   └──────────┘    └────────────┘   └──────────┘    └──────────┘
                          │                                │
                          │    candidate PoC               │
                          └───────────────────────────────►│
                                                           │ pass/fail
                                                           ▼
                                                    ┌──────────┐
                                                    │ Reporter │
                                                    └──────────┘

                    All execution wrapped in:
              ┌─────────────────────────────────┐
              │ Multi-tier per-job Docker (NEW) │
              │ - net=none for static           │
              │ - isolated bridge for dynamic   │
              │ - egress=metadata for SSRF      │
              └─────────────────────────────────┘
```

## 3. Component spec (4 thành phần mới)

### 3.1 SW-Mem — Salience-Weighted Memory

**Vấn đề:** SRMM lọc top-k recent per agent. Trong session > 50 turn, discovery quan trọng (vd credential dump ở turn 5) sẽ bị đẩy ra ngoài cửa sổ và mất.

**Đề xuất:**
- Mỗi observation `o_a,t` được gán `salience(o)` = LLM-judge score [0..1] dựa trên:
  - Có chứa credential / token / endpoint admin? → high
  - Có chứa stack trace / version string? → medium
  - Là HTTP 200 generic / banner? → low
- `Filter_k` đổi thành `top-k by combined score = α·salience + (1-α)·recency_score`.
- Compaction khi |Mtext_a| > N: gộp các o low-salience cũ thành 1 summary node.

**Eval design:** A/B Red-MIRROR base SRMM vs SW-Mem trên các challenge XBOW có chain ≥ 12 subtask (Red-MIRROR EDA: max 17, avg 9.3 — chia subset top-25% chain dài).

**Acceptance:** SCR cải thiện ≥ 5% trên long-chain subset.

### 3.2 B-Tools — Blind / Crypto Tool Suite

**Vấn đề:** Red-MIRROR & MAPTA = 0% blind SQLi. Crypto challenge cũng fail. LLM tự sinh script timing-based không đáng tin (jitter, false +/-).

**Đề xuất:** Đăng ký vào tool registry các function chuyên dụng:

| Tool | Input | Output | Fix gap |
|---|---|---|---|
| `blind_timing_sampler(url, payload_template, true_branch_payload, false_branch_payload, n_samples=30, alpha=0.05)` | URL + 2 payload | bit Boolean với p-value | G1 timing-based blind SQLi/cmd |
| `boolean_blind_oracle(url, payload_template, oracle_pattern)` | | bit | G1 boolean-based |
| `binary_search_extractor(url, payload_template, oracle_func, charset, max_len=64)` | | extracted string | G1 high-bandwidth extraction |
| `z3_solve(constraints)` | SMTLib | model | G2 crypto algebraic |
| `hashcat_crack(hash, mode, wordlist)` | | plaintext | G2 password/JWT brute |
| `jwt_alg_confusion(token)` | | forged token | G2 JWT (Red-MIRROR đã có nhưng có thể mở rộng) |

**Eval design:** Subset XBOW blind (3 challenge) + Vulhub crypto (nếu có) + tự tạo 5-10 fixture blind SQLi mới để có cỡ mẫu nghĩa.

**Acceptance:** Blind SQLi 0% → ≥ 50%.

### 3.3 FA-RAG — Framework-Aware RAG

**Vấn đề:** Red-MIRROR RAG corpus tổng quát; thiếu **payload placement convention** cho từng framework.

**Đề xuất:**
- Index riêng theo **(framework, vuln_class, payload_template, placement)** quadruples.
- Sources: Spring Boot security advisory, Django security release, Express middleware doc, Laravel/Symfony exploit writeup, framework-specific HackerOne report.
- Retrieval pipeline:
  1. Recon agent identify framework (đã có WhatWeb).
  2. Khi Exploiter cần payload → query FA-RAG với (framework, vuln_class).
  3. Re-rank bằng cross-encoder (bge-reranker-large).
  4. Compress: chỉ feed payload template + placement hint, bỏ prose.
- LlamaIndex stack (đúng hướng thầy gợi ý).

**Eval design:** Subset Vulhub CVE + 1 set fixture có framework-specific payload (vd Spring Actuator, Django debug page, Rails secret_key_base).

**Acceptance:** SR trên framework-specific subset cải thiện ≥ 15% so với Red-MIRROR base RAG.

### 3.4 DO-Val — Dual-Oracle Validator

**Vấn đề:** Red-MIRROR validator + Inter-reflection vote vẫn LLM-based → có thể đồng bộ hallucinate. MAPTA Validation agent cũng admit không guarantee zero FP.

**Đề xuất:** Validator có 2 oracle độc lập:
1. **LLM-judge oracle** (existing): LLM đọc response + ground truth → judge.
2. **Concrete side-effect oracle** (NEW): chạy 1 probe sau exploit để verify state change:
   - SQLi → re-query DB với credential thu được.
   - SSRF → check log Docker container có outbound request không (network capture).
   - File upload RCE → check process list trong container có spawn shell không.
   - IDOR → verify response chứa email/PII của user khác (phạm vi cho phép).

PoC chỉ pass nếu **cả 2 oracle agree**. Disagree → mark "supported" (như Red-MIRROR đã có status `supported`).

**Eval design:** Inject 10% deliberate FP vào benchmark (giả ground truth) → đo precision tăng vs Red-MIRROR base.

**Acceptance:** False positive rate giảm ≥ 30% với SR drop < 5%.

## 4. Diff vs scaffold hiện tại

Scaffold `vapt_orchestrator_safe` hiện tại đã có khung 7-agent (Intake, Recon, Signature, Analyst, Exploit, Validator, Report) + SharedMemory + BudgetTracker + benchmark harness. Cần thay/thêm:

| Scaffold component | Status | Action |
|---|---|---|
| `RuleBasedModel` (LLM mock) | KEEP as fallback | Add `OllamaModel` cạnh, target VPS 157.245.195.74 |
| `agents/recon.py` (regex) | REPLACE | LLM-driven, dùng tool registry (nmap, WhatWeb...) |
| `agents/signature.py` (keyword RAG) | REPLACE | FA-RAG (LlamaIndex + bge-m3 + reranker) |
| `agents/analyst.py` (if/else) | REPLACE | Planner LLM với DAG + Inter-reflection 3-vote |
| `agents/exploit.py` (templates) | REPLACE | Exploiter LLM + Intra-reflection + B-Tools |
| `agents/validator.py` (oracle match) | EXTEND | DO-Val 2-oracle |
| `memory/shared_memory.py` (list of dict) | EXTEND | SW-Mem (salience score + compaction) |
| `sandbox/local_lab.py` (file read) | REPLACE | Multi-tier Docker (chỉ cho Phase 2+) |
| `engine/orchestrator.py` (linear) | REPLACE | LangGraph cyclic (theo Red-MIRROR) |
| `engine/router.py` (capability score table) | KEEP | Bổ sung skill registry → tool routing động |
| `engine/budget.py` | KEEP | OK |
| `engine/benchmark.py` | EXTEND | Thêm metric: precision/recall/F1, blind/crypto/framework subset |
| Fixtures (3 toy) | EXTEND | Import XBOW Docker (104 sau MAPTA fix) + Vulhub 8 CVE Red-MIRROR + tự tạo blind/crypto subset |

## 5. Roadmap cập nhật (replace M1-M4 trong TRACKING)

| Milestone | Tuần | Output |
|---|---|---|
| M1 — Wire Ollama VPS | 1-2 | `OllamaModel`, prompt per role, smoke test 3 fixture cũ ra LLM-driven report |
| M2 — Replace Recon + Exploit + Validator agent | 3-4 | LLM-driven, tool registry layer (chưa có B-Tools), Docker per-job sandbox |
| M3 — FA-RAG + LlamaIndex | 5-6 | Index, retrieval, reranker, compression. A/B vs keyword baseline |
| M4 — SW-Mem | 7 | Salience scoring, compaction. A/B vs SRMM recency-only trên long-chain |
| M5 — B-Tools | 8-9 | blind_timing_sampler, z3, hashcat tool. Test trên blind subset |
| M6 — DO-Val | 10 | 2-oracle validator, precision eval với injected FP |
| M7 — Full eval matrix | 11-12 | XBOW + Vulhub + custom subset; 3 model size; ablation off/on từng component |
| M8 — Thesis writeup | 13-14 | Chương Background, Method, Eval, Limitation, Future Work |

## 6. Risk & open questions

- **Risk 1 — VPS không đủ mạnh** chạy 14B+: **xác nhận 2026-04-18, max 8B Q4 Ollama, no API budget**. → DACN reposition: claim cải thiện ở vuln class yếu (blind/framework-specific) thay vì match Red-MIRROR overall SR.
- **Risk 2 — XBOW Docker chưa fix hết**: clone PR của MAPTA hoặc giảm scope eval xuống 5-10 challenge ban đầu.
- **Risk 3 — Phạm vi quá lớn cho DACN 1 kỳ**: priority cut order = SW-Mem → DO-Val → FA-RAG, giữ B-Tools (G1) cuối cùng vì đánh trực tiếp gap 0% blind SQLi.
- **Open Q1 — LangGraph hay custom orchestration?** Hiện scaffold custom; có thể migrate sau khi Phase 1 ổn.
- **Open Q2 — Fine-tune LoRA?** Red-MIRROR's Qwen2.5-14B-LoRA chạy không nổi trên VPS hiện tại → DACN dùng base model nhỏ trực tiếp + relying on RAG/tools để compensate.
- **Open Q3 — Tên project**? Để thầy đặt.

## 7. Đã thực hiện (2026-04-18)

Sprint 1 D1+D2 done — xem `notes/sprint-01.md` cho chi tiết:
- `infra/vps-setup.sh` + Caddyfile bearer-token + ufw (chưa deploy lên VPS, đợi user chạy)
- `OllamaModel` adapter + `--llm` CLI + `llm-test` subcommand + 16 mock test (all pass)
- Backend label được track trong run summary để biết result đến từ rule vs ollama:gemma4:e2b
- `.env.local` loader cho OLLAMA_BASE_URL/OLLAMA_TOKEN/OLLAMA_TIMEOUT
