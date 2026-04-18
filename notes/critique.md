# Cross-paper synthesis & critique

**Scope:** 6 paper đã đọc (PentestGPT, Red-MIRROR, MAPTA, VulnBot, AutoPT, PentestAgent).
**Mục đích:** rút ra design space + common gap + nơi DACN có thể chen vào, theo priority "pentest output quality first" mà user đã chốt.

---

## 1. Bảng so sánh kiến trúc

| Paper | Year | Memory | Reflection | Tool layer | Sandbox | RAG | Backbone | XBOW | Self-positioning |
|---|---|---|---|---|---|---|---|---|---|
| PentestGPT | USENIX24 | PTT (text-tree, single-session per module) | Active feedback (manual) | Suggest only — human runs | None | Tried vector DB, **rejected** | GPT-3.5/4 | — | Pioneer, HITL |
| AutoPT | 2024 | LLM context per state | Check state retry | LangChain agent + scanner | None | None | GPT-4o mini | — | FSM-constrained |
| PentestAgent | 2024 (ASIA CCS25) | Per-agent context | Validation & debugging post-execute | Custom toolset, full integration | None explicit | **Yes** + online search aug | (multiple) | 50% (per Red-MIRROR) | RAG-heavy + auto |
| VulnBot | Jan 2025 | Per-phase + Summarizer bridge | Check & Reflection (in phase) | Generator + Executor | None explicit | Optional RAG | Llama3, DeepSeek-V3 | 6% (per Red-MIRROR) | Open-source LLM, PTG DAG |
| MAPTA | Aug 2025 | LLM context per agent + shared per-job Docker FS | Validation agent gates final | Generic run_command/run_python + std tools | **Per-job Docker** ephemeral | None | GPT-5 high-effort | **76.9%** | Cost-aware, real-world OSS proof |
| Red-MIRROR | Mar 2026 (preprint) | **SRMM** (formal append-only, agent-partitioned, deterministic top-k) | **Dual-phase**: Intra (Exploiter) + Inter (Planner, 3-vote) | 12+ specialized tools (XSS, JWT, IDOR, Playwright, CVE retrieval...) | Kali VM + Docker target | Static corpus + compression Σ | DeepSeek-V3.2 + Qwen2.5-14B-LoRA | **86%** | SOTA via memory + reflection |

## 2. Common limitations (chỗ DACN có thể đánh)

| # | Gap | Paper nào nhận | Output-quality impact | Difficulty cho DACN | Đề xuất ưu tiên |
|---|---|---|---|---|---|
| G1 | **Blind / low-signal vuln** (time-based blind SQLi, blind cmd inj) | Red-MIRROR ✓ explicit, MAPTA ✓ 0%, PentestGPT ✓ implicit | **HIGH** (mất 20-30% benchmark) | Medium (cần statistical inference tool) | ⭐⭐⭐ |
| G2 | **Cryptographic challenge** | Red-MIRROR ✓ explicit, PentestGPT ✓ | Medium (vuln class nhỏ nhưng gain tuyệt đối lớn vì hiện tại 0%) | High (cần integrate z3/SymPy/Hashcat) | ⭐⭐ |
| G3 | **Framework-specific payload placement** (custom HTTP header, routing field) | Red-MIRROR ✓ explicit | Medium-HIGH (cải thiện stable challenge) | Medium (RAG corpus extension + payload template lib) | ⭐⭐⭐ |
| G4 | **Limited / outdated knowledge** (CVE mới chưa có) | PentestAgent ✓ explicit C1 | Medium (gain trên CVE recent) | Medium (online search agent crawl Exploit-DB, HackerOne) | ⭐⭐ |
| G5 | **Session context loss** (traditional) | PentestGPT, VulnBot, AutoPT, PentestAgent đều nhận | Đã largely solved bởi SRMM (Red-MIRROR). Marginal gain. | — | ⭐ (đã có SRMM) |
| G6 | **Hallucinated commands** | PentestGPT, AutoPT, VulnBot | Medium | Low (self-consistency vote, validator) | ⭐ (Red-MIRROR đã có) |
| G7 | **Validation chính LLM-based** → có thể tự hallucinate | PentestAgent ✓, MAPTA admits | HIGH (false positive) | Medium (dual-oracle: LLM + concrete side-effect check) | ⭐⭐⭐ |
| G8 | **Business logic vuln** | MAPTA ✓ explicit | HIGH nhưng khó | Very High | ⭐ |
| G9 | **WAF / IDS in eval** | Red-MIRROR ✓ explicit (chưa test) | Indirect (relevance hơn là quality) | Medium | (drop per user priority) |
| G10 | **Multi-target / lateral movement** | Implicit ở mọi paper | Low-Medium | Very High | (drop per user priority) |
| G11 | **Cost / energy tracking** | Chỉ MAPTA detailed | Không phải output quality | — | (drop per user priority) |
| G12 | **SRMM recency-only**, không có salience-weighted | Implicit Red-MIRROR (paper không nhận) | Medium-HIGH cho session dài | Medium (thay Filterk top-k recent bằng top-k by importance score) | ⭐⭐ |

→ **Top 4 priority cho DACN** (output-quality + tractable cho 1 thesis): **G1, G3, G7, G12**.

## 3. Design axes (3 trục thiết kế cross-paper)

### Trục A — Memory mechanism

`text history (PentestGPT)` → `per-phase summarizer bridge (VulnBot)` → `per-agent context + shared FS (MAPTA)` → `formal append-only segregated R/W (Red-MIRROR SRMM)`

**Unexplored cell:** salience-weighted memory với forgetting/compaction cho session > 50 turn. Hiện SRMM filter k recent per agent — sẽ bỏ sót discovery quan trọng nếu nó cũ.

### Trục B — Reflection mechanism

`none / manual (PentestGPT)` → `check & retry (VulnBot)` → `Check state transition (AutoPT FSM)` → `validation post-execute (PentestAgent, MAPTA)` → `dual-phase intra+inter, vote (Red-MIRROR)`

**Unexplored cell:** **cost-conditioned reflection** — khi $$ spent tăng nhưng SR không đổi → trigger pivot strategy (kết hợp Inter-reflection của Red-MIRROR + early-stop heuristic của MAPTA).

### Trục C — Tool / sandbox

`HITL run (PentestGPT)` → `LangChain agent + scanner (AutoPT)` → `custom integration + KB (PentestAgent)` → `Generator + Executor in-process (VulnBot)` → `12+ specialized tools, Kali VM (Red-MIRROR)` → `generic run_command/python + per-job Docker (MAPTA)`

**Unexplored cell:** **multi-tier sandbox** — `network=none` Docker cho static analysis + `isolated bridge` cho dynamic + `egress=cloud-metadata` cho SSRF — chọn tier tự động theo hypothesis class. Cũng: **statistical inference tool dedicated cho blind class** (G1) — LLM sinh template, tool sample/aggregate.

## 4. Vị trí DACN — đề xuất framing 1 câu

> "DACN extends Red-MIRROR theo 3 trục output-quality: (a) **specialized tool layer cho blind / framework-specific vuln** mà Red-MIRROR nhận yếu (G1, G3); (b) **dual-oracle validation** combine LLM-judge + concrete side-effect để giảm false-positive (G7); (c) **salience-weighted memory** thay top-k recency của SRMM cho phiên pentest dài (G12). Eval trên XBOW + Vulhub (cùng setup Red-MIRROR) + 1 subset blind/crypto/framework-specific để measure direct gain."

## 5. Câu hỏi mở cần thầy chốt

1. **Có đủ infra để test trên XBOW (104 challenge) không?** XBOW Docker images: 43/104 cần fix theo MAPTA — họ release fix qua PR. Cần xem PR đã merge chưa.
2. **DeepSeek-V3.2 hay Qwen2.5-14B-LoRA Red-MIRROR đã release?** Nếu có Qwen LoRA → leverage trực tiếp. Nếu không → DACN phải fine-tune lại hoặc dùng base model.
3. **Scope vuln focus**: chốt **G1+G3** (blind + framework-specific) làm mục tiêu chính, hay thêm G7 (validation), G12 (memory)?
4. **VPS 157.245.195.74 spec**: Ollama có chạy được model 14B+ không? Nếu CPU-only → benchmark sẽ rất chậm.

---

*Last updated: 2026-04-18*
