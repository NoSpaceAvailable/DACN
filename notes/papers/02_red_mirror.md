# Red-MIRROR — Tran et al., arXiv 2603.27127 (preprint, Mar 2026)

**Paper:** Red-MIRROR: Agentic LLM-based Autonomous Penetration Testing with Reflective Verification and Knowledge-augmented Interaction
**Authors:** Tran Vy Khang, Nguyen Dang Nguyen Khang, Nghi Hoang Khoa, Do Thi Thu Hien, Van-Hau Pham, **Phan The Duy** (corresponding) — **UIT Information Security Lab, VNU-HCM**
**Funding:** VNU-HCM grant NCM2025-26-01
**Local PDF:** `notes/_red_mirror.pdf` (đã download qua WebFetch)

> ⚠️ **CỰC KỲ QUAN TRỌNG:** corresponding author là *Phan The Duy* (duypt@uit.edu.vn) — gần như chắc chắn là **thầy hướng dẫn DACN của bạn**. Tác giả chính (22520628, 22520617) là sinh viên UIT khoá 2022. Đề tài DACN của bạn nhiều khả năng là **mở rộng / kế thừa Red-MIRROR**, không phải làm lại từ đầu.

---

## Bối cảnh & đóng góp chính

**3 limitation của LLM pentest hiện tại (motivation):**
1. Memory & session fragmentation (VulnBot, PentestAgent, AutoPT)
2. Lack of payload validation → blind tool calling, malformed request
3. Tool integration không chuyên biệt cho web modern (chỉ dùng nmap, sqlmap general)

**4 đóng góp:**
1. **Red-MIRROR framework** = tightly coupled SRMM + Dual-Phase Reflection + RAG (kiến trúc graph, LangGraph).
2. **Fine-tuning dataset** 1,644 instruction-response pair (CVE 500 + CAPEC 239 + MITRE ATT&CK 905) → LoRA Qwen2.5-14B đua được với commercial LLM.
3. **Subtask-level benchmark**: 50 XBOW challenge (chia level 1/2/3) + 8 Vulhub critical CVE, có annotation từng subtask để chấm Subtask Completion Rate (SCR).
4. **Ethical safeguards**: RBAC, audit log, RAG knowledge gating.

## Kiến trúc / phương pháp

**4 agent + LangGraph orchestration:**

| Agent | Vai trò | Cơ chế đặc biệt |
|---|---|---|
| **Planner** | Sinh & revise Penetration Path Planning DAG, inter-reflection | Đọc SRMM aggregated context, không write |
| **Collector** | Recon (consolidate vào 1 agent để giảm fragmentation) | Tools: WhatWeb, curl, dirsearch, brute-force |
| **Exploiter** | Sinh & execute payload, **Intra-reflection** loop | Tools: HTTP, JWT, file upload, XSS fuzz, IDOR, Playwright, CVE retrieval, code injection |
| **Summarizer/Analyzer** | Knowledge synthesis + final report | Cross-correlate Collector output ↔ RAG ↔ Exploiter |

**SRMM (Shared Recurrent Memory Mechanism)** — đây là điểm bán paper:
- 3 thành phần: (1) Text Memory Storage Mtext (agent-partitioned, temporally indexed), (2) Shared Memory Aggregator Σ (LLM summarizer), (3) SRMM Manager (access control).
- **Write**: chỉ execution agent (Collector/Exploiter), append-only monotonic.
- **Read**: chỉ Planner, deterministic filter top-k recent per agent → format → summarize.
- **Formal properties**: monotonic growth, unidirectional flow (no feedback loop), bounded context window |Filterk(Mtext)| ≤ k·|AE|, deterministic retrieval, aggregation compression.

**Dual-Phase Reflection:**
- **Intra-reflection** (Algorithm 3, Exploiter): generate → execute → reflect-update state → retry, max N iterations.
- **Inter-reflection** (Algorithm 4, Planner): self-consistency 3-vote (majority), flag check, aggregate global context, re-plan, hard stop ở Tmax.
- Hard termination: max 10 iterations (mitigation cho DoS từ STRIDE analysis).

**RAG corpus:** SQLi/XSS payload, bypass technique, template/command injection example (MySQL, Jinja2, Twig…). Compression: aggregator Σ chiết "endpoint, credential, behavior, defense" và bỏ noise.

**LoRA config:** r=16, α=32, applied to all linear modules; cosine LR; differentiated learning rate (LoRA+).

## Dataset & metric

- **XBOW**: 50 challenge (21 L1 + 24 L2 + 5 L3), avg 9.3 subtask, blind/low-observability chỉ ~8%.
- **Vulhub**: 8 critical CVE (CVE-2019-10758, 2019-15107, 2021-26084, 2021-42013, 2022-22963, 2022-26134, 2023-22515, 2025-3248), avg 4.125 subtask.
- **Metric**: Success Rate (binary flag), Subtask Completion Rate (SCR — manual annotate, subjective), Time Budget (15 min DeepSeek, 30 min Qwen).
- **Models**: DeepSeek-V3.2 (128k ctx, $0.28/$0.42 per 1M tok) + Qwen2.5-14B-LoRA (32k, self-host Kaggle 4-bit T4).

## Kết quả

**XBOW (RQ1, identical DeepSeek-V3.2 backbone):**
- Red-MIRROR Full: **86.0% SR, 93.99% SCR**
- PentestAgent: 50.0%
- AutoPT: 46.0%
- VulnBot baseline: 6.0%

**Vulhub:** comparable to SOTA (paper không nhấn mạnh số).

**RQ3 ablation:** SRMM mạnh nhất ở stateful steps (session, multi-step IDOR), Dual-phase mạnh nhất ở injection có observable output. Khi tắt cả hai → degrade nghiêm trọng ở blind/low-signal.

## Điểm yếu / limitations (Sec 5.2 + 5.5 — quan trọng nhất cho DACN)

| Vấn đề | Chi tiết |
|---|---|
| **Blind/low-signal vuln** | Time-based & boolean blind SQLi, blind cmd injection — Dual-phase phá sản vì không có semantic feedback; SRMM chỉ store delay observation. Network jitter làm false +/-. |
| **Cryptography** | LLM yếu numerical/algebraic; cần delegate sang specialized solver (constraint solver, symbolic computation). |
| **Framework-specific exploit** | Cần precise payload placement (custom HTTP header, framework routing field) — RAG corpus hiện tại không đủ. |
| **Benchmark bias** | Chỉ ~8% blind challenge → overestimate trên sparse-feedback environment. |
| **Không có WAF / IDS / honeypot** trong test env. |
| **LLM stochasticity** dù temperature thấp, majority vote không khử hết. |
| **Data contamination**: XBOW & Vulhub có thể đã trong pre-training corpus — paper nói mitigate bằng zero-shot và dynamic flag. |
| **Subjectivity** trong manual subtask annotation. |
| **Không thay được human** với business-logic complex. |

**Hướng future work paper đề xuất:**
- Decouple high-level reasoning khỏi low-level measurement (LLM sinh template, tool chuyên dụng làm sampling/timing).
- Hybrid architecture với cryptanalytic tools (constraint solver, symbolic computation).
- Stronger framework-specific RAG retrieval (payload placement convention).
- Human-in-the-loop collaborative framework.
- Low-signal exploitation setting.

## Idea enhancement (cho DACN)

Vì đây nhiều khả năng là paper của lab thầy, **DACN không nên cố "đánh bại" mà nên enhance / fill gap**:

1. **Blind-vuln module**: build tool layer chuyên cho blind SQLi (controlled timing sampling + statistical inference), giải quyết weakness #1 mà paper tự nhận.
2. **Crypto-aware agent**: tích hợp z3 / SymPy / Hashcat làm tool, để LLM chỉ identify primitive + chọn attack model.
3. **Framework-aware RAG**: corpus extension với Spring Boot, Django, Express… payload placement convention (đây là weakness #3).
4. **Real-world / WAF eval**: deploy ModSecurity hoặc CRS-rules trên fixture, đo regression vs Red-MIRROR base. Paper tự nhận chưa test có WAF.
5. **Cost & energy benchmark**: paper chỉ track token cost, chưa so chi phí giữa DeepSeek API vs self-host Qwen2.5 chi tiết — DACN có thể là "cost-aware orchestration" extension.
6. **Memory schema critique**: SRMM monotonic append-only — chưa có forgetting / compaction. Khi session dài thật (>50 steps), bounded retrieval (top-k recent) sẽ bỏ sót info quan trọng cũ. Đề xuất salience-weighted memory thay vì recency-only.
7. **Multi-target / lateral movement**: Red-MIRROR chỉ test single web app. DACN có thể mở rộng ra chained target (web → API → cloud metadata) — đúng spirit "đa tác tử".
