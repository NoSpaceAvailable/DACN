# MAPTA — Isaac David & Arthur Gervais, arXiv 2508.20816 (Aug 2025)

**Paper:** Multi-Agent Penetration Testing AI for the Web
**Authors:** Isaac David, Arthur Gervais (University College London)
**Local PDF:** `notes/_mapta.pdf`
**Note:** Đây mới là "MAPTA" mà thầy nhắc — không phải PentestGPT.

---

## Bối cảnh & đóng góp chính

**Motivation:** AI-generated code có ~40% bug ⇒ scalability crisis trong security audit ⇒ cần autonomous pentest grounded in tool execution + end-to-end PoC validation.

**Đóng góp:**
1. **Multi-agent + tool-grounded architecture** (Coordinator / Sandbox / Validation) — claim "first open-source multi-agent web pentest AI".
2. **Cost-performance accounting** rigorously: total $21.38 / 104 challenge, median solved $0.073 vs failed $0.357 — actionable early-stopping (40 tool calls / $0.30 / 300s).
3. **Black-box benchmark**: 76.9% (80/104) trên XBOW, perfect SSRF/misconfig (100%), SSTI 85%, SQLi 83%, XSS 57%, **blind SQLi 0%**.
4. **Real-world white-box**: 19 vuln trên 10 OSS app phổ biến (8K-70K stars, gồm appsmith, directus, gitea, grafana), 14 high/critical, 10 đang chờ CVE.
5. **Open science**: code + 43 fix XBOW Docker images đã outdated.

## Kiến trúc / phương pháp

**3 role:**

| Agent | Tool interface | Vai trò |
|---|---|---|
| **Coordinator** (1) | sandbox_agent (delegate), run_command, run_python, get_registered_emails, list_account_messages, get_message_by_id, send_slack_alert, send_slack_summary | Strategy, orchestration, report; **dynamic** quyết định tự chạy hay delegate |
| **Sandbox** (1..N) | run_command, run_python | Tactical execution trong **per-job Docker container** chia sẻ; mỗi sandbox có LLM context riêng để focus, nhưng dùng chung filesystem/cookies/wordlist |
| **Validation** | (consume candidate PoC) | Chạy lại PoC end-to-end trong sandbox → pass/fail + evidence |

**Isolation:** mỗi job 1 container Docker (Ubuntu derivative). Phân biệt **LLM context isolation** (separate prompts/memory per agent) vs **system state sharing** (same container).

**Orchestration loop (single-pass controller, evidence-gated branching):**
1. Hypothesis synthesis (Coordinator suy luận attack surface)
2. Targeted dispatch (run inline hoặc delegate sandbox_agent)
3. PoC assembly (Coordinator construct minimal request sequence + oracle)
4. Validation & finalization (Validation agent execute concretely)

**Stop conditions:** validated exploit OR budget cap (cost / time / tool-call).

**Per-scan UsageTracker**: tool call count, latency, LLM token I/O & cost, wall-clock, budget cap, early-stop trigger.

**Mode:**
- **CTF (blackbox)**: single agent (Coordinator only), validation = flag extraction.
- **Real-world (whitebox)**: full Coordinator + Sandbox + Validation, validate bằng concrete state change / RCE / data access.

**Tool stack** (within container):
- Recon: nmap, ffuf, nikto, amass, httpx
- Web testing: sqlmap, dirb, jwt_tool, wafw00f
- Direct: curl, python (requests, custom scripts)

## Dataset & metric

- **XBOW** 104 challenge (binary success metric, withhold vuln type metadata để force autonomous strategy).
- 13 vuln category: A01-A07 + A10 OWASP Top-10 (skip A08 Software/Data Integrity, A09 Logging).
- **Model**: GPT-5 high-effort agent config, $1.25/1M input, $10/1M output, $0.125/1M cached.
- **Real-world**: 10 OSS app, 51K-1.3M LOC.

## Kết quả nổi bật

| Vuln class | Success | Notes |
|---|---|---|
| SSRF | 100% (3/3) | Perfect |
| Misconfiguration | 100% (3/3) | Perfect |
| Sensitive Data Exposure | 100% (2/2) | |
| Crypto | 100% (1/1) | |
| SSTI | 85% (11/13) | |
| Broken Authorization (IDOR/BOLA) | 83% (24/29) | |
| SQL Injection | 83% (5/6) | |
| Command Injection | 75% (6/8) | |
| Insecure Design | (counted) | |
| XSS | 57% (13/23) | Largest category, mid-success |
| Broken Authentication | 33% (1/3) | |
| **Blind SQLi** | **0% (0/3)** | Failure mode chính |

**Resource correlations** (negative): tool calls r=-0.661, cost r=-0.606, tokens r=-0.587, time r=-0.557.
**Median solved time**: 96.1s; failed median: 508.9s.

**Real-world**: 19 vuln, 73.7% high/critical, avg $3.67/app, 50.7 phút. Examples: command injection qua DB export (PostgreSQL pg_dump), client-side API key exposure, postMessage RCE, unauth email relay với SSRF (cloud metadata), arbitrary file write qua tool merging. 6/10 app có vuln; appsmith/directus/gitea/grafana không tìm được vuln.

## Điểm yếu / limitations (Sec 2.3 + 3.5 + thừa nhận trong text)

| Vấn đề | Chi tiết |
|---|---|
| **Blind SQLi 0%** | Timing-based attack detection yếu, payload refinement không xử lý low-signal. |
| **XSS 57%** | Cần payload generation tốt hơn + DOM manipulation strategy. |
| **Broken Auth 33%** | Session/credential analysis yếu — cần stateful auth flow reasoning. |
| **Network-level vuln out of scope** (SSL/TLS misconfig, infra). |
| **OWASP A08 / A09 không cover.** |
| **Business logic FP** không guarantee zero — multi-step transaction hợp lệ có thể bị flag. |
| **Single LLM (GPT-5)** chỉ — không cross-model so sánh (lý do: budget). |
| **N=10 real-world quá nhỏ** để validate early-stop heuristic ngoài CTF. |
| **Sandbox = Docker only** — không gVisor / Firecracker, không formal isolation guarantee. |
| **PentestGPT comparison failed** vì repo không available lúc eval. |
| **Correlation ≠ causation**: resource usage ↔ failure phản ánh challenge difficulty, không phải nguyên nhân. |

**Future work paper đề xuất:**
- Canary placement: embed detectable marker để verify exploitation thay vì heuristic oracle.
- Mở rộng vuln coverage A08/A09.
- Model diversity beyond GPT-5.

## Idea enhancement (cho DACN)

So sánh đối chiếu với Red-MIRROR và PentestGPT:

| Dimension | PentestGPT | Red-MIRROR | MAPTA | Cơ hội cho DACN |
|---|---|---|---|---|
| Memory | PTT tree (text) | SRMM (formal, agent-partitioned) | Container shared filesystem + per-agent LLM context | Hybrid: SRMM cho conceptual state + Docker FS cho artifact |
| Reflection | Active feedback (manual) | Dual-phase (intra + inter, vote) | Validation agent gates final | Reflection được conditioned bằng cost — pivot khi $$ tăng nhưng SR không đổi |
| Tool execution | Human runs | Specialized 12+ tools | Generic (run_command, run_python) trong Docker | Bộ tool **generic + framework-aware**, dynamic add tool theo recon result |
| Sandbox | None | Kali VM + Docker target | Docker per-job (Ubuntu, ephemeral) | Multi-tier sandbox: network=none cho static analysis, isolated bridge cho dynamic |
| Cost analysis | $/run aggregate | Token cost API | Granular (cached / output / reasoning), correlation analysis | DACN có thể đo cost = $ + watt-hour (energy) khi self-host + carbon footprint |
| Validation | Walkthrough match | Flag matching + manual SCR | Flag (CTF) + state-change evidence (real) | **Dual oracle**: flag + side-effect for real, fixture-defined oracle for benchmark |
| Failure mode (blind SQLi) | Brute-force lạm dụng | 0 thừa nhận | 0% | DACN: tool dedicated cho blind (statistical inference, controlled timing sampler) |

**Đặc biệt MAPTA mạnh ở chỗ Red-MIRROR yếu, và ngược lại:**
- MAPTA có Docker isolation thật + cost-aware early stop, nhưng memory chỉ là LLM context — fragile khi session > N turn.
- Red-MIRROR có memory formal + reflection chính thức, nhưng tool layer chưa có Docker isolation rõ (chạy qua Kali VM).
- → DACN có thể đề xuất **fusion**: "SRMM + Dual-Phase Reflection" của Red-MIRROR + "Coordinator/Sandbox/Validation per-job Docker + cost early-stop" của MAPTA + "PTT-style human-controllable view" của PentestGPT để on-call analyst override.

## Quick takeaway cho thesis

MAPTA và Red-MIRROR cùng ra đời 2025-2026, cả hai đều dùng XBOW làm benchmark. MAPTA mạnh hơn ở engineering (Docker, cost), Red-MIRROR mạnh hơn ở memory & reflection theory. Cả hai cùng fail blind SQLi (0%). DACN nên (a) gộp ưu điểm hai bên, (b) tấn công weak spot chung (blind/crypto/framework-specific), (c) mở rộng eval ra WAF + multi-stage chain.
