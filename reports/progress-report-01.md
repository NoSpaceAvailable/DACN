# Báo cáo tiến độ DACN — Lần 1

**Sinh viên:** [Tên SV]
**GVHD:** TS. Nghi Hoang Khoa
**Đề tài:** Nghiên cứu cơ chế điều phối và quản lý đa tác tử trong kiểm thử xâm nhập ứng dụng web
**Kỳ báo cáo:** Tuần 1-2 (đến 2026-04-18)
**Phase hiện tại:** Phase 0 — Research & Architecture (DONE) → chuẩn bị Phase 1

---

## 1. Tóm tắt việc đã làm

### 1.1 Tiếp nhận project từ thành viên trước
- Repo: `vapt_orchestrator_safe` (1 commit init từ "yuugay project")
- Đã audit: pipeline 7-agent (Intake → Recon → Signature → Analyst → Exploit → Validator → Report) chạy được, test pass, benchmark cho ra số. **Tuy nhiên mọi tầng intelligence là mock**: LLM = string template, recon = regex, RAG = keyword overlap, sandbox = đọc file JSON.
- Kết luận: scaffold đúng pattern MAPTA-style nhưng cần thay máu phần lõi.

### 1.2 Đọc & critique 6 paper related work

| # | Paper | Năm | XBOW SR |
|---|---|---|---|
| 1 | PentestGPT (Deng et al., USENIX Security 2024) | 2024 | — (HTB) |
| 2 | **Red-MIRROR (Tran, ..., Khoa, ..., Phan The Duy)** — **paper từ lab thầy** | Mar 2026 | **86.0%** |
| 3 | MAPTA (David & Gervais, UCL) | Aug 2025 | 76.9% |
| 4 | VulnBot (Kong et al., CAS) | Jan 2025 | 6.0% |
| 5 | AutoPT (Wu et al., USTC) | Nov 2024 | (41% trên benchmark riêng) |
| 6 | PentestAgent (Shen et al., Northwestern) — ASIA CCS 2025 | Nov 2024 | 50.0% |

Mỗi paper có note riêng tại `notes/papers/0X_*.md` theo template:
bối cảnh & đóng góp / kiến trúc / dataset & metric / kết quả / **limitations** / idea enhancement.

### 1.3 Xác định 12 common gap → chốt 4 gap ưu tiên

Đã viết `notes/critique.md` (synthesis cross-paper) và `notes/architecture-v1.md` (kiến trúc đề xuất). 4 gap được chọn theo priority "pentest output quality":

| Gap | Component đề xuất | Đánh paper nào |
|---|---|---|
| G1 — Blind / low-signal vuln | **B-Tools** (statistical inference + z3 + hashcat) | Red-MIRROR & MAPTA cùng 0% blind SQLi |
| G3 — Framework-specific payload placement | **FA-RAG** (LlamaIndex + framework-aware corpus) | Red-MIRROR Sec 5.2 thừa nhận |
| G7 — Validator có thể tự hallucinate | **DO-Val** (dual-oracle: LLM-judge + concrete side-effect) | MAPTA + PentestAgent C3 admit |
| G12 — SRMM recency-only, mất salient info cũ | **SW-Mem** (salience + recency weighted filter) | Implicit Red-MIRROR |

### 1.4 Hạ tầng — VPS Ollama

- Setup VPS DigitalOcean (4 vCPU, 7.8 GB RAM, no GPU) tại `157.245.195.74`.
- Pull `gemma4:e2b` từ Ollama registry (7.2 GB).
- **Constraint phát hiện:** chỉ chạy được model ≤ 8B Q4 do CPU-only + 8 GB RAM. **Không** chạy được 14B (Qwen2.5-LoRA của Red-MIRROR) hoặc DeepSeek-V3.2.

---

## 2. Vấn đề & quyết định cần thầy duyệt

### 2.1 Reposition DACN scope dưới constraint VPS

Vì chỉ self-host được model nhỏ (≤ 8B) và **không có budget API thương mại**, không thể reproduce Red-MIRROR backbone (DeepSeek-V3.2 / Qwen2.5-14B-LoRA).

**Đề xuất reposition DACN:** thay vì cố match SOTA SR của Red-MIRROR (86%), DACN claim:

> "Với model nhỏ open-source (≤8B), DACN-X chứng minh các component chuyên biệt (B-Tools / FA-RAG / DO-Val) có thể thu hẹp khoảng cách với SOTA, đặc biệt trên các vuln class mà SOTA cũng yếu (blind, framework-specific)."

Đây thực chất là extension hợp lý của thesis Red-MIRROR ("mid-scale OSS có thể đua với commercial") xuống một bậc nữa ("small-scale OSS với specialized components có thể đua với mid-scale").

### 2.2 4 component có quá nhiều cho 1 DACN không?

Nếu bị giới hạn thời gian, đề xuất cắt theo thứ tự:
1. Bỏ **SW-Mem** (G12) — phức tạp, gain marginal.
2. Bỏ **DO-Val** (G7) — có thể implement đơn giản phase sau.
3. Giữ **B-Tools** (G1) + **FA-RAG** (G3) — 2 component đánh trực tiếp output quality và là điểm yếu rõ nhất của Red-MIRROR.

### 2.3 Khác

- Có dùng Qwen2.5-14B-LoRA Red-MIRROR đã release không (nếu có) — sẽ cần upgrade VPS hoặc xài Kaggle như paper?
- Có cần fine-tune LoRA mới riêng cho DACN không?
- Thầy có muốn đặt tên project align với lineage "Red-MIRROR" không, hay tên độc lập?

---

## 3. Kế hoạch tuần tới (Sprint 1)

5 ngày làm việc, mỗi task có deliverable concrete:

| Ngày | Task | Output |
|---|---|---|
| D1 | Security setup VPS (firewall + reverse proxy + token) | `vps-plan.md` đã setup, smoke test `curl` từ máy local |
| D2 | Implement `OllamaModel` adapter trong scaffold + `--llm` CLI flag | `vapt-safe run --llm ollama:gemma4:e2b` ra output từ model thật |
| D3 | Replace `agents/recon.py` regex → LLM-driven với prompt template | Recon agent đọc HTTP transcript, sinh structured JSON về attack surface |
| D4 | Pull XBOW Docker images (3-5 challenge) làm fixture mới | 3-5 fixture XBOW chạy được local, có ground truth |
| D5 | Smoke test full pipeline LLM-driven trên 1 fixture XBOW + viết weekly note | Demo: Red-MIRROR-style flow chạy thật trên 1 challenge |

→ Sau Sprint 1, có thể **demo cho thầy 1 pentest run end-to-end** với LLM thật, dù output chưa đẹp như Red-MIRROR.

## 4. Roadmap tiếp theo (sau Sprint 1)

| Tuần | Phase | Output |
|---|---|---|
| 3-4 | Phase 2: Tool registry + per-job Docker sandbox | Tool layer abstract, sandbox isolation chuẩn |
| 5-6 | Phase 3: FA-RAG (LlamaIndex + framework-aware) | Index corpus, A/B vs keyword baseline |
| 7-8 | Phase 5: B-Tools (blind/crypto suite) | Tool dedicated, eval trên blind subset |
| 9 | Phase 6: DO-Val (nếu giữ scope này) | Dual-oracle validator |
| 10-11 | Phase 7: Full eval matrix + ablation | Số liệu cuối |
| 12-14 | Phase 7: Thesis writeup | Bản nháp các chương |

## 5. Files đã có

```
D:/CourseUIT/DACN/
├── README.md                          (kế thừa)
├── TRACKING.md                        ← progress tracker (mới)
├── Makefile                           ← thêm target: run-ollama, llm-test
├── requirements.txt                   ← thêm requests
├── .env.example                       ← OLLAMA_BASE_URL/OLLAMA_TOKEN/OLLAMA_TIMEOUT
├── infra/                             ← MỚI
│   ├── vps-setup.sh                   ← idempotent: bind localhost + Caddy + ufw
│   └── README.md
├── src/vapt_orchestrator_safe/
│   ├── llm/
│   │   ├── ollama_model.py            ← MỚI: adapter (generate/chat/list_tags)
│   │   ├── registry.py                ← refactor: factory backend rule|ollama
│   │   └── ...
│   ├── engine/orchestrator.py         ← pass backend, label trong summary
│   ├── cli.py                         ← MỚI: --llm flag + llm-test subcommand
│   ├── config.py                      ← MỚI: .env/.env.local loader
│   └── (agents/, memory/, sandbox/, utils/ — chưa thay máu, sẽ làm Sprint 2)
├── tests/
│   ├── test_pipeline.py               (kế thừa, vẫn pass)
│   ├── test_benchmark.py              (kế thừa, vẫn pass)
│   └── test_ollama_model.py           ← MỚI: 16 unit test (mock requests)
├── data/fixtures/                     (3 toy fixture, Sprint 2 sẽ thêm XBOW)
├── notes/
│   ├── papers/0[1-6]_*.md             (6 paper note)
│   ├── critique.md                    (synthesis cross-paper)
│   ├── architecture-v1.md             (4 component đề xuất + roadmap)
│   ├── vps-plan.md                    (3 strategy + security setup)
│   └── sprint-01.md                   (sprint plan + progress)
└── reports/
    └── progress-report-01.md          (file này)
```

## 7. Demo có thể show thầy

```bash
# 1. Xem progress
cat TRACKING.md
ls -R notes/

# 2. Run pipeline (offline mode default — vẫn pass)
make test           # 18 passed
make run            # status validated, backend=rule

# 3. Sau khi setup VPS theo infra/vps-setup.sh + set .env.local:
make llm-test       # probe Ollama VPS (list_tags + 1 generate)
make run-ollama     # chạy 1 fixture qua Ollama gemma4:e2b
```

## 6. Câu hỏi/yêu cầu cho thầy

1. Duyệt sơ bộ **architecture v1** — 4 component (B-Tools, FA-RAG, DO-Val, SW-Mem) có hợp lý không?
2. Chốt **scope ưu tiên** (gợi ý B-Tools + FA-RAG; bỏ SW-Mem, DO-Val nếu thiếu thời gian).
3. **Backbone model**: tự fine-tune LoRA mới hay dùng Qwen2.5-14B-LoRA của Red-MIRROR (cần infra mạnh hơn)?
4. Có thể xin lab cấp Kaggle account (như Red-MIRROR dùng T4) hoặc 1 GPU server không? VPS hiện tại không đủ cho benchmark final.
