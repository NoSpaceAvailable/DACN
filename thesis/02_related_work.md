# Chương 2 — Công trình liên quan

## 2.1 PentestGPT (Deng et al., USENIX Security 2024)

- Kiến trúc 3 mô-đun: **Reasoning**, **Generation**, **Parsing**. Reasoning chịu trách nhiệm lập PTT (Pentesting Task Tree), Generation sinh câu lệnh cụ thể, Parsing trích xuất kết quả.
- Human-in-the-loop: cần người xác nhận nhiều bước. Chưa thực sự autonomous.
- **Điểm yếu quan trọng đối với DACN**: context loss khi PTT lớn, hallucination khi generate command, experiment vector DB nhưng confused. Không có cơ chế cắt loop tự động.

## 2.2 Red-MIRROR (UIT InSec Lab — Phan The Duy et al., 2026)

- Kiến trúc 4 tác tử: **Planner / Collector / Exploiter / Summarizer**. Đồng hành với **SRMM** (Shared Reflection & Memory Module — append-only log các plan/reflection).
- **Dual-Phase Reflection**: Intra-reflection trong Exploiter (kiểm nghiệm từng bước), Inter-reflection trong Planner (3 vote majority) → giảm infinite loop.
- Backbone: Qwen2.5-14B-Instruct + LoRA fine-tune trên 1644 sample pentest. Framework: LangGraph.
- Evaluation: XBOW 86% bug found, best trong 3 hệ thống đọc được.
- **Điểm yếu quan trọng đối với DACN**: (a) Inter-reflection vẫn vote trong cùng một họ tấn công → vẫn loop ở cấp cấu trúc; (b) chờ EOS rồi mới reflection — tốn 100–1000 token mỗi lần sai; (c) SRMM là log append-only thuần, không trả lời câu hỏi "đã gọi nmap 3 lần cùng args chưa?" một cách rẻ.
- Thầy hướng dẫn của DACN là co-author #3 của Red-MIRROR → DACN tiếp nối hướng lab, tập trung vào gaps C1/C2 (cấu trúc) và C3 (efficiency).

## 2.3 MAPTA (David & Gervais, UCL, 2025)

- Kiến trúc **Coordinator / Sandbox(N) / Validation**. Per-job Docker container đảm bảo isolation. Cost accounting chi tiết xuống từng tool call.
- Backbone: GPT-5. XBOW: 76.9% bug found. Real-world: 19 vuln, $3.67/app.
- **Điểm yếu quan trọng đối với DACN**: blind SQLi 0% (không có cơ chế timing sampler), framework-specific payloads kém, không có WAF trong eval.
- Pattern Coordinator/Sandbox/Validation được DACN giữ: Dispatcher tương đương Coordinator, DockerSandbox giống Sandbox, ValidatorAgent = Validation.

## 2.4 Các hệ thống khác

- **VulnBot** (cited baseline, 6% XBOW) — kiến trúc đơn giản, mô hình fine-tune hẹp, không có memory.
- **PentestAgent** (cited baseline, 50% XBOW) — single-agent lặp, dễ loop.
- **AutoPT** (cited baseline, 46% XBOW) — multi-agent nhưng không có loop guard.

## 2.5 Điểm yếu chung (DACN làm gì khác)

| Nhược điểm của các paper trên | DACN giải quyết qua |
|---|---|
| Wait-for-EOS rồi mới phản ứng | **C1** streaming watchdog cắt mid-thinking |
| Reflection ở cấp CoT → vẫn loop cấu trúc | **C2** signature-based loop break |
| Raw-chunk RAG tốn token | **C3** triple-based KG RAG |
| Phụ thuộc một backbone cụ thể | LangChain abstraction — 1 env var swap |

## 2.6 Bảng tổng hợp

| Hệ thống | Loop guard | Mid-thinking | KG | Backbone | XBOW |
|---|---|---|---|---|---|
| PentestGPT | human | ✗ | vector RAG | GPT-4 | n/a |
| VulnBot | ✗ | ✗ | ✗ | Qwen2.5-7B | 6% |
| PentestAgent | ✗ | ✗ | ✗ | — | 50% |
| AutoPT | ✗ | ✗ | ✗ | — | 46% |
| MAPTA | ✗ | ✗ | ✗ | GPT-5 | 76.9% |
| Red-MIRROR | inter-reflection | ✗ | ✗ | Qwen2.5-14B-LoRA | 86% |
| **DACN (đề xuất)** | **signature (C2)** | **streaming (C1)** | **triples (C3)** | gemma4:e2b / swap | — |

> **Trạng thái chương này**: DRAFT. Sẽ cập nhật sau khi chốt XBOW subset và Sprint 9 đo được.
