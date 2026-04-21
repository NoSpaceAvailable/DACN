# Chương 1 — Giới thiệu

## 1.1 Bối cảnh

Kiểm thử xâm nhập ứng dụng web (web-app penetration testing, VAPT) là công việc đòi hỏi kiến thức rộng (recon, phân tích mã nguồn, tổng hợp payload, viết exploit, kiểm chứng oracle) và thường chiếm thời gian lớn của các đội bảo mật. Trong ba năm gần đây (2023–2026), nhiều hệ thống đa tác tử (multi-agent) sử dụng mô hình ngôn ngữ lớn (LLM) đã được đề xuất để tự động hoá một phần hoặc toàn bộ quy trình này — tiêu biểu là **PentestGPT** (Deng et al., USENIX Security 2024), **Red-MIRROR** (UIT InSec Lab, 2026), và **MAPTA** (UCL, 2025).

Mỗi hệ thống đem lại một đóng góp thiết kế quan trọng: PentestGPT tách Reasoning/Generation/Parsing, Red-MIRROR giới thiệu SRMM (append-only shared memory) + Dual-phase Reflection, MAPTA đưa ra kiến trúc Coordinator/Sandbox/Validation với per-job Docker + cost accounting. Tuy nhiên cả ba đều mang những **điểm yếu chung**:

1. Không có cơ chế **phát hiện và cắt loop ở cấp cấu trúc** — chỉ dựa trên reflection ở cấp chuỗi tư tưởng.
2. Không có cơ chế **can thiệp vào khi LLM đang sinh chain-of-thought** — chi phí "nhận ra sai" luôn bằng một round-trip hoàn chỉnh.
3. Chi phí truy vấn tri thức (RAG) vẫn cao — raw text chunks, không cấu trúc.

## 1.2 Mục tiêu đề tài

Đồ án xây dựng một **hệ thống đa tác tử** cho web pentest với ba đóng góp nguyên gốc nhằm giảm các nhược điểm trên:

- **C1 — Mid-thinking intervention (streaming watchdog).** Dispatcher chạy LLM ở chế độ streaming và giám sát buffer sau mỗi chunk. Ba watchdog kiểm tra drift (mất tập trung), scope (vượt phạm vi), và loop (chuẩn bị gọi tool đã loop). Khi vi phạm, stream bị huỷ, hướng dẫn chỉnh sửa được tiêm vào lượt kế tiếp.
- **C2 — Anti-loop guard (signature buffer).** Mỗi tool call đẩy một signature `hash(tool_name, kwargs)` vào buffer có giới hạn của Blackboard. Khi cùng một signature xuất hiện ≥ 3 lần, guard log sự kiện, reset buffer, và tiêm thông báo bắt buộc gọi `pivot(reason=…)` ở lượt sau.
- **C3 — Knowledge-graph RAG.** Thay vì trả về đoạn văn thô, KG trả về các triple có cấu trúc (`Payload -[TARGETS]-> Sink`, `Payload -[CLASSIFIED_AS]-> CWE`, …). Tiết kiệm 10–20× token cho cùng câu hỏi khi hỏi về họ tấn công / framework / sink.

## 1.3 Phạm vi

- Hệ thống chạy offline trong một **local lab** dựa trên fixture (HTTP transcript + source snapshot + oracle). Không quét IP/ domain công khai. Không ship exploit weaponised.
- Tầng LLM được trừu tượng hoá qua LangChain nên có thể chạy trên Ollama (VPS self-host), OpenAI, Anthropic, OpenRouter hoặc bất kỳ endpoint OpenAI-compatible nào chỉ bằng thay đổi biến môi trường `LLM_BACKEND_*`.
- Mục tiêu so sánh: với cùng cấu hình fixture, hệ thống DACN phải đạt ≥ 80% success-rate của gpt-5-mini và claude-sonnet-4.5 khi dùng backbone nhỏ hơn (gemma4:e2b trên CPU VPS).

## 1.4 Đóng góp chính

Tóm tắt ba đóng góp nguyên gốc của đồ án (sẽ được triển khai chi tiết ở Chương 3):

| Ký hiệu | Tên | Tóm tắt ý tưởng |
|---|---|---|
| **C1** | Mid-thinking intervention | Streaming + 3 watchdog cắt sinh câu trả lời khi LLM đi sai — tiết kiệm 100–1000 token/lần sai thay vì chờ EOS |
| **C2** | Anti-loop guard | Signature buffer + forced pivot — không phụ thuộc vào reflection của LLM |
| **C3** | KG RAG | Triple-based retrieval thay cho raw-chunk RAG — giảm 10–20× token cho truy vấn có cấu trúc |

Các đóng góp này trực giao nhau; đồ án có ablation matrix chứng minh mỗi thành phần có lợi riêng (Chương 4).

## 1.5 Cấu trúc đồ án

- Chương 2 khảo sát công trình liên quan: PentestGPT, Red-MIRROR, MAPTA, VulnBot, AutoPT, PentestAgent; tổng hợp điểm yếu chung.
- Chương 3 mô tả kiến trúc DACN (4 tầng: Orchestration / Agent / Tool / RAG) và ba đóng góp C1/C2/C3.
- Chương 4 đánh giá: ablation matrix trên bộ fixture, so sánh backbone nhỏ (gemma4) vs baseline (gpt-5-mini / claude-sonnet).
- Chương 5 kết luận + hạn chế + hướng phát triển.

> **Trạng thái chương này**: DRAFT. Các số liệu ở §1.3 và §1.4 sẽ được cập nhật sau khi Sprint 9 hoàn tất eval trên dataset HTB + Vulhub rộng hơn.
