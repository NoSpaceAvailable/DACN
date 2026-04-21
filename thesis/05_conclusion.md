# Chương 5 — Kết luận và Hướng phát triển

## 5.1 Kết luận

Đồ án đã xây dựng **DACN** — một hệ thống đa tác tử cho web pentest với kiến trúc 4 tầng (Orchestration / Agent / Tool / RAG) và ba đóng góp nguyên gốc:

- **C1 — Mid-thinking intervention**. Lần đầu tiên trong các hệ thống pentest LLM (so với PentestGPT / Red-MIRROR / MAPTA), dispatcher có thể huỷ câu trả lời của LLM ngay giữa quá trình sinh token khi phát hiện drift / vượt scope / sắp loop. Ba watchdog ship (Drift, Scope, Loop) kiểm tra sau mỗi chunk, zero-dependency, fire-and-inject-correction pattern.
- **C2 — Anti-loop guard**. Signature buffer `hash(tool, kwargs)` + ngưỡng 3 lần → forced pivot. Cơ chế cắt loop ở cấp cấu trúc, không phụ thuộc LLM reflection, hoạt động đồng nhất trên mọi backbone.
- **C3 — Knowledge-graph RAG**. Trả về triple có cấu trúc thay cho raw chunks. Test `test_kg_is_cheaper_than_rag_for_same_question` chứng minh giảm token đáng kể cho cùng câu hỏi.

Cả ba đóng góp được gói trong abstraction LangChain nên DACN có thể chạy trên Ollama self-host (dev cost) hoặc Anthropic/OpenAI (benchmark) chỉ bằng một biến môi trường.

Hệ thống có **187 unit / integration test pass** (zero-fail CI), CLI `vapt-safe dispatch` chạy end-to-end trên fixture offline, CLI `vapt-safe ablation` sinh báo cáo so sánh 5 cấu hình × N fixture.

## 5.2 Hạn chế

- **Eval chưa thực tế**: các số liệu hiện tại (Chương 4) đều trên fixture offline + scripted chat model. Cần Sprint 9 để đo trên backbone thật (Ollama gemma4:e2b) và fixture rộng hơn (HTB / Vulhub / XBOW subset).
- **KG corpus nhỏ**: chỉ seed được 3 họ tấn công (IDOR/SSRF/SQLi). Cần distill ~5000 entry từ NVD + writeup (Sprint 8 theo directive #9 của thầy).
- **Watchdog heuristic**: LoopWatchdog hiện dùng regex pattern match trên JSON tool-call; đủ cho demo nhưng cần parser chuẩn khi LLM sinh markdown với indent khác.
- **Chưa có blind / timing exploit tool**: C-tools specialised (BlindTimingSampler, Z3Solve, Hashcat, JwtAlgConfusion) đã nằm trong roadmap Sprint 7 nhưng chưa triển khai — quan trọng để cover các gap của MAPTA/Red-MIRROR (blind SQLi 0%).

## 5.3 Hướng phát triển

1. **Sprint 9 — Real-LLM eval matrix**: chạy ablation qua gemma4:e2b trên VPS, so sánh với gpt-5-mini / claude-sonnet-4.5 trên HTB subset; báo cáo success rate / token / USD / wall-clock.
2. **Mở rộng KG corpus**: pipeline ingestion từ NVD JSON + ExploitDB + HackerOne disclosed + PortSwigger Academy. Token budget ≤ 300 token/entry, target ~5000 entry.
3. **Specialised tools** cho các gap nổi bật trong paper:
   - `BlindTimingSamplerTool` — bù vào gap MAPTA 0% blind SQLi.
   - `Z3SolveTool` — hỗ trợ constraint-based exploit (crypto padding, JWT alg confusion).
   - `HashcatTool` — password cracking in-sandbox.
4. **Dynamic fixture mode**: docker-compose chạy DVWA / WebGoat làm target sống, agent dùng tool thật (nmap / curl / http_probe / sandbox) để khai thác.
5. **Extended watchdog**: ngoài drift/scope/loop, thêm `budget-watchdog` cắt khi còn ít budget và LLM chưa propose tool call.
6. **LangGraph migration**: nếu cần phối hợp nhiều agent song song (multi-target), chuyển Dispatcher từ tool-use loop hiện tại sang LangGraph supervisor — trạng thái giống Red-MIRROR.

## 5.4 Lời cảm ơn

> Đồ án chuyên ngành này được thực hiện dưới sự hướng dẫn của **TS. Nghi Hoang Khoa** (UIT InSec Lab), co-author của Red-MIRROR. Hướng nghiên cứu DACN tiếp nối trực tiếp công trình Red-MIRROR, tập trung vào các gap mà Inter-reflection và SRMM chưa giải quyết được (loop cấu trúc, mid-thinking, token efficiency).

> **Trạng thái chương này**: DRAFT. Hoàn thiện sau khi Sprint 9 đo xong.
