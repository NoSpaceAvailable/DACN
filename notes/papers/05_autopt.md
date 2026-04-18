# AutoPT — Wu et al., arXiv 2411.01236 (Nov 2024)

**Paper:** AutoPT: How Far Are We from the End2End Automated Web Penetration Testing?
**Authors:** Benlong Wu, Guoqiang Chen (QI-ANXIN), Kejiang Chen (corresponding), Xiuwei Shang, Jiapeng Han (Chaitin), Yanru He, Weiming Zhang, Nenghai Yu — USTC + industry partners
**Local:** `notes/_autopt.pdf`

---

## Đóng góp chính

1. **End-to-end web pentest benchmark** dựa trên Vulhub: 20 Docker env, gắn nhãn simple/complex theo số step (≥3 = complex), có **clear target string** để check tự động (giải quyết "không có stop signal" của benchmark cũ).
2. **Penetration testing State Machine (PSM)**: kết hợp FSM cổ điển + LLM agent. 5 state cố định:
   - **Scanning** (open-source scanner ra vuln list)
   - **Selection** (LLM chọn vuln likely nhất)
   - **Reconnaissance** (tool scout theo vuln info)
   - **Exploitation** (LLM sinh exploit attempt)
   - **Check** (parse output → state transition)
3. **AutoPT** = PSM impl trên LangChain.

## Kiến trúc khác biệt

- **Constraint mạnh**: state transition là rule-based (không phải LLM tự quyết) → giảm hallucination trong control flow, LLM chỉ làm task con.
- Trade-off: kém flexible hơn LangGraph dynamic của Red-MIRROR; nhưng dễ debug, dễ trace.
- Tách bạch **Agent state** (LLM-driven) vs **Rule state** (deterministic).

## Kết quả

- ReAct + GPT-4o mini baseline: **22%** task completion
- AutoPT + GPT-4o mini: **41%**
- Cost giảm 71.6% so với baseline; thời gian giảm 96.7%.

## Limitation tự nhận

- Vẫn fail trên complex multi-step exploit (hallucination command)
- Chỉ web pentest, post-exploit/report không cover
- FSM cứng → khó adapt vuln class mới mà không thiết kế state mới
- **Không có RAG** (knowledge chỉ từ pre-trained)
- Backbone yếu (GPT-4o mini chỉ vì cost) — không test trên model lớn

## Vì sao Red-MIRROR đập AutoPT 86% vs 46%?

- AutoPT FSM thiếu reflection toàn cục (Check state chỉ retry/transition, không re-plan strategy)
- Không có shared memory giữa state — message history vẫn nằm trong LLM context window từng lượt
- Tool generic (chưa có XSS fuzz / JWT / IDOR module chuyên)

## Idea cho DACN

- **PSM idea hay**: dùng FSM cho meta-control (đảm bảo không lệch quy trình), nhưng nội mỗi state để LLM agent tự do. DACN có thể combine **FSM outer loop + LangGraph inner agent loop** — vừa robust vừa flexible.
- Benchmark style "clear target string per task" rất phù hợp scaffold hiện tại (`ground_truth.json` đã có `oracle` field) — bạn có thể mở rộng fixture theo pattern này.
