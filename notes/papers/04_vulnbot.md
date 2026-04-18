# VulnBot — Kong et al., arXiv 2501.13411 (Jan 2025)

**Paper:** VulnBot: Autonomous Penetration Testing for A Multi-Agent Collaborative Framework
**Authors:** He Kong, Die Hu, Jingguo Ge, Liangxiong Li, Tong Li, Bingzhen Wu (CAS Beijing — Institute of Information Engineering)
**GitHub:** https://github.com/KHenryAegis/VulnBot
**Local:** `notes/_vulnbot.pdf`

---

## Đóng góp chính

1. **Tri-phase design**: Reconnaissance → Scanning → Exploitation (mỗi phase 1 set agent chuyên).
2. **Penetration Task Graph (PTG)**: model task + dependency dưới dạng DAG, chạy theo topology, có Check & Reflection để retry.
3. **4 module**: Planner (generate next task từ PTG), Generator (sinh tool command), Summarizer (truyền context giữa phase), Executor (chạy command thực).
4. **3 mode**: automatic / semi-automatic / human-involved (paper eval chỉ automatic).
5. **Open-source LLM focus**: Llama3.3-70B, Llama3.1-405B, DeepSeek-V3 — tránh phụ thuộc GPT-4.

## Kiến trúc khác biệt

- PTG tương tự PTT của PentestGPT nhưng là **DAG** (cho phép parallel branch & dependency rõ ràng), trong khi PTT là tree.
- **Summarizer** nằm giữa các phase → giảm context loss khi chuyển recon → exploit (chính là gap PentestGPT thừa nhận trong sec 5.7).
- **Generative penetration behavior** + tool-specific command translation (gần với MAPTA `run_command`).

## Benchmark & kết quả

- **AUTOPENBENCH** (33 task, in-vitro + real CVE)
- **AI-Pentest-Benchmark** (13 real Vulnhub machine)
- VulnBot-Llama3.1-405B: **30.3% overall, 69.05% subtask** trên AUTOPENBENCH (vs Llama3.1-405B trần 9.09%, GPT-4o trần 21.21%).
- Với RAG: end-to-end thành công 1 số real-world machine mà GPT-4o + Llama3.1-405B không làm được khi không có HITL.

## Failure modes (Table 1, paper)

220 trial fail, breakdown:
- **Session context loss**: 42.36% (vẫn là cause #1, giống PentestGPT)
- Failed tool: 19.7%
- Failed command param: 19.21%
- False output interpretation: 8.87%
- Deadlock: 5.42%

## Limitations (Sec 8 + Discussion)

- Vẫn fail blind/long-chain task (paper không nhấn mạnh con số)
- Bị giới hạn capability LLM open-source
- Privilege escalation yếu trên hard machine
- Reflection chỉ là retry trong phase, không có inter-phase strategy revision (đây là gap mà Red-MIRROR's Inter-reflection lấp)

## Vì sao Red-MIRROR đập VulnBot 86% vs 6%?

Red-MIRROR sec 4 chạy VulnBot trên DeepSeek-V3.2 backbone (cùng) và VulnBot chỉ đạt 6% XBOW. Lý do (theo Red-MIRROR critique):
1. PTG không có persistent shared memory — context vẫn fragment qua phase boundary.
2. Reflection chỉ local trong Executor, không có self-consistency vote như Inter-reflection của Red-MIRROR.
3. Tool integration tổng quát, chưa specialized cho web (XSS fuzz, JWT, IDOR module riêng — Red-MIRROR có).

## Idea cho DACN

- VulnBot là baseline yếu nhất trong 3 baseline → **không cần đua**, chỉ ghi nhận.
- Nhưng **PTG DAG** là idea tốt: cho phép parallel branch và prerequisite checking — Red-MIRROR dùng "Penetration Path Planning DAG" của Planner cũng theo idea tương tự.
- DACN có thể **kế thừa PTG idea** + thêm "salience-weighted memory" (vs SRMM recency-only) để giải quyết failure mode #1 (session context loss) tốt hơn.
