# Nghiên cứu cơ chế điều phối và quản lý đa tác tử trong kiểm thử xâm nhập ứng dụng web

*A study on multi-agent orchestration and management for web application penetration testing*

**Đồ án chuyên ngành — NT114.Q21.ANTN — Học kỳ 2, Năm học 2025–2026**
Trường Đại học Công nghệ Thông tin, ĐHQG-HCM — Khoa Mạng máy tính và Truyền thông

| Sinh viên thực hiện | MSSV |
|---|---|
| Lê Quốc Cường | 23520197 |
| Ngô Phúc Dương | 23520350 |

**Giảng viên hướng dẫn:** ThS. Nghi Hoàng Khoa

---

## 1. Giới thiệu

Đề tài xây dựng một **hệ thống đa tác tử (multi-agent) dùng mô hình ngôn ngữ lớn (LLM)** để tự động hoá kiểm thử xâm nhập ứng dụng web. Trung tâm hệ thống là một **Bộ điều phối (Dispatcher)** điều khiển bằng LLM theo phong cách tool-use (giống Claude Code / Codex CLI), phối hợp các tác tử chuyên biệt và các công cụ qua một **bộ nhớ chia sẻ (Blackboard)**.

Hệ thống đề xuất **ba đóng góp nguyên gốc** nhằm khắc phục điểm yếu chung của PentestGPT, Red-MIRROR, MAPTA:

- **C1 — Can thiệp giữa lúc suy luận (mid-thinking intervention):** giám sát luồng token theo thời gian thực và cắt sớm khi LLM đi lệch hướng / vượt phạm vi / sắp lặp, thay vì chờ sinh xong câu trả lời.
- **C2 — Bộ chống lặp (anti-loop guard):** phát hiện lặp dựa trên chữ ký cấu trúc của lời gọi công cụ và buộc đổi hướng tấn công (pivot), không phụ thuộc khả năng phản tư của LLM.
- **C3 — Truy xuất tri thức bằng đồ thị (KG-RAG):** trả về các bộ ba có cấu trúc thay cho đoạn văn thô, tiết kiệm token đáng kể khi hỏi về họ tấn công / framework / sink.

## 2. Kiến trúc bốn tầng

```
Input: fixture (manifest + transcript HTTP + source + oracle)  hoặc  instance Docker sống
  └── Tầng Điều phối : Dispatcher (LLM) + Blackboard + Model Selector
        └── Tầng Tác tử : Recon / Signature / Analyst / Exploit / Validator / Report
              └── Tầng Công cụ : read_source, record_finding, submit_flag,
                                  query_cve / query_ghsa / query_nuclei (tra CVE trực tuyến),
                                  nmap / curl / http_probe, sandbox Docker
                    └── Tầng Tri thức : query_kg (đồ thị) + query_rag (văn bản nén)
Output: report.md, run_summary.json (detected / solved), memory.json
```

**Tầng tri thức** được xây dựng tự động: chưng cất 172 trang **HackTricks** thành 741 bản ghi có cấu trúc → đồ thị ~3.000 node / 6.500 cạnh (23 lớp lỗ hổng), bổ sung tra cứu **NVD / GitHub Advisory / Nuclei / Exploit-DB** trực tuyến cho tri thức theo phiên bản thành phần.

Toàn bộ tầng LLM được trừu tượng hoá — đổi nhà cung cấp (Ollama, OpenAI, Anthropic, Mistral, Google Gemini, DeepSeek, Groq…) chỉ qua biến môi trường, không sửa mã.

## 3. Hai chế độ chạy

- **Detection (phân tích tĩnh):** đọc mã nguồn/transcript, phát hiện và phân loại lỗ hổng.
- **Live exploit (`--live`):** tự khởi chạy container thử thách qua Docker, khai thác instance sống và **lấy flag** (metric solve-rate, so sánh trực tiếp với benchmark).

## 4. Cài đặt

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements.txt
```

## 5. Chạy thử

```bash
# Phát hiện lỗ hổng trên một fixture (Mistral đọc key từ .env)
python scripts/bench_api_local.py --provider mistral --model mistral-medium-latest \
    --fixtures web-019 --configs all --require-source-read

# Chế độ khai thác trực tiếp (boot Docker → khai thác → lấy flag)
python scripts/bench_api_local.py --provider mistral --model mistral-medium-latest \
    --fixtures live_no_pass_needed --configs all --live

# Kiểm tra quota các provider
python scripts/check_quota.py

# Thống kê detection rate + khoảng tin cậy Wilson 95% + z-test
python scripts/bench_stats.py

# Bọc challenge NYU CTF Bench thành fixture live-exploit
python scripts/wrap_nyuctf_live.py --limit 10
```

Cấu hình khoá API đặt trong `.env` (xem `.env.example`) — file này **không** được commit.

## 6. Kết quả tóm tắt

Trên 20 fixture web (nguồn NYU CTF Bench / CSAW Quals) × 8 mô hình × 5 cấu hình ablation:

- Cấu hình dispatcher tốt nhất đạt **~78% detection rate**, **cạnh tranh được** với hai baseline CLI mã đóng: `gpt-5-mini` qua Codex CLI (75%) và `claude-sonnet-4-5` qua Claude CLI (65%).
- Chênh lệch **không có ý nghĩa thống kê** (kiểm định z hai tỉ lệ, khoảng tin cậy Wilson chồng lấn) — xem mục *Threats to Validity* trong báo cáo.
- `gemma-4-31b-it` miễn phí (Google AI Studio) đạt 75% ngang `gpt-5-mini` khi làm dispatcher — cho thấy tiềm năng backbone nhỏ/rẻ.
- Phát hiện đúng các lỗ hổng khó: **HTTP Request Smuggling** (nginx CVE-2019-20372), **SSTI**.

## 7. An toàn và phạm vi

- Hệ thống chạy trong **phòng thí nghiệm cục bộ**; live-exploit chỉ chạy container bind loopback, không mở egress.
- **Không** quét IP/tên miền công khai, **không** phát tán mã khai thác vũ khí hoá.
- Công cụ thực thi được cô lập trong Docker sandbox (`--network=none`, read-only, giới hạn CPU/RAM).

## 8. Cấu trúc mã nguồn

```
src/vapt_orchestrator_safe/
  engine/     dispatcher, dispatcher_runner, watchdogs (C1), anti_loop (C2), eval_case, ablation
  agents/     intake, recon, signature, analyst, exploit, validator, report
  tools/      analysis_tools (read_source/record_finding), flag_tools (submit_flag),
              kg_tools (C3), cve_tool/ghsa_tool/nuclei_tool/exploitdb_tool, security/
  kg/         knowledge_graph, in_memory, neo4j_kg        (C3)
  dataset/    cve_entry, seed, distiller                  (chưng cất tri thức)
  sandbox/    live_lab (boot challenge Docker), docker_sandbox
  llm/        backend_factory (đa nhà cung cấp), text_tool_wrapper
scripts/      bench_api_local, bench_stats, wrap_nyuctf_live, distill_hacktricks, check_quota, ...
data/         fixtures/ (thử thách), corpus/ (hacktricks.jsonl), kb/
tests/        (pytest)
```

## 9. Kiểm thử

```bash
python -m pytest -q
```
