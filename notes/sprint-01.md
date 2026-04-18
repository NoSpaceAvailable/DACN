# Sprint 1 — Tuần 2026-04-19 → 2026-04-25

**Mục tiêu:** demo cho thầy 1 pentest run end-to-end với LLM thật (Ollama) trên 1 XBOW challenge thật. Cụ thể:
- VPS Ollama secured + reachable.
- Scaffold `vapt-safe` gọi được LLM thật (không còn `RuleBasedModel`).
- Recon agent thực sự dùng LLM phân tích target.
- 1 fixture XBOW thật chạy thông pipeline.

**Constraint:** model max 8B Q4 trên VPS, không có API budget, đang trong Phase 0→1.

---

## D1 (Thứ 2) — Security setup VPS  ✅ DONE 2026-04-18

### Output
- ✅ `infra/vps-setup.sh` (idempotent, viết xong, chưa chạy trên VPS)
- ✅ `infra/README.md` (usage doc)
- ⏳ User cần chạy script trên VPS với token tự sinh, sau đó smoke test `curl` từ máy local

### Step-by-step

```bash
# Trên VPS:
sudo systemctl edit ollama.service   # Add Environment="OLLAMA_HOST=127.0.0.1:11434"
sudo systemctl restart ollama

sudo apt install -y caddy
# /etc/caddy/Caddyfile (example):
#   :80 {
#       @auth header Authorization "Bearer ollama_dacn_2026_xxx"
#       reverse_proxy @auth localhost:11434
#       respond 401
#   }
sudo systemctl reload caddy

sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw deny 11434
sudo ufw enable
```

Lưu token vào `.env.local` (không commit).

**Risk:** HTTP plaintext → bearer token có thể bị sniff. Acceptable cho dev DACN nội bộ; production sau cần TLS.

---

## D2 (Thứ 3) — `OllamaModel` adapter + CLI flag  ✅ DONE 2026-04-18

### Output
- ✅ `src/vapt_orchestrator_safe/llm/ollama_model.py` — adapter (summarize/generate/chat/list_tags + clear errors)
- ✅ `src/vapt_orchestrator_safe/llm/registry.py` — factory `parse_backend()` + `OllamaConfig`
- ✅ `src/vapt_orchestrator_safe/engine/orchestrator.py` — pass backend through, label trong run summary
- ✅ `src/vapt_orchestrator_safe/cli.py` — `--llm` flag + new `llm-test` subcommand
- ✅ `src/vapt_orchestrator_safe/config.py` — `get_ollama_env()` + .env/.env.local loader
- ✅ `requirements.txt` — `requests>=2.31`
- ✅ `.env.example` — OLLAMA_BASE_URL/OLLAMA_TOKEN/OLLAMA_TIMEOUT
- ✅ `tests/test_ollama_model.py` — 16 test mới (parse_backend, registry, generate, summarize, headers, 401/404/5xx, timeout, list_tags, chat) — all mocked
- ✅ `Makefile` — thêm `run-ollama`, `llm-test` target

### Verification log (2026-04-18)
- `pytest -q` → **18 passed** (16 mới + 2 cũ).
- `vapt-safe run --llm rule` → status `validated`, backend label `rule`.
- `vapt-safe run --llm ollama:gemma4:e2b` (no env) → fail clean với message guide setup.
- `vapt-safe llm-test --llm ollama:gemma4:e2b` (env trỏ test IP) → fail clean với ConnectTimeoutError, không crash.

### Acceptance đã đạt
- Adapter API stable: `summarize()` (BaseModel contract) + `generate()` (structured response với token counts) + `chat()` + `list_tags()`.
- Errors clear: 401, 404 (mention model name), 5xx, timeout (mention OLLAMA_TIMEOUT), non-JSON, connect failure.
- Sau khi chạy `infra/vps-setup.sh` trên VPS + set env, command sau sẽ work end-to-end:
  ```
  make llm-test           # smoke test connectivity
  make run-ollama         # chạy 1 fixture qua Ollama (chỉ summarize() — agents D3 mới gọi thực sự)
  ```

---

## D3 (Thứ 4) — LLM-driven Recon agent

### Output
- Update: `src/vapt_orchestrator_safe/agents/recon.py` thay regex bằng LLM call.
- Mới: `src/vapt_orchestrator_safe/prompts/recon.md` (prompt template).
- Mới: structured output schema (JSON) cho recon result.

### Spec prompt

```
You are a reconnaissance agent for web pentesting.

INPUT:
- HTTP transcript (routes, observations): {transcript}
- Source files (snippets): {source_files}

OUTPUT (JSON only, no prose):
{
  "endpoints": [{"method": "...", "path": "...", "params": [...]}],
  "auth_surface": "session" | "bearer" | "none" | "...",
  "stack_fingerprint": "...",
  "suspicious_patterns": [
    {"pattern": "unsafe_sql_formatting", "evidence": "...", "file": "..."}
  ],
  "next_recon_actions": ["enumerate /api/v1/*", "..."]
}
```

Acceptance:
- Model trả về JSON parse được trên 3 fixture cũ.
- Output có thông tin meaningful (không phải hallucinate route không tồn tại).
- Diff nhau giữa 3 fixture (không cùng template).

---

## D4 (Thứ 5) — Pull XBOW Docker fixture

### Output
- Mới: `data/fixtures/xbow_*` (3-5 challenge import từ XBOW)
- Script: `scripts/import_xbow.sh` (clone XBOW + apply MAPTA fix PR + chọn 3-5 easy challenge)
- Mỗi fixture có `manifest.json`, `ground_truth.json`, source nếu cần (hoặc chỉ URL container)

### Lưu ý
- XBOW có 104 challenge. Chọn 3-5 dễ trước: SSRF basic, IDOR basic, SQLi error-based.
- Cần Docker trên máy dev (local Windows + WSL2/Docker Desktop, hoặc trên VPS).
- Lưu Docker image hash để reproducible.

### Reference
- XBOW repo: https://github.com/xbow-engineering/validation-benchmarks
- MAPTA fix PR (43/104 outdated): xem `notes/papers/03_mapta.md` Sec 3 — có link

---

## D5 (Thứ 6) — Full pipeline smoke test trên XBOW + viết weekly note

### Output
- Run `vapt-safe run --fixture data/fixtures/xbow_idor_01 --llm ollama:gemma4:e2b` thành công (status có thể `supported` hoặc `verified`, không cần SOTA).
- Capture toàn bộ run output: `outputs/xbow_idor_01_*/memory.json` + `report.md` + `run_summary.json`.
- Viết `reports/sprint-01-results.md` ghi lại:
  - Cái gì work, cái gì không
  - Tốc độ thực tế (token/s)
  - Hallucination case quan sát được
  - Cost (số request, tổng thời gian)
  - Hình screenshot terminal cho thầy

---

## Backlog (nếu xong sớm)

- D6: Thử model lớn hơn (`qwen2.5:7b` hoặc `llama3.1:8b`) so với gemma4:e2b → so chất lượng.
- D7: Bắt đầu thay agent thứ 2 (Analyst) hoặc set up LlamaIndex skeleton cho Phase 3.

## Risk register

| Risk | Mitigation |
|---|---|
| VPS không stable, latency cao | Test 3 lần D2; nếu lỗi → fallback test trên local Ollama của bạn (nếu có) |
| `gemma4:e2b` output JSON kém (model nhỏ) | Switch sang `qwen2.5:7b` dù chậm hơn; nếu vẫn kém → dùng output free-text + parse heuristic |
| XBOW Docker fix chưa merge | Tự fork và apply patch tay (max 1-2 challenge cần fix) |
| Setup Caddy không thông | Fallback: nginx + auth_basic; hoặc tạm bind 0.0.0.0 + ufw allow chỉ IP của bạn |
| Hết tuần không xong D5 | Trượt D5 sang D6 cuối tuần — vẫn báo cáo được Sprint 1 partial |

## Next: Sprint 2 (D8-D12, tuần sau)

- Replace Analyst + Exploit agent với LLM
- Bắt đầu thiết kế tool registry abstraction (chuẩn bị Phase 2)
- Bổ sung 5 fixture XBOW nữa
- Đo baseline: SR & SCR của pipeline LLM-driven (chưa có B-Tools / FA-RAG / DO-Val) trên 8-10 fixture XBOW
