# Chương 4 — Đánh giá

## 4.1 Tập kiểm thử

- **Scaffold fixtures** (3 challenge, offline): IDOR, SSRF, SQLi. Mỗi challenge gồm manifest.json + HTTP transcript + source snapshot + ground_truth.
- **Planned expansion** (Sprint 9): HTB lab subset + Vulhub (8 CVE, giống Red-MIRROR) + XBOW subset (per MAPTA). Kèm allowlist scope cho các fixture động.

## 4.2 Ablation matrix

Sprint 8 đã cài đặt runner `engine/ablation.py` so sánh 5 cấu hình:

| Config | C1 | C2 | C3 |
|---|---|---|---|
| `baseline` | off | off | off |
| `C2_only` | off | **on** | off |
| `C3_only` | off | off | **on** |
| `C1_only` | **on** | off | off |
| `all` | **on** | **on** | **on** |

### 4.2.1 Kết quả trên 3 fixture scaffold (offline, scripted chat model)

Output của `vapt-safe ablation` (trên outputs/ablation):

| config | runs | validated | tool_calls | loops | watchdog | KG tok | RAG tok |
|---|---|---|---|---|---|---|---|
| `baseline` | 3 | 2 | 18 | 0 | 0 | 0 | 0 |
| `C2_only` | 3 | 2 | 18 | 0 | 0 | 0 | 0 |
| `C3_only` | 3 | 2 | 18 | 0 | 0 | 196 | 0 |
| `C1_only` | 3 | 2 | 18 | 0 | 0 | 0 | 0 |
| `all` | 3 | 2 | 18 | 0 | 0 | 196 | 0 |

**Kết luận sơ bộ**: trên fixture offline (LLM được script đi đúng đường), các đóng góp không thay đổi số bug tìm thấy — điều này là kỳ vọng vì script không có loop / không có drift / không có scope violation. C3 chỉ thêm 196 token KG (cao hơn 0 của baseline nhưng vẫn rất nhỏ so với chunks RAG ước tính tương đương).

### 4.2.2 Chờ eval thật với LLM thật

Khi chuyển sang backbone thật (Ollama gemma4:e2b hoặc OpenRouter gemma-27b), kỳ vọng là:

- `C2_only` sẽ giảm `tool_calls` và `steps` trên các fixture mà LLM nhỏ bị stuck (Red-MIRROR báo cáo infinite loop ở blind SQLi / framework-specific).
- `C1_only` sẽ giảm token tiêu thụ mid-stream trên fixture mà LLM drift.
- `C3_only` sẽ giảm `approx_tokens` retrieval 10–20×.
- `all` sẽ vượt baseline về success-rate trên fixture HTB khó.

Các số liệu cụ thể sẽ được bổ sung sau Sprint 9.

## 4.3 So sánh với baseline paper

**Dự kiến** (chưa đo):

| Hệ thống | Backbone | Tập kiểm thử | Success |
|---|---|---|---|
| VulnBot | Qwen2.5-7B | XBOW | 6% |
| AutoPT | — | XBOW | 46% |
| PentestAgent | — | XBOW | 50% |
| MAPTA | GPT-5 | XBOW | 76.9% |
| Red-MIRROR | Qwen2.5-14B-LoRA | XBOW | 86% |
| **DACN (target)** | gemma4:e2b | XBOW subset | **≥ 80% của claude-sonnet-4.5 baseline** |

## 4.4 Metric bổ sung

- **Token cost per run** — từ `budget.to_dict()` trong `run_summary.json`.
- **Wall-clock** — `wall_ms` trong ablation row.
- **Loop intervention count** — `bb.events['loop_detected']` count, C2 dashboard.
- **Watchdog trip count per type** — drift / scope / loop separate, C1 dashboard.
- **KG vs RAG token ratio** — metric chứng minh C3 (đã có unit test `test_kg_is_cheaper_than_rag_for_same_question`).

## 4.5 Reproducibility

Toàn bộ ablation offline có thể reproduce bằng:

```bash
vapt-safe ablation \
  --fixtures-dir data/fixtures \
  --outputs-root outputs/ablation
```

Output JSON + MD deterministic vì chat model được script.

Cho ablation với LLM thật: wire `chat_model_factory` programmatic API của `run_ablation` với `build_chat_model("ollama:gemma4:e2b")` hoặc `build_chat_model("anthropic:claude-sonnet-4-5")`. CLI cho đường đó sẽ thêm ở Sprint 9.

> **Trạng thái chương này**: DRAFT. Bảng §4.2.1 đã có số thật từ scripted run; §4.2.2 + §4.3 chờ Sprint 9.
