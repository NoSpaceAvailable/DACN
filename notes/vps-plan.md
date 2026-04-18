# VPS plan — Ollama @ 157.245.195.74

## Spec hiện tại

| Resource | Value | Note |
|---|---|---|
| CPU | 4 vCPU Xeon Platinum 8168 @ 2.7 GHz | AVX-512 ✓ (tốt cho ggml/llama.cpp) |
| RAM | 7.8 GiB | Không có swap |
| GPU | Không | CPU-only inference |
| OS | Linux (host: `ollama`) | |
| Provider | Likely DigitalOcean Premium Intel 8GB | ~$48/mo |
| Ollama | Installed | Default port 11434 |
| Models pulled | `gemma4:e2b` (7.2 GB) | |

## Reality check — model nào chạy được

CPU-only + 7 GiB RAM hữu dụng (~6 GiB cho model + 1 GiB OS/buffer):

| Class | Q4_K_M size | Khả năng | Tokens/sec ước lượng | OK cho pipeline? |
|---|---|---|---|---|
| **2B** (Gemma3n E2B) | ~2 GB | ✅ thoải mái | 5-8 tok/s | ✅ dev/test |
| **4B** | ~3 GB | ✅ ổn | 3-5 tok/s | ✅ dev/test |
| **7B** (Mistral, Qwen2.5-7B) | ~5 GB | ✅ vừa | 2-3 tok/s | ⚠️ benchmark chậm |
| **8B** (Llama 3.1) | ~5.5 GB | ✅ chật | 2-3 tok/s | ⚠️ benchmark chậm |
| **14B** (Qwen2.5-14B = Red-MIRROR) | ~9 GB | ❌ OOM | — | ❌ |
| **27B** (Gemma 2/3) | ~16 GB | ❌ | — | ❌ |
| **70B** (Llama 3.3, Red-MIRROR alt) | ~40 GB | ❌ | — | ❌ |
| **DeepSeek-V3.2** (Red-MIRROR primary) | hàng trăm GB | ❌ | — | ❌ |

**Kết luận:** VPS hiện tại đủ cho **dev/test pipeline**, nhưng **không đủ cho benchmark match được Red-MIRROR/MAPTA**.

## Tốc độ ước tính cho 1 pentest run

Giả sử mỗi agent step sinh 300 token, mỗi pentest cần 50 step:
- 8B Q4 tại 2.5 tok/s → 300/2.5 = 120s/step → **100 phút / 1 pentest**
- Benchmark 50 challenge × 4 size variant × 3 ablation = 600 run × 100 phút = **1000 giờ** ≈ 6 tuần liên tục

→ Không khả thi nếu chỉ dùng VPS này cho full benchmark.

## 3 chiến lược (chọn 1)

### A. Self-host all + chấp nhận limit
- Chỉ benchmark trên 2B/4B/8B (drop 14B+).
- Drop ambition match Red-MIRROR 86% — DACN chỉ claim "với model nhỏ, kiến trúc DACN-X cải thiện X% so với baseline cùng size".
- Pros: cost = $48/mo tổng; full reproducible
- Cons: số liệu yếu; không so sánh fair với Red-MIRROR (vì khác backbone)

### B. Hybrid — VPS cho dev + API cho benchmark
- VPS: smoke test, develop prompts, debug agent logic với 2B/4B model (nhanh, free).
- Benchmark final: dùng API
  - **DeepSeek-V3.2** ($0.28/$0.42 per 1M tok, đúng backbone Red-MIRROR → fair comparison)
  - hoặc **Anthropic Claude Sonnet/Haiku** ($3/$15 per 1M Sonnet, $0.80/$4 Haiku)
  - hoặc **Gemini 2.5 Flash** rẻ
- Cost benchmark XBOW theo MAPTA: ~$21 cho 104 challenge với GPT-5; với DeepSeek-V3.2 sẽ ≤$5/run của 104 challenge
- Pros: số liệu đáng tin, fair comparison; cost benchmark nhỏ
- Cons: cần budget API ($20-50 cho full eval)

### C. Upgrade VPS
- Resize droplet lên 16 GB RAM ($96/mo) → chạy được 14B Q4
- Hoặc lên 32 GB ($192/mo) → chạy được 27B Q4
- Hoặc lên GPU droplet (DO có A100/H100 ~$2-3/giờ) → chạy được 70B
- Pros: full control, không cần API
- Cons: cost cao hơn nhiều; tok/s vẫn không cao bằng GPU

**Khuyến nghị: chiến lược B** — thực dụng cho output quality + cost hợp lý.

## Multi-tier model routing (đúng spirit thầy "best-practice model per skill")

Áp dụng `ModelRouter` của scaffold cho heterogeneous backbone:

| Agent | Skill cần | Đề xuất model | Lý do |
|---|---|---|---|
| Coordinator/Planner | Reasoning + planning | DeepSeek-V3.2 API hoặc Claude Sonnet | Long-horizon strategy, vote 3-self-consistency tốn token |
| Recon/Collector | Tool calling + parsing | Gemma 3n E2B local trên VPS | Output có cấu trúc, model nhỏ đủ |
| Signature/Search | Embedding + RAG synthesis | Local embedding (bge-m3) + Gemma 4B local | Embedding không cần lớn |
| Exploit | Code gen + reasoning | DeepSeek-V3.2 API hoặc Qwen2.5-Coder API | Cần coding |
| Validator | Judge/classification | Gemma 4B local | Classification đơn giản |
| Report | Long-form writing | Llama 3.1 8B local | Đủ cho markdown |

→ **Local cho task nhẹ + API cho task nặng** = giảm 60-80% cost so với "all API".

## Security setup cần làm trước khi expose 11434

Ollama default API binding `0.0.0.0:11434` **không có auth**. Bất cứ ai biết IP đều dùng được model.

**Tối thiểu:**
1. **Firewall** chỉ cho IP của bạn / mạng UIT:
   ```
   ufw allow from <your-ip> to any port 11434
   ufw deny 11434
   ```
2. **Reverse proxy + token** (Caddy đơn giản nhất):
   ```caddyfile
   ollama.your-domain.tld {
       @auth header Authorization "Bearer <random-token>"
       reverse_proxy @auth localhost:11434
       respond 401
   }
   ```
3. **Bind Ollama localhost only**: `OLLAMA_HOST=127.0.0.1:11434` trong service file → buộc traffic qua reverse proxy.
4. **Rate limit** + log tất cả request vào file để audit.
5. (Tốt hơn) **TLS** với Let's Encrypt — Caddy auto-cấp.

Lưu ý dual-use risk: VPS này host model có khả năng hỗ trợ pentest. Phải log đủ để chứng minh chỉ dùng cho DACN nếu DigitalOcean abuse team hỏi.

## Action items theo thứ tự

| # | Task | Owner | ETA |
|---|---|---|---|
| 1 | Confirm `gemma4:e2b` là model gì (custom tag hay Gemma3n E2B) — check `ollama show gemma4:e2b` | User | hôm nay |
| 2 | Setup firewall + reverse proxy + token cho 11434 | User | hôm nay/ngày mai |
| 3 | Pull thêm `qwen2.5:7b` hoặc `llama3.1:8b` Q4 (5-6 GB RAM) làm option lớn hơn | User | hôm nay |
| 4 | Quyết định chiến lược A/B/C ở trên — **gợi ý B** | User | tuần này |
| 5 | Nếu chọn B: setup API key (DeepSeek tài khoản, top up $5-10 ban đầu) | User | trước Phase 1 |
| 6 | Test smoke từ máy bạn → VPS bằng `curl` (sau khi token-protect xong): `curl -H "Authorization: Bearer <token>" http://157.245.195.74/api/generate -d '{"model":"gemma4:e2b","prompt":"hello"}'` | User | sau khi #2 done |
| 7 | Phía code: viết `OllamaModel(BaseModel)` adapter trong `src/.../llm/ollama_model.py` | Mình (Phase 1) | M1 tuần 1-2 |

## Câu hỏi cho user

1. `gemma4:e2b` là tag custom của bạn / lab thầy, hay từ official Ollama registry? Output `ollama show gemma4:e2b` để xác minh.
2. Budget cho API có không? (DeepSeek $5-10 đủ cho ~50 benchmark run)
3. VPS có domain gắn vào không (cho TLS), hay chỉ dùng IP?
