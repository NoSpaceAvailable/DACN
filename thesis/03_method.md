# Chương 3 — Phương pháp

## 3.1 Tổng quan kiến trúc

DACN chia thành **4 tầng** (xem `notes/architecture-v2.md` để có sơ đồ đầy đủ):

```
Input (fixture: manifest + transcript + source + oracle)
 └── Orchestration: Dispatcher (LLM supervisor) + Blackboard (shared mem) + ModelSelector
       └── Agent: Recon / Signature / Analyst / Exploit / Validator / Report
             └── Tool: invoke_* (agent wrappers) + Nmap/Curl/HttpProbe + RunPythonSandbox
                   └── RAG: KG (Neo4j / InMemory) + Vector (CompressedRAG)
Output: report.md + report.json + memory.json + run_summary.json
```

Thành phần đã được cài đặt trong mã nguồn:

| File | Trách nhiệm |
|---|---|
| `engine/dispatcher.py` | Tool-use loop, streaming, watchdog hook |
| `engine/anti_loop.py` | **C2** — LoopGuard + AntiLoopHook |
| `engine/watchdogs.py` | **C1** — DriftWatchdog / ScopeWatchdog / LoopWatchdog |
| `engine/dispatcher_runner.py` | Intake + agent-invoker tools + security tools + KG + hooks |
| `kg/` | **C3** — InMemoryKG, Neo4jKG, schema, default corpus |
| `tools/agent_tools.py` | invoke_recon / _signature / _analyst / _exploit / _report / pivot |
| `tools/security/` | NmapTool / CurlTool / HttpProbeTool (scope-gated) |
| `tools/sandbox_exec.py` | RunPythonInSandboxTool |
| `sandbox/docker_sandbox.py` | Ephemeral container runtime |
| `utils/scope.py` | ScopeGuard (deny-by-default allowlist) |

## 3.2 Dispatcher (Claude-CLI style)

Dispatcher là một LLM có bound tools. Mỗi vòng lặp:

1. Nếu có `pending_correction` (watchdog đã trip): tiêm HumanMessage vào `messages`.
2. Gọi LLM. Nếu có `watchdogs` + model hỗ trợ stream → chạy ở chế độ streaming.
3. Nếu không có `tool_calls` → kết thúc, trả về `final_text`.
4. Với mỗi tool call: lookup tool, `invoke(args)`, append ToolMessage.
5. `pivot` là sentinel tool: reset loop signatures + log event.

## 3.3 C1 — Mid-thinking intervention

Đóng góp gốc của đồ án. Pseudocode:

```python
stream = chat_model.stream(messages)
buffer = ""
for chunk in stream:
    buffer += chunk.content
    for wd in watchdogs:
        v = wd.check(buffer)
        if v.tripped:
            log_event(wd.name, v.reason)
            pending_correction = v.correction_for_next_turn
            return AIMessage(content="[intervened:...]"), intervened=True
return final_response, intervened=False
```

Ba watchdog ship:

- **DriftWatchdog** (`engine/watchdogs.py`) — buffer vượt `max_drift_chars` không đề cập keyword focus → trip. Correction: "Re-centre, nêu target + attack family rồi gọi tool".
- **ScopeWatchdog** — regex tìm URL trong buffer, kiểm tra qua `ScopeGuard`. Correction: "URL ngoài scope, quay lại target khai báo".
- **LoopWatchdog** — phát hiện pattern `"name":"...","args":...` khớp tool đã loop threshold. Correction: "Gọi pivot, đừng lặp".

## 3.4 C2 — Anti-loop guard

Mỗi tool đẩy signature `hash(tool_name, kwargs)` vào `Blackboard.loop_signatures` (deque bounded 32). Sau mỗi step, `LoopGuard.check()` đếm: nếu một signature xuất hiện ≥ 3 lần → `AntiLoopHook` tiêm HumanMessage "pivot" + reset buffer. `max_trips=4` bảo vệ chống wedge.

Ưu điểm so với Red-MIRROR Inter-reflection: **không phụ thuộc CoT**, hoạt động như nhau trên mọi backbone.

## 3.5 C3 — Knowledge-graph RAG

Schema chính:

- Nodes: `CVE`, `Framework`, `Sink`, `Source`, `Payload`, `Endpoint`, `Parameter`, `CWE`.
- Edges: `AFFECTS`, `CLASSIFIED_AS`, `EXPLOITS`, `TARGETS`, `HAS_PARAM`, `FLOWS_TO`, `READS`, `RUNS_ON`.

Hai triển khai cùng Protocol:

- `InMemoryKG` — dict-of-dict, thread-safe, cho dev/test.
- `Neo4jKG` — parameterised Cypher, label validation, schema bootstrapped qua `infra/neo4j/init/001_schema.cypher`.

`QueryKGTool` trả về triple text dạng `Payload:x -[TARGETS]-> Sink:y` — đơn vị 50–200 token cho câu trả lời đầy đủ thay vì 1000+ token chunks thô của `QueryRAGTool`.

## 3.6 Trừu tượng hoá LLM backend (LangChain)

`llm/backend_factory.py` parse spec `provider:model` (ollama / openai / anthropic / openrouter / custom → `ChatOpenAI(base_url=...)`) và build đúng `BaseChatModel`. Per-role override qua `LLM_BACKEND_<ROLE>`, default `LLM_BACKEND_DEFAULT`. Chuyển backend chỉ cần thay 1 env var — không đụng code.

## 3.7 Safety & Scope

- `ScopeGuard` deny-by-default; tools như Nmap/Curl/HttpProbe bắt buộc check host/port/URL trước khi shell out.
- `DockerSandbox`: `--rm --network=none --read-only --tmpfs --cpus 0.5 --memory 256m --pids-limit 64 --security-opt no-new-privileges:true`.
- `utils/safety.py`: path traversal guard cho file I/O.

> **Trạng thái chương này**: DRAFT. Sẽ bổ sung hình minh hoạ + trace output khi Sprint 9 có demo video.
