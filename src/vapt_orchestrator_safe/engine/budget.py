from __future__ import annotations

import time
from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class BudgetTracker:
    max_tool_calls: int = 40
    max_time_seconds: int = 300
    max_simulated_cost: float = 0.30
    # Token cap thật trên tổng (input + output) qua mọi LLM call trong 1 phiên.
    # 0 = không giới hạn. Đặt cap khi bench thinking model trên API trả tiền
    # để tránh 1 run blow vài đô (Claude high-effort có thể 200k+ tok/phiên).
    max_llm_tokens: int = 0
    tool_calls: int = 0
    simulated_tokens: int = 0
    simulated_cost: float = 0.0
    # Token thật từ LLM provider (LangChain usage_metadata). Khác simulated_*
    # (vốn chỉ là heuristic cho rule-based backend). Dùng cho cost analysis.
    llm_tokens_in: int = 0
    llm_tokens_out: int = 0
    llm_calls: int = 0
    started_at: float = 0.0

    def start(self) -> None:
        self.started_at = time.time()

    def record_tool(self, cost: float, tokens: int) -> None:
        self.tool_calls += 1
        self.simulated_cost += cost
        self.simulated_tokens += tokens

    def record_llm_usage(self, tokens_in: int, tokens_out: int) -> None:
        self.llm_tokens_in += int(tokens_in or 0)
        self.llm_tokens_out += int(tokens_out or 0)
        self.llm_calls += 1

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.time() - self.started_at

    @property
    def llm_tokens_total(self) -> int:
        return self.llm_tokens_in + self.llm_tokens_out

    def limits_exceeded(self) -> bool:
        if (self.max_llm_tokens > 0
                and self.llm_tokens_total > self.max_llm_tokens):
            return True
        return (
            self.tool_calls > self.max_tool_calls
            or self.elapsed_seconds > self.max_time_seconds
            or self.simulated_cost > self.max_simulated_cost
        )

    def to_dict(self) -> Dict[str, float | int]:
        data = asdict(self)
        data["elapsed_seconds"] = round(self.elapsed_seconds, 4)
        return data
