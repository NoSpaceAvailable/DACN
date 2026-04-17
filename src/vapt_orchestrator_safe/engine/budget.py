from __future__ import annotations

import time
from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class BudgetTracker:
    max_tool_calls: int = 40
    max_time_seconds: int = 300
    max_simulated_cost: float = 0.30
    tool_calls: int = 0
    simulated_tokens: int = 0
    simulated_cost: float = 0.0
    started_at: float = 0.0

    def start(self) -> None:
        self.started_at = time.time()

    def record_tool(self, cost: float, tokens: int) -> None:
        self.tool_calls += 1
        self.simulated_cost += cost
        self.simulated_tokens += tokens

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.time() - self.started_at

    def limits_exceeded(self) -> bool:
        return (
            self.tool_calls > self.max_tool_calls
            or self.elapsed_seconds > self.max_time_seconds
            or self.simulated_cost > self.max_simulated_cost
        )

    def to_dict(self) -> Dict[str, float | int]:
        data = asdict(self)
        data["elapsed_seconds"] = round(self.elapsed_seconds, 4)
        return data
