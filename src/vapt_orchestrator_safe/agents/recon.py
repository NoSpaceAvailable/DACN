from __future__ import annotations

import re
from typing import Any, Dict, List

from vapt_orchestrator_safe.agents.base import BaseAgent
from vapt_orchestrator_safe.memory.evidence import EvidenceItem


ROUTE_HINTS = {
    "authorization": ["/api/invoices/", "/api/users/", "/api/orders/"],
    "ssrf": ["preview", "fetch", "webhook", "import", "url"],
    "sqli": ["/login", "search", "query", "id="],
}


class ReconAgent(BaseAgent):
    role = "recon"

    def run(self, transcript: Dict[str, Any], source_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.charge()
        routes = transcript.get("routes", [])
        route_map = [f"{route['method']} {route['path']}" for route in routes]
        auth_surface = any("auth" in obs.lower() or "token" in obs.lower() for obs in transcript.get("observations", []))
        parameters: List[str] = []
        endpoints_text = " ".join(route_map).lower()
        if "url" in endpoints_text or "url" in str(transcript).lower():
            parameters.append("url")
        if any("invoice" in item.lower() for item in route_map):
            parameters.append("invoice_id")
        if any("login" in item.lower() for item in route_map):
            parameters.extend(["username", "password"])

        source_indicators: List[str] = []
        for source in source_files:
            content = source["content"]
            if re.search(r"SELECT.+\{.+\}", content, re.IGNORECASE | re.DOTALL):
                source_indicators.append("unsafe_sql_formatting")
            if "requests.get(url" in content or "fetch(url" in content:
                source_indicators.append("server_side_fetch_of_user_url")
            if "owner_id" in content and "check" not in content.lower():
                source_indicators.append("missing_ownership_check")

        discovered = {
            "route_map": route_map,
            "parameters": sorted(set(parameters)),
            "auth_surface": auth_surface,
            "source_indicators": sorted(set(source_indicators)),
        }
        self.deps.memory.add_evidence(
            EvidenceItem(
                evidence_id="recon-surface",
                phase="recon",
                summary=f"Discovered {len(route_map)} routes, parameters {', '.join(discovered['parameters']) or 'none'}, and {len(discovered['source_indicators'])} source indicators.",
                details=discovered,
                tags=["recon", "surface"],
            )
        )
        self.log("Recon complete", discovered)
        return discovered
