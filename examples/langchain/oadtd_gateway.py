"""Minimal OADTD inline-gateway client — gate an agent tool call before it runs.

Pure Python standard library (no third-party dependencies) so it can be embedded
in any agent framework. The companion ``langchain_guard.py`` builds a LangChain
guard on top of this; this module is what actually talks to OADTD and is fully
usable (and testable) on its own.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Optional

ALLOW = "allow"
REQUIRE_APPROVAL = "require_approval"
DENY = "deny"


class ToolBlocked(Exception):
    """Raised when OADTD does not allow a tool call."""

    def __init__(self, verdict: str, reason: str) -> None:
        self.verdict = verdict
        self.reason = reason
        super().__init__(f"OADTD blocked tool call ({verdict}): {reason}")


@dataclass
class Decision:
    verdict: str
    reason: str
    risk: str = ""


class OADTDGateway:
    """Calls the OADTD inline gateway's read-only decide endpoint."""

    def __init__(
        self,
        url: str = "http://127.0.0.1:8080",
        token: Optional[str] = None,
        actor: str = "langchain-agent",
        asset_id: str = "langchain-agent",
        agent_id: Optional[str] = None,
        agent_token: Optional[str] = None,
        timeout: float = 15.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.actor = actor
        self.asset_id = asset_id
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.timeout = timeout

    def decide(self, tool_name: str, command: str = "", arguments: str = "", destination: str = "") -> Decision:
        payload = {
            "asset_id": self.asset_id,
            "actor": self.actor,
            "tool_name": tool_name,
            "command": command,
            "arguments": arguments,
        }
        if destination:
            payload["destination"] = destination
        if self.agent_id:
            payload["agent_id"] = self.agent_id
            payload["agent_token"] = self.agent_token or ""

        request = urllib.request.Request(
            self.url + "/api/gateway/decide",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.token:
            request.add_header("Authorization", "Bearer " + self.token)

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        return Decision(
            verdict=body.get("verdict", ""),
            reason=body.get("reason", ""),
            risk=body.get("risk", ""),
        )

    def enforce(
        self,
        tool_name: str,
        command: str = "",
        arguments: str = "",
        destination: str = "",
        allow_on_approval: bool = False,
    ) -> Decision:
        """Return the decision if the call may proceed, else raise ToolBlocked.

        ``allow_on_approval`` lets require_approval calls through (useful when a
        human-in-the-loop reviews them elsewhere); by default they are blocked.
        """
        decision = self.decide(tool_name, command=command, arguments=arguments, destination=destination)
        if decision.verdict == ALLOW:
            return decision
        if decision.verdict == REQUIRE_APPROVAL and allow_on_approval:
            return decision
        raise ToolBlocked(decision.verdict, decision.reason)
