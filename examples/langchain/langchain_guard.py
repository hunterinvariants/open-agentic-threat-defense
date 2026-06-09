"""Gate LangChain tool calls through the OADTD inline gateway.

Each guarded tool consults OADTD before it runs: a denied or approval-required
call raises ToolBlocked instead of executing, so a compromised or misled agent
cannot reach a dangerous tool.

    from langchain_core.tools import Tool
    from oadtd_gateway import OADTDGateway
    from langchain_guard import guard_tool

    gateway = OADTDGateway(url="http://127.0.0.1:8080", token="...")
    tools = [guard_tool(t, gateway) for t in raw_tools]
    # ... build your AgentExecutor with `tools` ...
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import BaseTool, Tool

from oadtd_gateway import OADTDGateway


def guard_tool(tool: BaseTool, gateway: OADTDGateway, allow_on_approval: bool = False) -> Tool:
    """Wrap a LangChain tool so OADTD gates every invocation before it runs.

    The gate is in the execution path (not a best-effort callback), so a blocked
    call never reaches the underlying tool. Single-input tools work as-is;
    structured tools should be wrapped with the same pattern on a StructuredTool.
    """

    def _guarded(tool_input: Any = "") -> Any:
        command = tool_input if isinstance(tool_input, str) else json.dumps(tool_input, default=str)
        gateway.enforce(tool.name, command=str(command), allow_on_approval=allow_on_approval)
        return tool.run(tool_input)

    return Tool(name=tool.name, description=tool.description, func=_guarded)
