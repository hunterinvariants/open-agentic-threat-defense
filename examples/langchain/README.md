# LangChain × OADTD — gated agent tools

A reference integration that routes a real third-party agent framework's tool
calls through the OADTD inline gateway. Every tool invocation is checked
**before it runs**: a denied or approval-required call raises `ToolBlocked`
instead of executing, so a compromised or prompt-injected agent cannot reach a
dangerous tool.

## Files

- **`oadtd_gateway.py`** — the gate client. Pure standard library, no
  dependencies. `decide()` returns the verdict; `enforce()` raises unless the
  call is allowed. Usable from any framework, not just LangChain.
- **`langchain_guard.py`** — `guard_tool(tool, gateway)` wraps a LangChain tool
  so the gate sits in its execution path.
- **`guarded_agent.py`** — a runnable example. Its `main()` shows enforcement at
  the tool level (no LLM needed) and documents how to wire the guarded tools into
  a full `AgentExecutor`.
- **`test_oadtd_gateway.py`** — standard-library tests of the client against a
  stub (no LangChain, no LLM, no OADTD binary).

## Verify the client (no dependencies)

```bash
python -m unittest test_oadtd_gateway
```

## Run against a live OADTD gateway

```bash
# 1) an OADTD server with an api-token and the demo tools approved
OATD_SESSION_SECRET=demo oadtd --addr 127.0.0.1:8080 --api-token "$TOKEN" &

# 2) the example (enforcement is visible without an LLM)
pip install -r requirements.txt
OATD_URL=http://127.0.0.1:8080 OATD_TOKEN=$TOKEN python guarded_agent.py
```

Expected: the benign call runs; the secret-exfiltration call is `BLOCKED by
OADTD`.

## Wire into your own agent

```python
from langchain_core.tools import Tool
from oadtd_gateway import OADTDGateway
from langchain_guard import guard_tool

gateway = OADTDGateway(url="http://127.0.0.1:8080", token="…",
                       actor="my-agent", agent_id="my-agent", agent_token="…")
tools = [guard_tool(t, gateway) for t in raw_tools]
# build your AgentExecutor with `tools`
```

Set `agent_id` / `agent_token` to a registered agent identity if your deployment
enforces `agent_identities`. Use `allow_on_approval=True` if a human-in-the-loop
reviews require-approval calls elsewhere.
