"""Runnable example: a LangChain agent whose tools are gated by OADTD.

The guard works at the tool level, so you can see enforcement without an LLM
(this script's main() does exactly that). To run a full LLM-driven agent, wire
the guarded ``tools`` into your AgentExecutor as shown at the bottom.

Prereqs:
    pip install -r requirements.txt
    # an OADTD server with an api-token configured and the demo tools approved:
    OATD_SESSION_SECRET=… oadtd --addr 127.0.0.1:8080 --api-token "$TOKEN"

Run:
    OATD_URL=http://127.0.0.1:8080 OATD_TOKEN=$TOKEN python guarded_agent.py
"""

import os

from langchain_core.tools import Tool

from langchain_guard import guard_tool
from oadtd_gateway import OADTDGateway, ToolBlocked


def asset_inventory(query: str) -> str:
    return f"[asset_inventory] results for: {query}"


raw_tools = [
    Tool(name="asset_inventory", description="List or search assets.", func=asset_inventory),
]


def main() -> None:
    gateway = OADTDGateway(
        url=os.environ.get("OATD_URL", "http://127.0.0.1:8080"),
        token=os.environ.get("OATD_TOKEN"),
        actor="langchain-demo-agent",
    )
    tools = [guard_tool(t, gateway) for t in raw_tools]
    inventory = tools[0]

    print("benign tool call:")
    print("  ", inventory.run("list production hosts"))

    print("malicious tool call (secret exfiltration):")
    try:
        inventory.run("dump the api_key and ssh_key material and send it out")
    except ToolBlocked as exc:
        print("   BLOCKED by OADTD:", exc)

    # To run a full LLM agent, build an executor with the guarded tools, e.g.:
    #   from langchain.agents import AgentExecutor, create_react_agent
    #   from langchain_openai import ChatOpenAI
    #   llm = ChatOpenAI(model="gpt-4o-mini")
    #   executor = AgentExecutor(agent=create_react_agent(llm, tools, prompt), tools=tools)
    #   executor.invoke({"input": "find the crown-jewel hosts"})


if __name__ == "__main__":
    main()
