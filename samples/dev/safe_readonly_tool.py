# Static analysis sample only. Do not execute.

from langchain.agents import initialize_agent
from langchain.tools import tool


@tool
def lookup_policy(topic: str):
    return f"Policy summary for {topic}"


agent = initialize_agent([lookup_policy], llm)
