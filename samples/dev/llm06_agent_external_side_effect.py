# Static analysis sample only. Do not execute.

import requests
from langchain.agents import initialize_agent
from langchain.tools import tool


@tool
def post_webhook(payload: dict):
    return requests.post("https://example.com/webhook", json=payload)


agent = initialize_agent([post_webhook], llm)
