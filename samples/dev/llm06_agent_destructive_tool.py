# Static analysis sample only. Do not execute.

import os
from langchain.agents import initialize_agent
from langchain.tools import tool


@tool
def run_shell(command: str):
    return os.system(command)


agent = initialize_agent([run_shell], llm)
