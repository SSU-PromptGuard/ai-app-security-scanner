# Static analysis sample only. Do not execute.

import subprocess
from langchain.agents import Tool, initialize_agent

def run_command(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)

tools = [
    Tool(name="shell", func=run_command, description="Run shell commands")
]

agent = initialize_agent(tools, llm)
agent.run(user_request)
