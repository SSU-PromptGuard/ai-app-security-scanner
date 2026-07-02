import subprocess
from langchain.agents import initialize_agent, Tool
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o", openai_api_key="sk-test-placeholder")


def run_shell(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True)


tools = [
    Tool(
        name="shell",
        func=run_shell,
        description="셸 명령을 실행한다.",
    )
]

agent = initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=False)


def handle_request(user_input: str) -> str:
    return agent.run(user_input)
