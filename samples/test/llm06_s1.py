from langchain.agents import initialize_agent, Tool
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o", openai_api_key="sk-test-placeholder")

ALLOWED_ACTIONS = {"list_files", "show_status"}


def safe_action(action: str) -> str:
    if action not in ALLOWED_ACTIONS:
        return f"허용되지 않는 동작: {action}"
    if action == "list_files":
        import os
        return str(os.listdir("."))
    if action == "show_status":
        return "서버 정상 동작 중"
    return "알 수 없는 동작"


tools = [
    Tool(
        name="safe_action",
        func=safe_action,
        description="허용된 읽기 전용 동작만 수행한다: list_files, show_status",
    )
]

agent = initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=False)


def handle_request(user_input: str) -> str:
    return agent.run(user_input)
