import shutil
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.tools import tool
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate

llm = ChatOpenAI(model="gpt-4o", openai_api_key="sk-test-placeholder")


@tool
def delete_directory(path: str) -> str:
    """주어진 경로의 디렉토리를 삭제한다."""
    shutil.rmtree(path)
    return f"{path} 삭제 완료"


tools = [delete_directory]
prompt = ChatPromptTemplate.from_messages([
    ("system", "파일 관리 에이전트야. 요청에 따라 파일을 관리해."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
agent = create_openai_functions_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)


def handle_request(user_input: str) -> str:
    return executor.invoke({"input": user_input})
