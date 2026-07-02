# Static analysis sample only. Do not execute.

from langchain.agents import Tool, initialize_agent

def search_docs(query):
    return vectorstore.similarity_search(query)

tools = [
    Tool(name="search_docs", func=search_docs, description="Read-only document search")
]

agent = initialize_agent(tools, llm)
agent.run(user_question)
