# Static analysis sample only. Do not execute.


def run(llm, user_question):
    prompt = f"Answer this question: {user_question}"
    return llm.invoke(prompt)
