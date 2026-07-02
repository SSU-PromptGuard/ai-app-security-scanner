# Static analysis sample only. Do not execute.

response = get_fake_llm_response()
answer = response.choices[0].message.content
result = eval(answer)
