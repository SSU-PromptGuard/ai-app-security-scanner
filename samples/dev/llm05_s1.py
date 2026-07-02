import ast
from openai import OpenAI

client = OpenAI(api_key="sk-test-placeholder")


def calculate(user_expr: str) -> any:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "숫자 결과만 반환해."},
            {"role": "user", "content": user_expr},
        ],
    )
    answer = response.choices[0].message.content
    result = ast.literal_eval(answer)
    return result
