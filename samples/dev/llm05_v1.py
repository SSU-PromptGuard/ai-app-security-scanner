from openai import OpenAI

client = OpenAI(api_key="sk-test-placeholder")


def calculate(user_expr: str) -> any:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "수식을 Python 표현식으로 변환해."},
            {"role": "user", "content": user_expr},
        ],
    )
    answer = response.choices[0].message.content
    return eval(answer)
