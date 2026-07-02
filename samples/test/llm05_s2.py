import sqlite3
from openai import OpenAI

client = OpenAI(api_key="sk-test-placeholder")


def search_user(query: str) -> list:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "사용자 검색어를 정리해서 이름만 반환해."},
            {"role": "user", "content": query},
        ],
    )
    llm_output = response.choices[0].message.content

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE name = ?"
    cursor.execute(sql, (llm_output,))
    return cursor.fetchall()
