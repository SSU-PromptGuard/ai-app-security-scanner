# Static analysis sample only. Do not execute.

file_text = open("uploaded_resume.txt").read()
messages = [
    {"role": "user", "content": f"Review this resume:\n{file_text}"}
]

client.chat.completions.create(model="gpt-4o", messages=messages)
