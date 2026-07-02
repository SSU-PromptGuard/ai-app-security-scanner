# Static analysis sample only. Do not execute.

import os


api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)
response = client.responses.create(input="Summarize the release notes")
