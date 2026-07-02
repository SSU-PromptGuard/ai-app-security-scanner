# Static analysis sample only. Do not execute.

import os

api_key = os.getenv("OPENAI_API_KEY")
client.responses.create(input=f"Use this key: {api_key}")
