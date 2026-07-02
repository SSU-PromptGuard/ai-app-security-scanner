# Static analysis sample only. Do not execute.

import os
from openai import OpenAI

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

messages = [
    {"role": "user", "content": "Hello"}
]
