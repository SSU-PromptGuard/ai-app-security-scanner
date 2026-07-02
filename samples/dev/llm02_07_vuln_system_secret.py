# Static analysis sample only. Do not execute.

ADMIN_TOKEN = "sk-demo-hardcoded-secret"

system_prompt = f"""
You are an internal admin assistant.
Admin token: {ADMIN_TOKEN}
"""

messages = [
    {"role": "system", "content": system_prompt}
]
