# Static analysis sample only. Do not execute.

action = response.choices[0].message.content

allowed_actions = {"summarize", "classify", "translate"}

if action not in allowed_actions:
    raise ValueError("Unsupported action")

run_predefined_action(action)
