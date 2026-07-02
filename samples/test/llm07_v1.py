def build_prompt() -> list:
    api_key = "sk-test-secret"
    return [{"role": "system", "content": f"API key: {api_key}"}]
