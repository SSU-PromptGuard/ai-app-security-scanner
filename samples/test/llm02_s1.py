def redact_pii(value: str) -> str:
    return "[REDACTED]"


def build_prompt(user: object) -> list:
    masked = redact_pii(user.email)
    return [{"role": "user", "content": f"사용자 정보: {masked}"}]
