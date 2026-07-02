def build_prompt(user: object) -> list:
    secret = user.email
    return [{"role": "user", "content": f"사용자 정보: {secret}"}]
