import requests


def sanitize(content: str) -> str:
    return f"<<DATA START>>\n{content}\n<<DATA END>>"


def build_prompt(url: str) -> list:
    page_text = requests.get(url).text
    safe_text = sanitize(page_text)
    prompt = f"다음 데이터만 사용해줘: {safe_text}"
    return [{"role": "user", "content": prompt}]
