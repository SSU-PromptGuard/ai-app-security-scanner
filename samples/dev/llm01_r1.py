import requests


def build_prompt(url: str) -> list:
    page_text = requests.get(url).text
    prompt = f"다음 페이지를 바탕으로 요약해줘: {page_text}"
    return [{"role": "user", "content": prompt}]
