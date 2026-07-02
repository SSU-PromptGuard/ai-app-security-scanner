from pathlib import Path


def build_prompt(path: str) -> list:
    content = Path(path).read_text(encoding="utf-8")
    prompt = f"다음 파일 내용을 바탕으로 답변해줘: {content}"
    return [{"role": "user", "content": prompt}]
