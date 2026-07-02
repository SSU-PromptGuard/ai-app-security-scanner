"""Layer B — LLM Judge.

레이어 A가 탐지한 Finding을 받아 LLM이 reason과 fix를 생성한다.
숭실대 MindLogic API Gateway를 사용한다.

사용자 수준 (user_level):
    beginner     — 비전공자도 이해할 수 있는 쉬운 설명
    intermediate — 개발자 수준의 설명
    expert       — 보안 전문가 수준의 기술적 설명

3사 비교 실험:
    - GPT, Gemini   → OpenAI SDK + /v1/gateway
    - Claude        → Anthropic SDK + /v1/gateway/claude
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from dotenv import load_dotenv
from openai import OpenAI
import anthropic

load_dotenv()

_OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY", "")
_CLAUDE_API_KEY   = os.getenv("ANTHROPIC_AUTH_TOKEN", _OPENAI_API_KEY)  
_OPENAI_BASE_URL  = os.getenv("OPENAI_BASE_URL",   "https://factchat-cloud.mindlogic.ai/v1/gateway")
_CLAUDE_BASE_URL  = os.getenv("CLAUDE_BASE_URL",   "https://factchat-cloud.mindlogic.ai/v1/gateway/claude")

MODELS = {
    "gpt-5.4":               "OpenAI GPT-5.4",
    "claude-sonnet-4-5-20250929": "Anthropic Claude Sonnet 4.5",
    "gemini-3.1-pro-preview":           "Google Gemini 3.1 Pro (Preview)",
}

DEFAULT_MODEL = "gpt-5.4"

# Claude 모델 판별
_CLAUDE_MODELS = {"claude-sonnet-4-5-20250929"}

LEVEL_INSTRUCTIONS = {
    "beginner": (
        "당신은 친절한 보안 도우미입니다. "
        "설명 대상은 Python을 막 배우기 시작한 입문자입니다. "
        "전문 용어는 최대한 피하고, 일상적인 언어로 쉽게 설명하세요. "
        "fix는 '이렇게 바꿔보세요'처럼 구체적이고 따라 하기 쉽게 작성하세요."
    ),
    "intermediate": (
        "당신은 경험 많은 보안 코드 리뷰어입니다. "
        "설명 대상은 Python 개발자입니다. "
        "기술적 용어를 사용해도 좋으나, 왜 위험한지 흐름을 명확히 설명하세요. "
        "fix는 실제 코드 수정 방향을 구체적으로 제시하세요."
    ),
    "expert": (
        "당신은 LLM 애플리케이션 보안 전문가입니다. "
        "설명 대상은 보안 엔지니어입니다. "
        "OWASP LLM Top 10, taint analysis, attack vector 등 전문 용어를 사용하세요. "
        "fix는 보안 아키텍처 관점에서 근본적인 해결책을 제시하세요."
    ),
}

def _build_prompt(finding_dict: dict) -> str:
    return f"""\
아래는 Python LLM 애플리케이션 코드에서 정적 분석으로 탐지된 보안 패턴이다.

[탐지 정보]
- Rule:     {finding_dict.get("rule_id", "")}
- Category: {finding_dict.get("category", "")}
- Status:   {finding_dict.get("status", "")}
- Severity: {finding_dict.get("severity", "")}
- Source:   {finding_dict.get("source", "")} ({finding_dict.get("source_kind", "")})
- Sink:     {finding_dict.get("sink", "")} ({finding_dict.get("sink_kind", "")})
- Flow:     {finding_dict.get("flow", "")}
- Evidence: {finding_dict.get("evidence", "")}
- File:     {finding_dict.get("file", "")}, Line {finding_dict.get("line", "")}

반드시 아래 JSON 형식으로만 응답하라. JSON 외 다른 텍스트나 마크다운 코드 블록은 포함하지 마라.
주의: "reason"과 "fix"의 값 내부에서 마크다운 제목 기호인 '#' (샵 기호)는 절대 사용하지 마라. 강조가 필요하다면 '**텍스트**' 처럼 볼드체만 사용하라.

{{
  "reason": "왜 이 코드가 위험한지 설명",
  "fix": "어떻게 수정해야 하는지 설명 (줄바꿈이 필요하다면 문자열 내에 반드시 \\n 기호를 사용하여 개행할 것)"
}}
"""

def _parse_json(raw: str) -> dict:
    clean = raw.strip()
    clean = (
        clean.removeprefix("```json")
        .removeprefix("```")
        .removesuffix("```")
        .strip()
    )
    
    try:
        return json.loads(clean, strict=False)
    except Exception:
        return {"reason": f"응답 파싱 실패 원본: {clean[:100]}", "fix": "가이드를 가져오지 못했습니다."}
# ---------------------------------------------------------------------------
# Judge 함수
# ---------------------------------------------------------------------------

@dataclass
class JudgeResult:
    reason: str
    fix: str
    model_used: str
    error: str | None = None


def _judge_openai(finding_dict: dict, user_level: str, model: str) -> JudgeResult:
    """GPT / Gemini — OpenAI SDK + /v1/gateway"""
    client = OpenAI(api_key=_OPENAI_API_KEY, base_url=_OPENAI_BASE_URL)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": LEVEL_INSTRUCTIONS[user_level]},
            {"role": "user",   "content": _build_prompt(finding_dict)},
        ],
        max_tokens=2048,
        temperature=0.2,
        response_format={"type": "json_object"} 
    )
    raw = response.choices[0].message.content or ""
    parsed = _parse_json(raw)
    return JudgeResult(
        reason=parsed.get("reason", ""),
        fix=parsed.get("fix", ""),
        model_used=model,
    )


def _judge_claude(finding_dict: dict, user_level: str, model: str) -> JudgeResult:
    """Claude — Anthropic SDK + /v1/gateway/claude"""
    client = anthropic.Anthropic(
        auth_token=_CLAUDE_API_KEY,
        base_url=_CLAUDE_BASE_URL,
    )
    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=LEVEL_INSTRUCTIONS[user_level],
        messages=[
            {"role": "user", "content": _build_prompt(finding_dict)},
        ],
    )
    raw = response.content[0].text if response.content else ""
    parsed = _parse_json(raw)
    return JudgeResult(
        reason=parsed.get("reason", ""),
        fix=parsed.get("fix", ""),
        model_used=model,
    )


def judge(
    finding_dict: dict,
    user_level: str = "intermediate",
    model: str = DEFAULT_MODEL,
) -> JudgeResult:
    """Finding 하나를 받아 LLM이 reason과 fix를 생성한다.

    Args:
        finding_dict: Finding.to_dict() 결과
        user_level:   "beginner" | "intermediate" | "expert"
        model:        사용할 모델 ID (MODELS 딕셔너리 참고)

    Returns:
        JudgeResult(reason, fix, model_used, error)
    """
    if not _OPENAI_API_KEY:
        return JudgeResult(
            reason="API 키가 설정되지 않았습니다. .env 파일에 OPENAI_API_KEY를 설정해주세요.",
            fix="",
            model_used=model,
            error="missing_api_key",
        )

    level = user_level if user_level in LEVEL_INSTRUCTIONS else "intermediate"

    try:
        if model in _CLAUDE_MODELS:
            return _judge_claude(finding_dict, level, model)
        else:
            return _judge_openai(finding_dict, level, model)

    except json.JSONDecodeError as e:
        return JudgeResult(
            reason="LLM 응답 파싱 실패",
            fix="",
            model_used=model,
            error=f"json_parse_error: {e}",
        )
    except Exception as e:
        return JudgeResult(
            reason="LLM 판정 중 오류 발생",
            fix="",
            model_used=model,
            error=str(e),
        )


def judge_all(
    findings: list[dict],
    user_level: str = "intermediate",
    model: str = DEFAULT_MODEL,
) -> list[JudgeResult]:
    """Finding 리스트 전체에 judge를 적용한다."""
    return [judge(f, user_level=user_level, model=model) for f in findings]