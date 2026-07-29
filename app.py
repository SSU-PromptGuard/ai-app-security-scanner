"""PromptGuard Lite - Streamlit UI.

Static scanner for Python LLM applications. This app NEVER executes the code it
analyzes; it only parses it as text and inspects the AST.
"""

from __future__ import annotations

import ast
import os

import pandas as pd
import streamlit as st

from scanner import analyze_code
from scanner.models import Finding
from scanner.rules import DICTIONARY, RULE_TABLE
from engine.layer_b import judge, MODELS, DEFAULT_MODEL

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(ROOT, "samples", "dev")

SAMPLE_OPTIONS = {
    "LLM01 - 외부 웹 콘텐츠 → prompt": "llm01_external_to_prompt.py",
    "LLM02 - Secret → LLM input": "llm02_secret_to_prompt.py",
    "LLM03 - trust_remote_code=True": "llm03_trust_remote_code.py",
    "LLM03 - pickle.load (unsafe deserialization)": "llm03_unsafe_load.py",
    "LLM05 - LLM output → eval": "llm05_eval.py",
    "LLM05 - LLM output → shell 실행": "llm05_shell.py",
    "LLM05 - LLM output → SQL 실행": "llm05_sql.py",
    "LLM06 - Agent + 파괴적 tool (os.system)": "llm06_agent_destructive_tool.py",
    "LLM06 - Agent + 외부 side effect (webhook POST)": "llm06_agent_external_side_effect.py",
    "LLM07 - Secret → system prompt": "llm07_secret_system_prompt.py",
    "Safe - 기본 LLM 호출": "safe_basic_llm_call.py",
    "Safe - env client only": "safe_env_client_only.py",
    "Safe - read-only agent tool": "safe_readonly_tool.py",
}

SEVERITY_STYLE = {
    "critical": ("🟥", "#ef4444"),
    "high":     ("🟧", "#f97316"),
    "medium":   ("🟨", "#eab308"),
    "low":      ("🟦", "#3b82f6"),
}

SEVERITY_LABEL = {
    "critical": "치명적",
    "high":     "높음",
    "medium":   "보통",
    "low":      "낮음",
}

STATUS_LABEL = {
    "vulnerable": "❌ 확실히 위험한 패턴이 발견됐어요",
    "risky":      "⚠️ 위험할 수 있는 패턴이 발견됐어요",
}

SEVERITY_DESC = {
    "critical": "시스템 실행권한·명령 실행·치명적 DB 조작 등 즉각적이고 큰 피해를 줄 수 있어요",
    "high":     "민감정보 노출·위험 tool 권한·remote code 신뢰 등 심각한 피해를 줄 수 있어요",
    "medium":   "외부 콘텐츠가 LLM prompt로 들어가거나 제한적 정보 노출이 가능한 경우예요",
    "low":      "직접적인 보안 영향은 제한적이지만 안전한 설계 관점에서 개선이 필요해요",
}

# 카드 안 뱃지 hover용 — 레벨별 설명이 아니라 개념 자체를 설명
SEVERITY_CONCEPT = "이 문제가 실제로 악용됐을 때 영향이 얼마나 큰지를 나타내요. 치명적 > 높음 > 보통 > 낮음 순으로 구분해요."
CONFIDENCE_CONCEPT = "이 탐지 결과의 근거가 얼마나 명확한지를 나타내요. 확률이 아니라 판단 근거의 명확성을 뜻하는 값이라, 낮다고 해서 위험도가 낮은 건 아니에요."

# source_kind / sink_kind 를 사용자에게 보여줄 자연어 라벨로 변환
SOURCE_KIND_LABEL = {
    "external_content":    "외부 콘텐츠 (웹, 파일 등)",
    "secret":              "민감 정보 (API 키·비밀번호 등)",
    "llm_output":          "LLM이 생성한 응답",
    "serialized_artifact": "저장돼 있던 모델/데이터 파일",
    "remote_model":        "외부에서 받아온 모델",
    "tool_capability":     "AI 에이전트가 쓸 수 있는 기능",
}

SINK_KIND_LABEL = {
    "llm_input":                "LLM에 전달되는 입력",
    "system_prompt":            "시스템 프롬프트",
    "code_execution":           "코드 실행",
    "shell_execution":          "시스템 명령 실행",
    "sql_execution":            "데이터베이스 명령 실행",
    "unsafe_deserialization":   "안전하지 않은 방식으로 데이터 불러오기",
    "remote_code_trust":        "외부 코드를 그대로 신뢰하는 설정",
    "destructive_or_execution": "파괴적인 동작 또는 실행",
    "external_side_effect":     "외부로 나가는 요청",
}

# About 섹션 — OWASP 6개 케이스 탐지 범위 표
OWASP_SCOPE = [
    ("LLM01", "Prompt Injection",
     "외부 웹/파일/RAG 문서 내용이 prompt/messages에 들어가 LLM call로 전달되는 구조",
     "prompt 텍스트 자체가 공격문인지 판단, 실제 injection 성공 여부",
     "risky", "medium"),
    ("LLM02", "Sensitive Information Disclosure",
     "API key·token·password·DB URL·env secret·개인정보 후보가 prompt/log/print/response에 들어가는 구조",
     "실제 개인정보 여부의 완전 판별, DB 내부 데이터 추론",
     "vulnerable", "high"),
    ("LLM03", "Supply Chain",
     "pickle.load, torch.load, joblib.load, trust_remote_code=True",
     "전체 dependency audit, pip CVE 조회, 모델 파일 무결성 검증",
     "risky", "high"),
    ("LLM05", "Improper Output Handling",
     "LLM output이 검증 없이 eval·exec·subprocess·os.system·SQL execute로 전달되는 구조",
     "실제 명령 실행 여부, runtime permission 확인",
     "vulnerable", "critical"),
    ("LLM06", "Excessive Agency",
     "agent/tool에 shell·file delete·DB write·email send 등 고위험 capability가 연결된 구조",
     "agent가 실제로 그 tool을 호출하는지, 권한 정책 전체 분석",
     "risky", "high"),
    ("LLM07", "System Prompt Leakage",
     "system prompt에 secret·internal URL·admin rule·hidden policy가 포함되는 구조",
     "모델이 실제로 system prompt를 유출하는지 실험",
     "vulnerable", "high"),
]


def load_sample(filename: str) -> str | None:
    path = os.path.join(SAMPLES_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def confidence_label(confidence: float) -> tuple[str, str]:
    """Confidence는 확률이 아니라 '탐지 근거가 얼마나 명확한가'를 나타낸다.
    Severity(영향 크기)와는 서로 독립적인 축이라 낮아도 위험도가 낮다는 뜻이 아니다.
    분석기가 실제로 내는 값은 {0.9, 0.75, 0.6} 셋 중 하나다."""
    if confidence >= 0.9:
        return "높음", "코드에서 위험한 값이 어디서 시작해서 어디로 전달되는지 정확한 패턴으로 확인됐어요"
    if confidence >= 0.75:
        return "보통", "흐름은 확인됐지만, 일부는 변수명이나 문자열 패턴 추정에 의존했어요"
    return "낮음", "키워드 기반 추정이 강하게 들어가 있어 오탐 가능성이 있어요, 직접 확인해보시는 걸 추천해요"


# ---------------------------------------------------------------------------
# Finding card rendering
# ---------------------------------------------------------------------------

def render_finding(f: Finding) -> None:
    emoji, _ = SEVERITY_STYLE.get(f.severity, ("⬜", ""))
    severity_label = SEVERITY_LABEL.get(f.severity, f.severity)
    status_label = STATUS_LABEL.get(f.status, f.status)
    source_label = SOURCE_KIND_LABEL.get(f.source_kind, f.source_kind)
    sink_label = SINK_KIND_LABEL.get(f.sink_kind, f.sink_kind)
    conf_level, _conf_desc = confidence_label(f.confidence)

    with st.container(border=True):
        st.markdown(f"#### {emoji} {f.category}")
        st.markdown(status_label)

        badge_col1, badge_col2 = st.columns(2)
        badge_col1.metric(
            "**심각도**",
            severity_label,
            help=SEVERITY_CONCEPT,
        )
        badge_col2.metric(
            "**근거 확실성**",
            conf_level,
            help=CONFIDENCE_CONCEPT,
        )

        st.markdown(f"**어디서 시작됐나요?** : {source_label}")
        st.code(f.source, language="text")

        st.markdown(f"**어디로 전달됐나요?** : {sink_label}")
        st.code(f.sink, language="text")

        st.markdown("**어떻게 전달됐나요?**")
        st.code(f.flow, language="text")

        st.markdown("**코드에서 확인된 부분**")
        st.code(f.evidence, language="text")

        st.caption(f"코드 위치: {f.line}번째 줄")

        # 레이어 B가 생성한 reason / fix (있을 때만 표시)
        if getattr(f, "reason", None):
            st.divider()
            st.markdown("**왜 위험한가요? (AI)**")
            st.write(f.reason)
        if getattr(f, "fix", None):
            st.markdown("**이렇게 고쳐보세요 (AI)**")
            st.write(f.fix)
        if getattr(f, "_judge_error", None):
            st.caption(f"⚠️ AI 설명을 만드는 중 오류가 발생했어요: {f._judge_error}")

        st.caption(f"규칙 ID: {f.rule_id}")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def render_findings_summary(findings: list[Finding]) -> None:
    counts = severity_counts(findings)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("탐지된 개수", len(findings))
    c2.metric("치명적", counts["critical"], help=SEVERITY_DESC["critical"])
    c3.metric("높음",   counts["high"],     help=SEVERITY_DESC["high"])
    c4.metric("보통",   counts["medium"],   help=SEVERITY_DESC["medium"])


# ---------------------------------------------------------------------------
# Streamlit app
# ---------------------------------------------------------------------------

st.set_page_config(page_title="PromptGuard Lite", page_icon="", layout="wide")

st.markdown(
    """
    <style>
    /* Scan 탭: Code 입력창을 Input 컬럼 실제 높이에 맞춰 항상 Scan 버튼까지 채움 */
    .st-key-scan_io [data-testid="stHorizontalBlock"] {
        align-items: stretch;
    }
    .st-key-scan_io [data-testid="stVerticalBlock"] {
        height: 100%;
    }
    .st-key-scan_io [data-testid="stElementContainer"]:has([data-testid="stTextArea"]) {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-height: 0;
    }
    .st-key-scan_io [data-testid="stTextArea"] {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-height: 0;
    }
    .st-key-scan_io [data-testid="stTextAreaRootElement"] {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-height: 0;
    }
    .st-key-scan_io [data-testid="stTextAreaRootElement"] > div {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-height: 0;
    }
    .st-key-scan_io textarea {
        flex: 1;
        height: 100% !important;
        min-height: 0;
    }

    /* 심각도/근거 확실성 등 metric help 툴팁 — 폭을 좁혀서 오른쪽에 안정적으로 뜨도록 */
    div[data-testid="stTooltipContent"] {
        max-width: 260px;
    }

    /* Primary 버튼 색상 — 인디고 (severity 색상인 빨강/주황/노랑/파랑과 안 겹치게) */
    button[kind="primary"], [data-testid="stBaseButton-primary"] {
        background-color: #6366F1;
        border-color: #6366F1;
    }
    button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover {
        background-color: #4f46e5;
        border-color: #4f46e5;
        color: #ffffff;
    }
    button[kind="primary"]:active, [data-testid="stBaseButton-primary"]:active {
        background-color: #4338ca;
        border-color: #4338ca;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "active_section" not in st.session_state:
    st.session_state.active_section = "scan"

# ===========================================================================
# 헤더 — Scan이 메인 화면. Dictionary/About은 우측 상단 메뉴에서만 접근
# ===========================================================================
header_left, header_right = st.columns([5, 1])
with header_left:
    st.title("PromptGuard Lite")
    st.caption("코드를 붙여 넣으면 위험할 수 있는 부분을 자동으로 찾아드려요. 코드를 직접 실행하지는 않아요.")
with header_right:
    st.write("")
    with st.popover("더 알아보기", use_container_width=True):
        st.caption("이 도구가 무엇을 찾아내는지, 어떤 한계가 있는지 확인해보세요.")
        if st.button("어떤 걸 찾아내나요?", use_container_width=True):
            st.session_state.active_section = "dict"
            st.rerun()
        if st.button("소개 및 한계 보기", use_container_width=True):
            st.session_state.active_section = "about"
            st.rerun()

section = st.session_state.active_section

if section in ("dict", "about"):
    if st.button("← 검사 화면으로 돌아가기"):
        st.session_state.active_section = "scan"
        st.rerun()
    st.divider()

# ===========================================================================
# 화면: 검사 (메인)
# ===========================================================================
if section == "scan":
    sample_keys = list(SAMPLE_OPTIONS)
    if "code" not in st.session_state:
        st.session_state.code = load_sample(SAMPLE_OPTIONS[sample_keys[0]]) or ""
    if "last_findings" not in st.session_state:
        st.session_state.last_findings = None
    if "sample_choice" not in st.session_state:
        st.session_state.sample_choice = sample_keys[0]
    if "_loaded_sample" not in st.session_state:
        st.session_state._loaded_sample = sample_keys[0]

    with st.container(key="scan_io"):
        left, right = st.columns([1, 1])

        with left:
            st.subheader("코드 준비")
            choice = st.selectbox(
                "샘플 코드 선택",
                sample_keys,
                key="sample_choice",
            )
            if choice != st.session_state._loaded_sample:
                loaded = load_sample(SAMPLE_OPTIONS[choice])
                if loaded is None:
                    st.error(f"샘플 파일을 찾을 수 없습니다: `{SAMPLE_OPTIONS[choice]}`")
                else:
                    st.session_state.code = loaded
                    st.session_state.last_findings = None
                st.session_state._loaded_sample = choice

            uploaded = st.file_uploader("직접 만든 .py 파일 업로드", type=["py"])
            if uploaded is not None:
                st.session_state.code = uploaded.read().decode("utf-8", errors="replace")
                st.session_state.last_findings = None
            use_layer_b = st.toggle("AI로 이유와 해결 방법까지 보기", value=False)

            if use_layer_b:
                user_level = st.selectbox(
                    "설명 수준",
                    ["beginner", "intermediate"],
                    index=1,
                    format_func=lambda x: {
                        "beginner":     "입문자: 쉬운 설명",
                        "intermediate": "개발자: 기술적 설명",
                    }[x],
                )
                judge_model = st.selectbox(
                    "사용할 AI 모델",
                    list(MODELS.keys()),
                    format_func=lambda x: MODELS[x],
                )
            else:
                user_level = "intermediate"
                judge_model = DEFAULT_MODEL

            scan = st.button("검사하기", type="primary", use_container_width=True)

        with right:
            st.subheader("코드")
            st.session_state.code = st.text_area(
                "Python code",
                value=st.session_state.code,
                height=200,
                label_visibility="collapsed",
            )

    if scan:
        try:
            ast.parse(st.session_state.code)
        except SyntaxError as exc:
            st.session_state.syntax_error = (
                f"Python 문법에 오류가 있어요 ({exc.lineno}번째 줄): {exc.msg}"
            )
            st.session_state.last_findings = None
        else:
            st.session_state.syntax_error = None
            findings = analyze_code(st.session_state.code, "<input>")

            # 레이어 B: reason / fix 생성
            if use_layer_b and findings:
                with st.spinner("AI가 설명을 만드는 중..."):
                    for f in findings:
                        result = judge(
                            f.to_dict(),
                            user_level=user_level,
                            model=judge_model,
                        )
                        f.reason = result.reason
                        f.fix    = result.fix
                        f._judge_error = result.error

            st.session_state.last_findings = findings

    if st.session_state.get("syntax_error"):
        st.divider()
        st.warning("⚠️ " + st.session_state.syntax_error)
    elif st.session_state.last_findings is not None:
        findings = st.session_state.last_findings
        st.divider()
        st.subheader("탐지 결과")
        if not findings:
            st.success(
                "지금 규칙으로는 위험해 보이는 부분을 찾지 못했어요. "
                "(코드가 완전히 안전하다는 뜻은 아니에요.)"
            )
        else:
            render_findings_summary(findings)
            for f in findings:
                render_finding(f)

# ===========================================================================
# 화면: Source/Sink 사전
# ===========================================================================
elif section == "dict":
    st.subheader("Source / Sink 사전")
    st.markdown(
        "PromptGuard는 코드에서 위험이 시작되는 지점(**source**)이 위험이 실제로 "
        "발동하는 지점(**sink**)까지 이어지는지를 추적합니다. 아래는 분석기가 인식하는 대표적인 "
        "source/sink API 패턴 목록입니다."
    )
    st.info(
        "**Source** = 신뢰할 수 없거나 민감한 값이 코드에 처음 등장하는 지점 "
        "(예: 외부 웹 응답, API 키, LLM 응답)\n\n"
        "**Sink** = 그 값이 흘러 들어가면 위험해지는 지점 "
        "(예: eval(), os.system(), LLM system prompt)\n\n"
        "→ 같은 rule 안에서 **source의 값이 sink까지 오염 없이 도달**하면 finding이 발생합니다."
    )

    if DICTIONARY:
        df = pd.DataFrame(
            DICTIONARY,
            columns=["Type", "대표 API / 패턴", "의미", "관련 OWASP"],
        )
        st.markdown("**Source (위험이 시작되는 지점)**")
        st.dataframe(
            df[df["Type"] == "Source"].drop(columns=["Type"]),
            use_container_width=True, hide_index=True,
        )
        st.markdown("**Sink (위험이 발동하는 지점)**")
        st.dataframe(
            df[df["Type"] == "Sink"].drop(columns=["Type"]),
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("Dictionary will be populated once Layer A rules are finalized.")

# ===========================================================================
# 화면: 소개 및 범위
# ===========================================================================
elif section == "about":
    about_intro, about_scope, about_structure, about_policy = st.tabs(
        ["개요", "탐지 범위 (OWASP)", "내부 구조", "정책 & 한계"]
    )

    # -- 개요 -----------------------------------------------------------
    with about_intro:
        st.markdown(
            "> 이 도구는 코드를 실제로 실행하지 않아요. 코드를 읽어보고 위험해 보이는 부분을 "
            "찾아낼 뿐, 그 공격이 실제로 통하는지까지는 확인하지 않아요."
        )

        st.markdown("#### 이 도구는 무엇을 하나요?")
        st.markdown(
            "PromptGuard는 Python으로 만든 LLM(챗봇, AI 에이전트) 프로그램에 보안 문제가 될 "
            "만한 코드가 있는지 확인해줘요. 프롬프트에 적힌 문장이 나쁜 내용인지 판단하는 게 "
            "아니라, **위험할 수 있는 값이 코드 안에서 어디서 시작해 어디로 흘러가는지**를 살펴봐요."
        )

        st.markdown("#### 탐지 결과, 이렇게 이해해주세요")
        st.markdown(
            "무언가 탐지됐다고 해서 \"이 코드는 무조건 공격당한다\"는 뜻은 **아니에요**. "
            "\"이 부분은 보안 관점에서 한 번 확인해볼 필요가 있다\"는 의미로 봐주시면 돼요. "
            "예를 들면 이런 경우들을 찾아내요:"
        )
        st.markdown("""
- 외부에서 가져온 내용이 검증 없이 AI에게 그대로 전달되는 경우
- 비밀번호나 API 키 같은 민감한 정보가 AI 입력이나 로그에 들어가는 경우
- 안전하지 않은 방식으로 파일이나 외부 모델을 불러오는 경우
- AI가 만든 답변을 검증 없이 그대로 실행해버리는 경우
- AI 에이전트에게 파일 삭제·명령 실행 같은 위험한 기능이 연결돼 있는 경우
""")

        st.markdown("#### 어떻게 검사하나요?")
        st.markdown(
            "코드를 한 줄씩 읽으면서 위험할 수 있는 값이 어디서 시작해서 어디로 전달되는지를 "
            "따라가요. 별도 프로그램을 설치하거나 실행할 필요 없이, 코드 구조만 보고 판단해요."
        )

    # -- 탐지 범위 --------------------------------------------------------
    with about_scope:
        st.markdown("#### Supported OWASP Cases")
        scope_df = pd.DataFrame(
            OWASP_SCOPE,
            columns=["Case", "Name", "탐지 대상", "탐지하지 않는 것", "Status", "Severity"],
        )
        st.dataframe(scope_df, use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("#### Status / Severity 범례")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Status** (정적 분석 결과의 확실성)")
            st.markdown("""
| Status | 의미 |
|---|---|
| ❌ vulnerable | 취약한 코드 흐름이 정적으로 확인됨 |
| ⚠️ risky | 위험 가능성이 있으나 단정하기 어려움 |
| ✅ safe | 위험 흐름이 확인되지 않음 (finding 미출력) |
""")

        with col2:
            st.markdown("**Severity** (실제 악용 시 영향도)")
            st.markdown("""
| Severity | 의미 |
|---|---|
| 🟥 critical | 즉각적 명령 실행·파괴·치명적 DB 조작 |
| 🟧 high | 민감정보 노출·위험 권한·remote code 신뢰 |
| 🟨 medium | 외부 콘텐츠 유입·제한적 정보 노출 가능 |
| 🟦 low | 직접 피해 제한적, 설계 개선 필요 |
""")

    # -- 내부 구조 --------------------------------------------------------
    with about_structure:
        st.markdown("#### Source / Sink Family")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Source Family**")
            source_df = pd.DataFrame([
                ("external_content", "웹, 파일, PDF, RAG, vector search 결과", "LLM01"),
                ("secret",           "API key, token, password, DB URL",        "LLM02, LLM07"),
                ("llm_output",       "LLM/chain/agent 응답값",                  "LLM05"),
                ("serialized_artifact", "pickle/joblib/torch 로딩 대상",         "LLM03"),
                ("remote_model",     "remote model repository",                  "LLM03"),
                ("tool_capability",  "agent tool의 위험 기능",                   "LLM06"),
            ], columns=["source_kind", "의미", "주요 Rule"])
            st.dataframe(source_df, use_container_width=True, hide_index=True)

        with col2:
            st.markdown("**Sink Family**")
            sink_df = pd.DataFrame([
                ("llm_input",              "LLM 입력",              "llm.invoke, messages=",           "LLM01, LLM02"),
                ("system_prompt",          "system role prompt",    'role="system", SystemMessage',    "LLM07"),
                ("code_execution",         "Python 코드 실행",       "eval, exec",                      "LLM05"),
                ("shell_execution",        "OS/process 실행",       "os.system, subprocess.run",       "LLM05"),
                ("sql_execution",          "SQL 실행",              "cursor.execute, conn.execute",    "LLM05"),
                ("unsafe_deserialization", "위험한 역직렬화",         "pickle.load, torch.load",         "LLM03"),
                ("remote_code_trust",      "remote code 신뢰",      "trust_remote_code=True",          "LLM03"),
                ("destructive_or_execution","agent 실행/파괴",       "shell, file delete",              "LLM06"),
                ("external_side_effect",   "agent 외부 side effect","DB write, email, POST",           "LLM06"),
            ], columns=["sink_kind", "의미", "대표 API", "주요 Rule"])
            st.dataframe(sink_df, use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("#### Required Rule Table")
        rule_df = pd.DataFrame(RULE_TABLE).rename(columns={
            "no":             "No",
            "rule_id":        "Rule ID",
            "category":       "Category",
            "detection_type": "Detection Type",
            "source_kind":    "Source Kind",
            "sink_kind":      "Sink Kind",
            "status":         "Status",
            "severity":       "Severity",
            "confidence":     "Default Confidence",
        })
        st.dataframe(rule_df, use_container_width=True, hide_index=True)

    # -- 정책 & 한계 ------------------------------------------------------
    with about_policy:
        st.markdown("#### 중복 처리 정책")
        st.markdown("""
- **동일 finding 병합**: `(file, rule_id, line, sink)` 가 같으면 하나로 병합
- **LLM07 우선**: secret → system prompt가 잡히면 같은 source의 LLM02는 숨김
- **서로 다른 sink_kind는 모두 표시**: code_execution / shell_execution / sql_execution 각각 표시
- **서로 다른 OWASP 의미는 모두 표시**: LLM01+LLM05, LLM01+LLM06, LLM05+LLM06 등
""")

        st.divider()
        st.warning(
            "**MVP 제외 범위 (현재 미지원)**\n\n"
            "1. 입력 코드를 실행하지 않음 (정적 분석만)\n"
            "2. 실제 exploit 가능 여부 미검증\n"
            "3. 단일 파일 분석만 지원 (inter-file taint 미지원)\n"
            "4. complex inter-procedural analysis 미지원\n"
            "5. JS/TS 미지원 (Python only)\n"
            "6. package CVE audit 미지원\n"
            "7. 모델 파일 hash 검증 미지원\n"
            "8. advanced sanitizer verification 미지원\n"
            "9. runtime permission analysis 미지원\n"
            "10. agent의 실제 tool 호출 여부 미분석\n"
            "11. risky 결과는 사람의 추가 검토 필요"
        )
