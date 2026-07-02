"""PromptGuard Lite - Streamlit UI.

Static scanner for Python LLM applications. This app NEVER executes the code it
analyzes; it only parses it as text and inspects the AST.
"""

from __future__ import annotations

import ast
import os

import pandas as pd
import streamlit as st

from scanner import analyze_code, evaluate
from scanner.models import Finding
from scanner.rules import DICTIONARY, RULE_TABLE
from engine.layer_b import judge, MODELS, DEFAULT_MODEL

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(ROOT, "samples")

SAMPLE_OPTIONS = {
    "LLM05 - Vulnerable eval": "llm05_vuln_eval.py",
    "LLM05 - Vulnerable subprocess (shell)": "llm05_vuln_subprocess.py",
    "LLM05 - Safe print": "llm05_safe_print.py",
    "LLM05 - Safe allow-list": "llm05_safe_allowlist.py",
    "LLM01 - External web content to prompt": "llm01_risky_web_prompt.py",
    "LLM01 - File content to prompt": "llm01_risky_file_prompt.py",
    "LLM06 - Agent with shell tool": "llm06_vuln_shell_tool.py",
    "LLM06 - Agent with read-only tool (safe)": "llm06_safe_readonly_tool.py",
    "LLM02/07 - Secret in system prompt": "llm02_07_vuln_system_secret.py",
    "LLM02 - Env client only (safe)": "llm02_safe_env_client_only.py",
    "LLM03 - pickle.load": "llm03_risky_pickle_load.py",
    "LLM03 - trust_remote_code=True": "llm03_risky_trust_remote_code.py",
}

SEVERITY_STYLE = {
    "critical": ("🟥", "#ef4444"),
    "high":     ("🟧", "#f97316"),
    "medium":   ("🟨", "#eab308"),
    "low":      ("🟦", "#3b82f6"),
}

STATUS_EMOJI = {
    "vulnerable": "❌ vulnerable",
    "risky":      "⚠️ risky",
    "safe":       "✅ safe",
}

# status / severity 설명 (결과 카드 tooltip용)
STATUS_DESC = {
    "vulnerable": "취약한 코드 흐름이 정적으로 확인됨",
    "risky":      "위험 가능성이 있는 패턴이 확인되나 취약하다고 단정하기는 어려움",
}

SEVERITY_DESC = {
    "critical": "시스템 실행권한·명령 실행·치명적 DB 조작 등 즉각적이고 큰 피해",
    "high":     "민감정보 노출·위험 tool 권한·remote code 신뢰 등 심각한 피해",
    "medium":   "외부 콘텐츠가 LLM prompt로 들어가거나 제한적 정보 노출이 가능한 경우",
    "low":      "직접적인 보안 영향은 제한적이지만 안전한 설계 관점에서 개선이 필요",
}

# About 탭 — OWASP 6개 케이스 탐지 범위 표
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


def load_sample(filename: str) -> str:
    path = os.path.join(SAMPLES_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Finding card rendering
# ---------------------------------------------------------------------------

def _row(label: str, value, mono: bool = False) -> None:
    col_label, col_value = st.columns([1, 4])
    col_label.markdown(f"**{label}**")
    if mono:
        col_value.code(str(value), language="text")
    else:
        col_value.write(value)


def render_finding(f: Finding) -> None:
    emoji, _ = SEVERITY_STYLE.get(f.severity, ("⬜", ""))
    status_label = STATUS_EMOJI.get(f.status, f.status)
    status_desc = STATUS_DESC.get(f.status, "")
    severity_desc = SEVERITY_DESC.get(f.severity, "")

    with st.container(border=True):
        st.markdown(f"#### {emoji} {f.category}")
        st.markdown(f"**{f.rule_id}** · {f.severity.upper()} · {status_label}")

        # status / severity 설명을 caption으로 표시
        st.caption(f"status: {status_desc}  |  severity: {severity_desc}")

        _row("Source kind", f.source_kind)
        _row("Source",      f.source,    mono=True)
        _row("Sink kind",   f.sink_kind)
        _row("Sink",        f.sink,      mono=True)
        _row("Flow",        f.flow,      mono=True)
        _row("Evidence",    f.evidence,  mono=True)
        _row("Line",        f.line)
        _row("Confidence",  f"{f.confidence:.0%}")
        # 레이어 B가 생성한 reason / fix (있을 때만 표시)
        if getattr(f, "reason", None):
            st.divider()
            _row("Reason (AI)", f.reason)
        if getattr(f, "fix", None):
            _row("Fix (AI)",    f.fix)
        if getattr(f, "_judge_error", None):
            st.caption(f"⚠️ Layer B error: {f._judge_error}")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def render_findings_summary(findings: list[Finding]) -> None:
    counts = severity_counts(findings)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Findings", len(findings))
    c2.metric("Critical",  counts["critical"])
    c3.metric("High",      counts["high"])
    c4.metric("Medium",    counts["medium"])


# ---------------------------------------------------------------------------
# Streamlit app
# ---------------------------------------------------------------------------

st.set_page_config(page_title="PromptGuard Lite", page_icon="🛡️", layout="wide")

st.title("🛡️ PromptGuard")
st.caption(
    "Static scanner for Python LLM apps — detects risky source → sink patterns "
    "(OWASP Top 10 for LLM Applications 2025). It does **not** execute your code."
)

tab_scan, tab_eval, tab_dict, tab_about = st.tabs(
    ["🔍 Scan", "📊 Evaluation", "📚 Source/Sink Dictionary", "ℹ️ About / Scope"]
)

# ===========================================================================
# Tab 1: Scan
# ===========================================================================
with tab_scan:
    if "code" not in st.session_state:
        st.session_state.code = load_sample(SAMPLE_OPTIONS["LLM05 - Vulnerable eval"])
    if "last_findings" not in st.session_state:
        st.session_state.last_findings = None

    left, right = st.columns([1, 2])

    with left:
        st.subheader("Input")
        choice = st.selectbox("Built-in sample", ["(keep current)"] + list(SAMPLE_OPTIONS))
        if st.button("Load sample", use_container_width=True) and choice != "(keep current)":
            st.session_state.code = load_sample(SAMPLE_OPTIONS[choice])
            st.session_state.last_findings = None

        uploaded = st.file_uploader("…or upload a .py file", type=["py"])
        if uploaded is not None:
            st.session_state.code = uploaded.read().decode("utf-8", errors="replace")
            st.session_state.last_findings = None

        st.divider()
        st.markdown("**🤖 AI 판정**")
        use_layer_b = st.toggle("AI 판정 사용 (reason / fix 생성)", value=False)

        if use_layer_b:
            user_level = st.selectbox(
                "설명 수준",
                ["beginner", "intermediate", "expert"],
                index=1,
                format_func=lambda x: {
                    "beginner":     "🟢 입문자 — 쉬운 설명",
                    "intermediate": "🟡 개발자 — 기술적 설명",
                    "expert":       "🔴 전문가 — 보안 심화 설명",
                }[x],
            )
            judge_model = st.selectbox(
                "판정 모델",
                list(MODELS.keys()),
                format_func=lambda x: MODELS[x],
            )
        else:
            user_level = "intermediate"
            judge_model = DEFAULT_MODEL

        scan = st.button("🔍 Scan", type="primary", use_container_width=True)

    with right:
        st.subheader("Code")
        st.session_state.code = st.text_area(
            "Python code",
            value=st.session_state.code,
            height=320,
            label_visibility="collapsed",
        )

    if scan:
        try:
            ast.parse(st.session_state.code)
        except SyntaxError as exc:
            st.session_state.syntax_error = (
                f"Invalid Python syntax (line {exc.lineno}): {exc.msg}"
            )
            st.session_state.last_findings = None
        else:
            st.session_state.syntax_error = None
            findings = analyze_code(st.session_state.code, "<input>")

            # 레이어 B: reason / fix 생성
            if use_layer_b and findings:
                with st.spinner("🤖 AI 판정 중..."):
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
        st.subheader("Findings")
        if not findings:
            st.success(
                "No risky source → sink patterns detected by the current rules. "
                "(This does not guarantee the code is safe.)"
            )
        else:
            render_findings_summary(findings)
            for f in findings:
                render_finding(f)

# ===========================================================================
# Tab 2: Evaluation
# ===========================================================================
with tab_eval:
    st.subheader("Evaluation on the built-in sample set")
    st.caption(
        "Binary convention: positive = vulnerable + risky, negative = safe. "
        "A sample is predicted positive when the analyzer returns ≥ 1 finding."
    )

    if st.button("Run evaluation", type="primary"):
        metrics, table = evaluate(ROOT)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Precision", f"{metrics['precision']:.2f}")
        c2.metric("Recall",    f"{metrics['recall']:.2f}")
        c3.metric("Accuracy",  f"{metrics['accuracy']:.2f}")
        c4.metric("Samples",   metrics["total"])

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("TP", metrics["TP"])
        c2.metric("FP", metrics["FP"])
        c3.metric("FN", metrics["FN"])
        c4.metric("TN", metrics["TN"])

        st.markdown("**Per-sample results**")
        st.dataframe(table, use_container_width=True, hide_index=True)
    else:
        st.info("Click **Run evaluation** to scan all labelled samples and compute metrics.")

# ===========================================================================
# Tab 3: Source/Sink Dictionary
# ===========================================================================
with tab_dict:
    st.subheader("Source / Sink dictionary used by this prototype")

    if DICTIONARY:
        df = pd.DataFrame(
            DICTIONARY,
            columns=["Type", "Name", "Description", "Related OWASP"],
        )
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Dictionary will be populated once Layer A rules are finalized.")

# ===========================================================================
# Tab 4: About / Scope
# ===========================================================================
with tab_about:
    st.subheader("About PromptGuard")

    st.markdown(
        """
**Purpose.** 

PromptGuard는 Python LLM/에이전트 애플리케이션이 *LLM을 안전하게 사용하는지* 검사합니다. 프롬프트 자체의 악의성 여부를 판단하는 것이 아니라, **코드 구조와 데이터 흐름**을 조사하여 위험한 `source → sink` 패턴을 포착합니다.

**Detection Philosophy.**

Finding은 "이 코드는 반드시 공격당한다"는 의미가 아닙니다.
Finding은 "LLM 애플리케이션에서 보안적으로 검토해야 할 위험한 source-to-sink 흐름 또는 위험 API 사용 패턴이 존재한다" 는 의미입니다.
- LLM01: prompt 내용의 악의성이 아닌, 외부 콘텐츠가 LLM prompt로 들어가는 **구조**를 탐지
- LLM05: LLM output이 검증 없이 eval/shell/SQL sink로 전달되는 **구조**를 탐지
- LLM06: agent가 tool을 실제로 호출했는지가 아닌, 고위험 capability가 **연결되어 있는지**를 탐지
- LLM02/07: secret/internal info가 LLM 입력·log·system prompt에 **포함되는 구조**를 탐지
- LLM03: 전체 supply chain audit이 아닌, **unsafe loading pattern**만 탐지

**Analysis method.** 

Python ast 구조 분석 + 간단한 변수 오염 추적(Taint Tracking) + 가벼운 정규식/문자열 휴리스틱 알고리즘을 사용합니다. 별도의 서드파티 스캐너는 필요하지 않습니다.
"""
    )

    st.divider()
    st.subheader("Supported OWASP Cases (LLM Top 10 2025)")

    scope_df = pd.DataFrame(
        OWASP_SCOPE,
        columns=["Case", "Name", "탐지 대상", "탐지하지 않는 것", "Status", "Severity"],
    )
    st.dataframe(scope_df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Status / Severity")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Status** — 정적 분석 결과의 확실성")
        st.markdown("""
| Status | 의미 |
|---|---|
| ❌ vulnerable | 취약한 코드 흐름이 정적으로 확인됨 |
| ⚠️ risky | 위험 가능성이 있으나 단정하기 어려움 |
| ✅ safe | 위험 흐름이 확인되지 않음 (finding 미출력) |
""")

    with col2:
        st.markdown("**Severity** — 실제 악용 시 영향도")
        st.markdown("""
| Severity | 의미 |
|---|---|
| 🟥 critical | 즉각적 명령 실행·파괴·치명적 DB 조작 |
| 🟧 high | 민감정보 노출·위험 권한·remote code 신뢰 |
| 🟨 medium | 외부 콘텐츠 유입·제한적 정보 노출 가능 |
| 🟦 low | 직접 피해 제한적, 설계 개선 필요 |
""")

    st.divider()
    st.subheader("Source / Sink Family")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Source Family (6종)**")
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
        st.markdown("**Sink Family (9종)**")
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
    st.subheader("Required Rule Table (10개)")
    st.caption("MVP에서 반드시 구현하는 10개 rule. detection_type ∈ {ast_taint, ast_search, ast_capability}")

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

    st.divider()
    st.subheader("중복 처리 정책")
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

    st.markdown(
        "> 이 프로토타입은 정적 분석만 수행하며, 입력 코드를 실행하지 않는다. 실제 공격 성공 "
        "여부를 검증하지 않고, 코드 구조상 위험한 source→sink 패턴을 탐지한다."
    )