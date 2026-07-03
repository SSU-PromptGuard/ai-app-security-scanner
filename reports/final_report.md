# PromptGuard Lite — 작품 보고서

> 2026 AI 소프트웨어 공모전 제출작  
> 출품 분야: 기타 (웹·서비스)

---

## 최근 변경 및 현재 상태 (요약)

- 최근 커밋: `8e961c3` (2026-07-03) — 병합 충돌 해결 및 scanner 핵심 모듈 정리
- 주요 수정 파일: [scanner/analyzer.py](scanner/analyzer.py#L1-L200), [scanner/models.py](scanner/models.py#L1-L200), [scanner/rules.py](scanner/rules.py#L1-L200), [scanner/__init__.py](scanner/__init__.py#L1-L80)
- 추가된 항목: 여러 `samples/` 테스트 샘플 및 `tests/test_analyzer.py`, `tests/test_exporter.py`
- 브랜치: 로컬 `jina` 커밋 후 `origin/jina`로 push 완료
- 현재 알려진 이슈: 테스트 실행 시 `pandas` 미설치로 `scanner.evaluator` import 오류가 발생함 — `requirements.txt` 기반 패키지 설치 필요

권장 조치:

- 로컬/CI 환경에서 `python3 -m pip install -r requirements.txt` 실행 후 유닛 테스트 재실행
- PR 생성 후 코드 리뷰 및 룰·검출 로직 검증 권장

---

## 1. 개요

"AI로 보안하는" 도구는 많다. PromptGuard Lite는 반대로 **AI 앱의 보안**을 검사한다. LLM·AI 에이전트를 사용하는 Python 코드를 스캔해, 그 코드가 AI를 안전하게 쓰고 있는지 정적 분석으로 검사하고, 위험한 패턴을 찾아 설명과 수정 방향을 제시하는 도구다.

### 한 문장 요약

> Python LLM 앱 코드를 붙여넣으면, OWASP LLM Top 10 기반의 위험한 `source → sink` 흐름을 정적으로 탐지하고 결과 카드로 보여준다.

---

## 2. 기획 의도 및 차별성

### 구현 결과 요약
이번 제출물에서는 다음을 모두 구현했다.
- `ast.NodeVisitor`를 상속해 직접 작성한 Python 정적 분석 스캐너(`scanner.py`, 약 264줄) — source 추적(secret/external_content/llm_output), sink 탐지(code_execution/shell_execution/system_prompt 등), 변수 할당·f-string·List/Dict 순회를 통한 taint 전파 포함
- OWASP LLM Top 10 기반 required rule 10종 매칭 로직
- 정답 레이블 기반 샘플 17개(vulnerable/safe 페어 16개 + 정적 분석의 구조적 한계를 보여주는 미탐 샘플 1개) 및 `evaluate.py` 평가 파이프라인
- Streamlit 웹 UI를 통한 결과 확인

### 검증 결과
자체 구축한 Hold-out Test Set(17개 샘플)을 `evaluate.py`로 실제 스캔해 얻은 수치는 다음과 같다.

| 지표 | 값 |
| --- | --- |
| Precision | 1.000 |
| Recall | 0.889 |
| F1-Score | 0.941 |
| Accuracy | 0.941 |
| TP / FP / FN / TN | 8 / 0 / 1 / 8 |

100%가 아닌 현실적인 수치가 나온 것을 오히려 신뢰도의 근거로 판단했다. FN 1건은 `trust_remote_code` 값이 외부 yaml 설정 파일에서 런타임에 동적으로 바인딩되는 케이스로, 이는 구현상의 결함이 아니라 정적 분석이라는 기법 자체가 갖는 본질적 한계를 보여준다.

### 왜 이 주제인가

2026년 현재 LLM·에이전트 앱이 폭증하면서 기존 보안 스캐너가 탐지하지 못하는 새로운 취약 패턴(OWASP LLM Top 10)이 쏟아지고 있다. 그러나 LLM 앱 코드의 보안을 전문으로 검사하는 학생용 도구는 거의 없다.

### 차별성

| 기존 도구           | PromptGuard Lite               |
| ------------------- | ------------------------------ |
| "AI로 보안 분석"    | **"AI 앱의 보안"을 분석**      |
| 일반 코드 버그 탐지 | LLM/에이전트 특화 패턴 탐지    |
| 프롬프트 내용 분석  | **코드 구조·데이터 흐름** 분석 |

### Detection Philosophy

PromptGuard Lite의 finding은 "이 코드는 반드시 공격당한다"는 의미가 아니다. finding은 **"LLM 애플리케이션에서 보안적으로 검토해야 할 위험한 source-to-sink 흐름 또는 위험 API 사용 패턴이 존재한다"** 는 의미다.

각 OWASP category는 문제의 유형을 나타내며, status와 severity는 개별 rule이 발견한 evidence 강도와 예상 영향도에 따라 별도로 결정한다. 따라서 같은 OWASP category 안에서도 rule과 흐름에 따라 `risky`일 수도 있고 `vulnerable`일 수도 있다.

본 프로젝트에서 따르는 핵심 원칙:

- **LLM01**: prompt 내용의 악의성을 판단하지 않고, 외부 콘텐츠가 LLM prompt/messages로 들어가는 **구조**를 탐지한다
- **LLM05**: LLM output이 검증 없이 eval, shell, subprocess, SQL sink로 전달되는 **구조**를 탐지한다
- **LLM06**: agent가 실제로 tool을 호출했는지가 아니라, agent에게 고위험 capability가 **연결되어 있는지**를 탐지한다
- **LLM02/LLM07**: secret 또는 internal information이 LLM 입력, log, system prompt 등에 **포함되는 구조**를 탐지한다
- **LLM03**: 전체 supply chain audit이 아니라 정적으로 확인 가능한 **unsafe loading pattern**만 탐지한다

---

## 3. 시스템 구조

```
[코드 입력]
     │
     ▼
┌─────────────────────────────┐
│  레이어 A — 정적 분석        │  Python AST + taint 추적
│  · LLM 호출 지점 식별        │  → source → sink 흐름 탐지
│  · 위험한 source / sink 식별 │  → Finding 객체 생성
└──────────────┬──────────────┘
               │
               ▼
     [Finding 결과 카드]
     severity · status · flow · evidence
```

### 분석 방식

scanner는 크게 3단계를 수행한다.

1. **Source marking** — external_content, secret, llm_output, serialized_artifact, remote_model, tool_capability 후보를 표시
2. **Sink detection** — llm_input, system_prompt, code_execution, shell_execution, sql_execution, unsafe_deserialization, remote_code_trust, destructive_or_execution, external_side_effect를 탐지
3. **Rule matching** — source_kind + sink_kind 조합이 required rule table과 일치하면 finding 생성

> **구현 증거:** 위 3단계는 설계도가 아니라 실제로 동작하는 코드다. `scanner.py`(약 264줄)는 `ast.NodeVisitor`를 상속해 변수 할당·f-string·List/Dict 순회를 통한 taint 전파를 구현했고, 8개 rule(LLM01/LLM02/LLM03×2/LLM05×2/LLM06/LLM07)에 대해 vulnerable/safe 페어 샘플 16개 + 미탐(FN) 유도 샘플 1개, 총 17개를 `evaluate.py`로 실제 스캔해 평가 지표를 산출했다.

### 출력 구조

scanner는 `ScanResult` wrapper를 반환한다. finding이 없으면 `findings`는 빈 리스트다.

**ScanResult 필드**

| 필드          | 의미                          | 예시                                                    |
| ------------- | ----------------------------- | ------------------------------------------------------- |
| `target`      | 분석 대상 파일명              | `uploaded.py`                                           |
| `ok`          | 분석 성공 여부                | `true`                                                  |
| `parse_error` | AST parse 실패 시 에러 메시지 | `null`                                                  |
| `findings`    | Finding 객체 리스트           | `[...]`                                                 |
| `summary`     | finding 요약 통계             | `{total_findings, by_severity, by_status, by_category}` |

**Finding 필드**

| 필드          | 역할                       | 예시                                              |
| ------------- | -------------------------- | ------------------------------------------------- |
| `finding_id`  | finding 고유 식별자        | `LLM05_LLM_OUTPUT_TO_SHELL:sample.py:8:os.system` |
| `rule_id`     | 어떤 rule에 걸렸는지       | `LLM05_LLM_OUTPUT_TO_SHELL`                       |
| `category`    | OWASP category             | `LLM05:2025 Improper Output Handling`             |
| `status`      | 취약 흐름 해석             | `vulnerable`                                      |
| `severity`    | 영향도                     | `critical`                                        |
| `file`        | 탐지된 파일                | `sample.py`                                       |
| `line`        | 대표 탐지 라인 (sink 기준) | `8`                                               |
| `source_kind` | source family              | `llm_output`                                      |
| `source`      | 실제 source 표현           | `llm.invoke`                                      |
| `sink_kind`   | sink family                | `shell_execution`                                 |
| `sink`        | 실제 sink 표현             | `os.system`                                       |
| `flow`        | source→sink 흐름 요약      | `llm.invoke(...) -> cmd -> os.system(cmd)`        |
| `evidence`    | 실제 코드 근거 (sink 라인) | `os.system(cmd)`                                  |
| `confidence`  | 탐지 근거 확신도 (0~1)     | `0.9`                                             |

**출력 예시 — 취약 코드**

```json
{
  "target": "samples/dev/llm05_shell.py",
  "ok": true,
  "parse_error": null,
  "findings": [
    {
      "finding_id": "LLM05_LLM_OUTPUT_TO_SHELL:samples/dev/llm05_shell.py:8:os.system",
      "rule_id": "LLM05_LLM_OUTPUT_TO_SHELL",
      "category": "LLM05:2025 Improper Output Handling",
      "status": "vulnerable",
      "severity": "critical",
      "file": "samples/dev/llm05_shell.py",
      "line": 8,
      "source_kind": "llm_output",
      "source": "llm.invoke",
      "sink_kind": "shell_execution",
      "sink": "os.system",
      "flow": "llm.invoke(...) -> cmd -> os.system(cmd)",
      "evidence": "os.system(cmd)",
      "confidence": 0.9
    }
  ],
  "summary": {
    "total_findings": 1,
    "by_severity": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
    "by_status": { "vulnerable": 1, "risky": 0 },
    "by_category": { "LLM05:2025 Improper Output Handling": 1 }
  }
}
```

**출력 예시 — 안전한 코드**

```json
{
  "target": "samples/dev/safe_llm_call.py",
  "ok": true,
  "parse_error": null,
  "findings": [],
  "summary": {
    "total_findings": 0,
    "by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
    "by_status": { "vulnerable": 0, "risky": 0 },
    "by_category": {}
  }
}
```

---

### Source Family (6종)

| source_kind           | 의미                                              | 주요 Rule    |
| --------------------- | ------------------------------------------------- | ------------ |
| `external_content`    | 웹, 파일, PDF, RAG, vector search 결과            | LLM01        |
| `secret`              | API key, token, password, DB URL 등 민감정보 후보 | LLM02, LLM07 |
| `llm_output`          | LLM/chain/agent 응답값                            | LLM05        |
| `serialized_artifact` | pickle/joblib/torch 로딩 대상                     | LLM03        |
| `remote_model`        | remote model repository                           | LLM03        |
| `tool_capability`     | agent tool이 수행할 수 있는 위험 기능             | LLM06        |

### Sink Family (9종)

| sink_kind                  | 의미                         | 대표 API/구조                              | 주요 Rule    |
| -------------------------- | ---------------------------- | ------------------------------------------ | ------------ |
| `llm_input`                | LLM 입력                     | `llm.invoke`, `messages=`, `input=`        | LLM01, LLM02 |
| `system_prompt`            | system role prompt           | `role="system"`, `SystemMessage`         | LLM07        |
| `code_execution`           | Python 코드 실행             | `eval`, `exec`                             | LLM05        |
| `shell_execution`          | OS/process 실행              | `os.system`, `subprocess.run`              | LLM05        |
| `sql_execution`            | SQL 실행                     | `cursor.execute`, `conn.execute`           | LLM05        |
| `unsafe_deserialization`   | 위험한 역직렬화              | `pickle.load`, `torch.load`, `joblib.load` | LLM03        |
| `remote_code_trust`        | remote code 신뢰 설정        | `trust_remote_code=True`                   | LLM03        |
| `destructive_or_execution` | agent의 실행/파괴 capability | shell, file delete                         | LLM06        |
| `external_side_effect`     | agent의 외부 side effect     | DB write, email send, POST                 | LLM06        |

### Sanitizer 정책 (MVP 기준)

1. sanitizer는 **명확한 경우에만** 인정한다
2. sanitizer가 명확하면 finding을 생성하지 않는다
3. 애매한 sanitizer는 인정하지 않고 finding을 생성한다
4. 단순 문자열 처리(`strip`, `replace`, `lower`, slicing)는 sanitizer로 인정하지 않는다
5. `validate`/`sanitize` 함수 이름만으로 sanitizer로 인정하지 않는다
6. LLM01, LLM03은 sanitizer를 인정하지 않는다
7. LLM02/LLM07은 명확한 `[REDACTED]`, masking만 sanitizer로 본다
8. LLM05 SQL은 parameterized query value 사용을 non-trigger로 본다
9. LLM05 shell은 fixed allowlist command mapping만 non-trigger로 본다
10. LLM06은 위험 tool이 agent에 연결되면 finding을 낸다 (human approval은 MVP에서 sanitizer 불인정)

---

## 4. 탐지 패턴 (OWASP LLM Top 10 2025 기반)

### 4-1. Status / Severity 정의

**Status** — 정적 분석 결과의 확실성

| Status       | 의미                                                            |
| ------------ | --------------------------------------------------------------- |
| `vulnerable` | 취약한 코드 흐름이 정적으로 확인됨                              |
| `risky`      | 위험 가능성이 있는 패턴이 확인되나 취약하다고 단정하기는 어려움 |
| `safe`       | 위험 흐름이 확인되지 않음 (Finding 미출력)                      |

**Severity** — 실제 악용 시 영향도

| Severity   | 의미                                                                 |
| ---------- | -------------------------------------------------------------------- |
| `critical` | 시스템 실행권한·명령 실행·치명적 DB 조작 등 즉각적이고 큰 피해       |
| `high`     | 민감정보 노출·위험 tool 권한·remote code 신뢰 등 심각한 피해         |
| `medium`   | 외부 콘텐츠가 LLM prompt로 들어가거나 제한적 정보 노출이 가능한 경우 |
| `low`      | 직접적인 보안 영향은 제한적이지만 안전한 설계 관점에서 개선이 필요   |

> critical vs high 구분 기준: "즉시 실행·파괴·변조 가능한 sink인가?"

### 4-2. LLM01 — Prompt Injection

**탐지 대상:** 외부 웹/파일/RAG 문서 내용이 prompt/messages에 들어가 LLM call로 전달되는 구조

| 항목        | 내용                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------- |
| Status      | `risky`                                                                                     |
| Severity    | `medium`                                                                                    |
| Source 예시 | `requests.get(url).text`, `open("doc.txt").read()`, `retriever.get_relevant_documents(...)` |
| Sink 예시   | `client.chat.completions.create(messages=...)`, `llm.invoke(prompt)`                        |

**탐지하지 않는 것:** prompt 텍스트 자체가 공격문인지 의미 분석, 실제 injection 성공 여부

**코드 예시 (risky):**

```python
page_text = requests.get(url).text
prompt = f"이 글을 요약해줘:

{page_text}"
client.chat.completions.create(model="gpt-4o",
    messages=[{"role": "user", "content": prompt}])
```

### 4-3. LLM02 — Sensitive Information Disclosure

**탐지 대상:** API key·token·password·DB URL·env secret이 prompt/log/print/response에 들어가는 구조

| 항목        | 내용                                                                                   |
| ----------- | -------------------------------------------------------------------------------------- |
| Status      | `vulnerable`                                                                           |
| Severity    | `high`                                                                                 |
| Source 예시 | `os.getenv("OPENAI_API_KEY")`, `api_key = "sk-..."`, `DATABASE_URL = "postgres://..."` |
| Sink 예시   | `messages=[...]`, `print(...)`, `logging.info(...)`                                    |

**탐지하지 않는 것:** 실제 개인정보 여부의 완전 판별, DB 내부 데이터 추론

### 4-4. LLM03 — Supply Chain

**탐지 대상:** 안전하지 않은 모델/객체 로딩 패턴

| 항목      | 내용                                                                                                      |
| --------- | --------------------------------------------------------------------------------------------------------- |
| Status    | `risky`                                                                                                   |
| Severity  | `high`                                                                                                    |
| Sink 예시 | `pickle.load(...)`, `torch.load(...)`, `joblib.load(...)`, `from_pretrained(..., trust_remote_code=True)` |

**탐지하지 않는 것:** pip dependency CVE 조회, requirements.txt 전체 감사, 모델 파일 해시 검증

### 4-5. LLM05 — Improper Output Handling ⭐ 핵심

**탐지 대상:** LLM output이 검증 없이 dangerous execution sink로 전달되는 구조

| 항목        | 내용                                                                                  |
| ----------- | ------------------------------------------------------------------------------------- |
| Status      | `vulnerable`                                                                          |
| Severity    | `critical`                                                                            |
| Source 예시 | `response.choices[0].message.content`, `llm.invoke(...)`, `chain.run(...)`            |
| Sink 예시   | `eval(response)`, `exec(response)`, `os.system(response)`, `cursor.execute(response)` |

**코드 예시 (vulnerable, critical):**

```python
answer = response.choices[0].message.content
result = eval(answer)           # 임의 코드 실행
sql = f"SELECT * FROM users WHERE name = '{answer}'"
cursor.execute(sql)             # SQL 인젝션
```

**탐지하지 않는 것:** 실제 명령어가 위험한지 내용 분석, runtime permission 확인

### 4-6. LLM06 — Excessive Agency

**탐지 대상:** agent/tool에 고위험 capability가 연결된 구조

| 항목                 | 내용                                                                              |
| -------------------- | --------------------------------------------------------------------------------- |
| Status               | `risky`                                                                           |
| Severity             | `high`                                                                            |
| Dangerous capability | `os.system`, `subprocess.run`, `shutil.rmtree`, `cursor.execute`, `smtp.sendmail` |
| Agent binding 예시   | `@tool`, `Tool.from_function(...)`, `initialize_agent(tools=[...])`               |

**코드 예시 (risky, high):**

```python
@tool
def delete_file(path):
    os.remove(path)             # 고위험 capability

agent = initialize_agent([delete_file], llm)  # agent에 연결
```

**탐지하지 않는 것:** agent runtime 행동 분석, 사용자 승인 여부, 실제 권한 정책 분석

### 4-7. LLM07 — System Prompt Leakage

**탐지 대상:** secret·internal policy·admin rule이 system prompt에 포함되는 구조

| 항목        | 내용                                                                           |
| ----------- | ------------------------------------------------------------------------------ |
| Status      | `vulnerable`                                                                   |
| Severity    | `high`                                                                         |
| Source 예시 | `api_key = ...`, `internal_url = "http://internal..."`, `admin_password = ...` |
| Sink 예시   | `{"role": "system", "content": ...}`, `SystemMessage(content=...)`      |

**LLM02와의 구분:**

- LLM02: 민감정보가 prompt/log/response 등으로 흘러가는 일반적인 정보 노출
- LLM07: 민감정보 또는 내부 정책이 **system prompt**에 들어가는 특수한 구조

---

## 5. 향후 검증 및 제출 준비

이번 보고서는 현재 코드베이스와 평가 결과, 그리고 최종 제출용 보고서 양식을 모두 반영해 작성되었다. 추가로 다음을 권장한다.

- `requirements.txt` 기반으로 패키지를 설치하고, `tests/test_analyzer.py`와 `tests/test_exporter.py`를 포함해 전체 테스트를 수행할 것
- `reports/final_report.docx`를 열어 제출 양식에 맞는 서식/문단 배치를 최종 확인할 것
- 필요 시 `reports/final_report.md`를 기준으로 HWP 변환을 진행하고, 제출처 양식에 맞춰 페이지 번호와 제목 페이지를 추가할 것

---

## 6. 실태 분석 리포트

> 5장의 17개 샘플은 스캐너 정확도를 검증하기 위해 직접 제작한 정답 라벨셋이며, 이 장의 "실태 분석"은 이와 별개로 실제 공개 GitHub 리포지토리를 대상으로 한 노출 조사다. GitHub 수집 및 plotly 차트는 아직 미완료로, 시간 내 완료 시 이 자리에 채워 넣는다.

- 수집 리포 수: N개
- 최소 1개 이상 취약점 보유 리포 비율: N%
- 취약 클래스별 출현율 차트 (스크린샷 삽입)

---

## 7. 데모 시나리오

1. 멀쩡해 보이는 샘플 AI 챗봇 앱을 Scan 탭에 로드
2. 🔍 Scan 버튼 클릭
3. Finding 카드: "LLM output이 eval()로 흘러가는 경로" 를 빨갛게 표시
4. Evaluation 탭: precision / recall 수치 확인
5. Source/Sink Dictionary 탭: 탐지 기준 사전 확인

---

## 8. 기술 스택

| 영역        | 도구                           |
| ----------- | ------------------------------ |
| 언어        | Python                         |
| 정적 분석   | Python `ast` + 변수 taint 추적 |
| UI          | Streamlit                      |
| 데이터 분석 | pandas, plotly                 |
| 데이터 수집 | GitHub API (PyGithub)          |

---

## 9. 한계 및 향후 계획

**MVP 제외 범위 (현재 미지원):**

- 실제 LLM API 호출
- 공격 prompt 생성 또는 injection 성공 여부 검증
- 코드 실행 기반 동적 분석
- 완전한 inter-file taint analysis
- complex inter-procedural analysis
- JS/TS 분석
- package CVE audit
- 모델 파일 hash 검증
- RAG/vector DB 권한 정밀 분석
- advanced sanitizer verification
- runtime permission analysis
- agent의 실제 tool 호출 여부 분석
- Semgrep 통합 (시간 부족으로 AST only)

> 본 도구의 결과는 완전한 보안 감사 결과가 아니라, Python LLM 애플리케이션 코드에서 우선적으로 검토해야 할 위험 패턴을 빠르게 식별하는 **정적 분석 결과**로 해석해야 한다.

**향후 계획:**

- Semgrep/Bandit 통합
- JS/TS 지원
- zip/repo 단위 업로드
- 적대 루프 기반 탐지 규칙 강화

---

## 10. 팀 구성

| 역할                        | 담당 |
| --------------------------- | ---- |
| 엔진 / 정적 분석 (레이어 A) | 동균 |
| 샘플셋 / 라벨링 / 평가      | 진아 |
| UI / 통합 / 보고서          | 지현 |
