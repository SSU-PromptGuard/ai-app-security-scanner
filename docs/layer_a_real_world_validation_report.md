# Layer A Real-World Validation Report

## 1. 최종 판정

`PASS WITH MINOR ISSUES`

Blocker와 Major는 발견되지 않았다. required rule/API/Schema 회귀 없이 P0 Major 재현과 신규 real-world pattern matrix가 통과했으므로 Layer A 코드 동결이 가능하다. Minor는 명시된 shallow/static-analysis 한계이며 이번 지원 주장과 충돌하지 않는다.

## 2. 환경과 기준

| 항목 | 값 |
| ---- | -- |
| OS/Shell | Windows / PowerShell |
| Python | 3.12.2 |
| Branch | `fix/layer-a-report-alignment` |
| HEAD | `fd0f8c656e22bf1deefadb95509dec9515e0df8d` |
| 기준 log | `fd0f8c6`, `c78e1c2`, `3890393` |

검증은 dirty working tree를 보존한 상태에서 수행했다. 자동 commit, push, merge, reset은 실행하지 않았다.

## 3. 실행 명령과 결과

| 명령 | Exit | 결과 |
| ---- | ---- | ---- |
| `python --version` | 0 | Python 3.12.2 |
| `python -m py_compile scanner/models.py scanner/rules.py scanner/analyzer.py scanner/__init__.py verify_scanner.py` | 0 | PASS |
| `python verify_scanner.py` | 0 | required metadata, 13 parse sample, 10 smoke sample, 3 safe sample, inline regression 전부 PASS |
| `python -m unittest discover -s tests -p "test_layer_a_*.py" -v` | 0 | 47 tests PASS |
| `python -m compileall scanner` | 0 | PASS |
| Schema adversarial inline runner | 0 | valid 3종 통과, invalid 9종 거부, category enum 6개 |
| `git diff --check` | 0 | 오류 없음 |
| `git status --short` | 0 | dirty tree 보존; 금지 scope 신규 변경 없음 |
| `git diff --stat` | 0 | tracked diff 확인 |
| `git diff --name-only` | 0 | tracked: analyzer/rules 및 시작 시 이미 수정된 verify_scanner |

컴파일이 생성한 추적/미추적 `__pycache__`만 시작 상태로 복구·제거한 뒤 최종 scope 명령을 실행했다.

## 4. 기존 회귀

| 항목 | 결과 | 근거 |
| ---- | ---- | ---- |
| required rule 정확히 10개 | PASS | contract test 및 verify_scanner |
| required samples | PASS | 10/10 expected rule |
| safe samples | PASS | 3/3 no findings |
| parse error ScanResult | PASS | contract test |
| empty summary zero keys | PASS | contract test |
| Finding/ScanResult fields | PASS | dataclass field contract |
| SHA-1 finding ID 안정성 | PASS | source/sink 변경 및 반복 실행 test |
| deterministic order | PASS | repeated scan test |
| JSON Schema serialization | PASS | contract + jsonschema runtime |
| fake sanitizer/re.sub | PASS | contract + real-world sanitizer matrix |
| unrelated invoke | PASS | exact receiver negative matrix |
| fixed shell allowlist | PASS | unchanged mapping non-trigger |
| parameterized SQL | PASS | value-only output non-trigger |
| LLM07 dedup/distinct prompt | PASS | existing contract |

## 5. P0 Major 재현

| 재현 | 예상 | 결과 |
| ---- | ---- | ---- |
| exact SDK client segment | positive | PASS |
| fakeclient/not_client | negative | PASS |
| SQL allowed receiver/method | positive | PASS |
| executor/workflow/task execute | negative | PASS |
| SQLAlchemy `text(query)` | positive | PASS |
| allowlist assign/update/setdefault/`|=`/delete mutation | invalidated and trigger | PASS |
| separate system/user secret | LLM07 + LLM02 | PASS |
| same privileged secret | LLM07 only | PASS |
| Attribute/Subscript assignment | taint retained | PASS |
| for/comprehension/generator/unpack | taint retained | PASS |
| unused nested destructive helper | no outer LLM06 | PASS |

## 6. Real-world pattern 검증

신규 `tests/test_layer_a_real_world_patterns.py`는 21개 test method와 다수 subtest로 다음을 검증한다.

- SDK positive/negative segment boundary
- model/chain/agent role 및 LCEL
- async/stream/batch family의 공통 call 판정
- loader/retriever/vector store/query engine 분리
- LLM output attribute/subscript extraction
- Name/Attribute/Subscript 및 container mutation
- walrus/AugAssign/comprehension/generator/for
- receiver-aware SQL 및 parameterized value negative
- allowlist mutation 전 종류
- LLM02/LLM07 identity/role suppression
- developer/system/instructions flow
- agent tool 등록과 실제 binding의 구분
- nested scope capability 제외
- Hugging Face trust flag
- direct import alias
- sanitizer literal policy
- asyncio subprocess argument 검사
- SQL SELECT/write agent capability 구분

각 test는 rule ID, finding 수, source_kind, sink_kind, confidence를 확인한다.

## 7. Schema/API 호환성

실제 `jsonschema` runtime 검증 결과:

- safe ScanResult: 통과
- finding ScanResult: 통과
- parse-error ScanResult: 통과
- invalid category/status/severity/source_kind/sink_kind: 거부
- confidence -0.1/1.1: 거부
- extra property: 거부
- summary `low` key 누락: 거부
- category enum: 정확히 6개

공개 모델과 `schemas/result_schema.json`은 수정하지 않았다.

## 8. Scope 검사

이번 hardening에서 변경하거나 생성한 허용 범위:

- `scanner/analyzer.py`
- `scanner/rules.py`
- `tests/test_layer_a_real_world_patterns.py`
- `docs/layer_a_real_world_*.md`
- `artifacts/layer_a_real_world_*`

수정하지 않은 금지 범위:

- `app.py`, UI
- evaluator
- `engine/layer_b.py`
- `data/**`
- `samples/**`
- `requirements.txt`
- 기존 결과보고서 원본 및 발표자료

`verify_scanner.py`, 기존 docs/tests/schema 및 ChatGPT 전달 폴더는 작업 시작 시 이미 dirty/untracked였으며 삭제하거나 되돌리지 않았다.

## 9. 발견 이슈

### Blocker

없음.

### Major

없음.

### Minor

1. branch/path merge가 없는 shallow environment이므로 분기별 정확한 kill/gen 판정은 하지 않는다.
2. 동적 subscript key와 일반 object alias graph는 추적하지 않는다.
3. nested helper가 outer tool에서 실제 호출되는지는 call graph가 없어 판정하지 않는다. 이번 계약대로 nested body를 outer capability에서 제외한다.
4. unqualified constructor와 모든 제3자 framework subtype을 완전히 구분하지 않는다. 직접 import alias와 명시된 constructor/factory만 우선한다.

### Informational

- role은 내부 판정 근거이며 Finding/Schema에는 노출하지 않는다.
- weak exact-name fallback은 confidence 0.6 cap을 적용한다.
- compile/test cache는 최종 working tree에서 제거했다.

## 10. 코드 동결 여부

동결 가능.

필수 계약, P0 재현, P1 real-world pattern, required/safe regression, Schema runtime validation이 모두 통과했다. 위 Minor는 요청에 명시된 single-file shallow AST 범위의 한계이며 현재 지원한다고 주장하는 동작의 실패가 아니다.

