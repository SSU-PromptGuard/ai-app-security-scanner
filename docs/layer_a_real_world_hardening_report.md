# Layer A Real-World Hardening Report

## 1. 결론

PromptGuard Lite Layer A의 required rule 10개, Finding/ScanResult 필드, Schema, 공개 API, SHA-1 finding ID 계약을 변경하지 않고 실제 LLM 애플리케이션 패턴을 지원하도록 analyzer 내부를 hardening했다.

수정 대상은 `scanner/analyzer.py`, `scanner/rules.py`, 신규 `tests/test_layer_a_real_world_patterns.py`이다. 시작 시 이미 수정되어 있던 `verify_scanner.py`와 기존 미추적 보고서·테스트·Schema는 보존했다. UI, evaluator, Layer B, `data/**`, `samples/**`, `requirements.txt`는 수정하지 않았다.

## 2. 문제와 변경

| 문제 | Before | After | 주요 함수/상수 |
| ---- | ------ | ----- | -------------- |
| SDK suffix 오인식 | 문자열 suffix가 `fakeclient`까지 허용할 수 있음 | `.` segment tuple을 비교하여 정확한 `client/responses/create`, `client/chat/completions/create`만 허용 | `_endswith_segments`, `_is_known_llm_call`, `OPENAI_SDK_CALL_SEGMENTS` |
| 모든 `.execute()` SQL 오인식 | unrelated receiver도 SQL sink | receiver 마지막 segment/role과 method allowlist를 함께 요구 | `_is_sql_execute_call`, `SQL_EXEC_SUFFIXES` |
| allowlist mutation 후 safe 유지 | 최초 literal 상태만 봄 | subscript assign, update, setdefault, `|=`, delete에서 safe 상태 무효화 | `_invalidate_safe_mapping`, `_apply_container_mutation`, `_handle_delete_target` |
| LLM02/LLM07 broad suppression | container에 system 문자열이 있으면 다른 secret도 억제 가능 | `(kind, source, line)` secret identity와 privileged/ordinary flow를 분리 | `_secret_usage`, `privileged_secrets`, `nonprivileged_secrets` |
| Name-only assignment | attribute/subscript taint 소실 | Name, Attribute, constant string/int Subscript canonical key 지원 | `_canonical_key`, `_bind_target` |
| loop/comprehension taint 소실 | target binding 없음 | for/async for, list/set/dict comprehension, generator, unpacking, walrus, AugAssign 지원 | `_eval_comprehension`, `_bind_target`, `_bind_named_expressions` |
| nested capability 혼입 | nested unused helper의 위험 call을 outer tool에 귀속 | nested function/async function/lambda/class scope 제외 | `_walk_function_scope` |
| 모든 `.invoke()`를 LLM으로 보기 어려움 | receiver type 근거 부족 | constructor/factory/method result/assignment/LCEL 기반 lightweight role registry | `_infer_roles`, `_roles_for_expr` |
| LLM input/output 기준 불일치 | 별도 call family 로직 | 동일한 `_is_known_llm_call` 사용 | `_is_llm_input_call`, `_is_llm_output_call` |
| output extraction 이름 heuristic | `output_text` 이름만으로 source 가능 | 상위 object가 LLM output일 때만 attribute/subscript로 전파 | `_classify_source`, `_eval_taints` |
| RAG source 부족 | 제한된 loader/retrieval suffix | loader, retriever, vector store, query engine role 기반 분류 | `LOADER_METHODS`, `RETRIEVER_METHODS`, `VECTOR_STORE_METHODS`, `QUERY_ENGINE_METHODS` |
| unknown transform가 sanitizer처럼 동작 | 일부 call 결과에서 taint 소실 | receiver/argument taint 보수 전파, literal replacement만 sanitizer | `_taints_from_call_inputs`, `_is_masking_literal` |
| agent tool 패턴 부족 | 일부 LangChain pattern만 인식 | FunctionTool, create_agent, SomeAgent.from_tools 등 제한 확장 | `_resolve_tool_expr`, `_is_agent_binding_call` |
| shell/SQL family 부족 | 일부 sink만 포함 | `os.popen`, asyncio subprocess, SQLAlchemy `text(query)` 지원 | `SHELL_EXEC_CALLS`, `_sql_literal_text` |
| import alias 미지원 | alias sink/source 누락 | 현재 파일의 직접 import/module/function alias만 해석 | `_collect_import_aliases`, `_resolve_name` |
| confidence 승격 위험 | provenance cap 부족 | source/role cap과 rule default의 최솟값 사용 | `Taint.confidence_cap`, `_llm_call_confidence_cap`, `_confidence_for_taint` |

## 3. FP/FN trade-off

- Receiver role이 불명확한 `.invoke`, `.run`, `.stream`, `.execute`는 finding을 만들지 않는다.
- `llm`, `chain`, `agent`의 기존 exact receiver 계약은 유지한다.
- 새 variable-name fallback(`model`, `rag_chain`, `retriever`, `query_engine` 등)은 substring이 아니라 마지막 segment exact match이며 confidence를 최대 0.6으로 제한한다.
- unknown transformation은 sanitizer로 보지 않고 argument와 receiver taint를 보수적으로 유지한다.
- shell fixed allowlist는 literal mapping이 mutation되는 순간 safe 상태를 폐기한다.
- SQL은 query 첫 인자 구조만 검사하므로 parameterized value로 전달된 LLM output은 기존대로 non-trigger다.
- privileged keyword는 Responses `instructions` 및 알려진 agent factory의 `system_prompt`로 제한하여 unrelated keyword FP를 막는다.

## 4. 지원 범위

- Python 단일 파일 AST
- function-local shallow taint
- Name/Attribute/constant Subscript canonical binding
- 제한된 constructor/factory/method role
- 직접 import alias
- shallow container mutation 및 comprehension/loop propagation
- 등록되고 agent 실행 구조에 연결된 tool capability

## 5. 미지원 범위

다음은 기존 아키텍처 제한이며 이번 hardening에서 새로 주장하지 않는다.

- full CFG 및 path sensitivity
- 완전한 inter-procedural/call graph 분석
- inter-file/repository analysis
- wildcard/re-export/dynamic import alias 해석
- 동적 subscript key 및 일반 alias graph
- 모든 프레임워크 객체 타입 추론
- nested helper가 실제 호출되는지 판정하는 call graph
- optional rule, UI/evaluator/Layer B 전환

## 6. 호환성

- required rule: 정확히 10개 유지
- rule metadata: ID/category/detection/source/sink/status/severity 불변
- confidence 값: `{0.9, 0.75, 0.6}` 유지
- Finding/ScanResult/summary 필드 불변
- `scan_code`, `scan_file`, `analyze_code` 반환 계약 불변
- JSON Schema 불변
- 기존 safe sample 및 required sample 동작 유지

## 7. Rollback

이번 hardening은 `scanner/analyzer.py`, `scanner/rules.py`, `tests/test_layer_a_real_world_patterns.py`와 본 작업의 신규 문서·artifact만 대상으로 한다. 자동 commit은 만들지 않았다. Rollback이 필요하면 이 작업에서 추가된 변경만 역패치해야 하며, 시작 시 존재하던 `verify_scanner.py` 및 기타 working tree 변경은 보존해야 한다.

