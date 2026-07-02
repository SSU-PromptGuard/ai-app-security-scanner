# FP/FN 분석 메모

## 현재 구현 상태
현재 분석기는 첨부된 샘플셋 기준으로는 매우 높은 성능을 보인다.
최근 검증 결과는 다음과 같다.
- Precision: 1.00
- Recall: 1.00
- Accuracy: 1.00

## 주요 장점
- LLM05의 eval/shell/SQL 패턴은 안정적으로 탐지된다.
- LLM06의 위험 tool 연결도 잘 잡힌다.
- LLM01/02/03의 prompt/message/secret 흐름도 샘플 기준으로 잘 식별된다.

## 주의할 점
- 위 규칙은 정적 AST 기반 휴리스틱이므로, 복잡한 동적 코드나 외부 라이브러리 내부 패턴에는 한계가 있다.
- sanitizer가 모호한 경우에는 false positive 가능성이 있다.

## 향후 확장 아이디어
- allowlist/approval 같은 sanitizer를 더 명시적으로 모델링
- 함수 호출 추적을 더 정교하게 확장
- CLI/CSV export 기능 추가
