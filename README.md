# PromptGuard Lite

## 1. 개요
PromptGuard Lite는 Python으로 작성된 LLM/에이전트 앱의 보안 취약점을 정적 분석하는 데모 도구입니다.
코드에서 위험한 source → sink 흐름을 찾아 OWASP LLM Top 10 관점의 위험을 시각화합니다.

## 2. 왜 이 도구가 필요한가
기존의 일반 코드 보안 도구는 LLM 출력 처리, 에이전트 권한, 프롬프트 인젝션 같은 LLM 특화 취약점을 잘 잡지 못합니다.
이 도구는 코드 구조와 데이터 흐름을 분석해 그런 패턴을 빠르게 확인합니다.

## 3. 동작 방식 (레이어 A + 레이어 B)
- 레이어 A: Python AST를 파싱하고 taint 분석을 수행해 위험 흐름을 탐지합니다.
- 레이어 B: 미리 정의된 샘플셋과 레이블을 기준으로 분석 결과를 평가합니다.

## 4. 탐지 패턴
- LLM01: 외부 콘텐츠가 프롬프트로 들어가는 구조
- LLM02/07: 비밀/PII가 프롬프트나 시스템 프롬프트로 흘러가는 구조
- LLM03: unsafe deserialization / trust_remote_code=True
- LLM05: LLM 출력이 eval / shell / SQL sink로 전달되는 구조
- LLM06: 에이전트에 고위험 tool이 연결되는 구조

## 5. 설치 및 실행 방법
```bash
cd /Users/jina/ai-app-security-scanner
python3 -m pip install -r requirements.txt
python3 -m streamlit run app.py --server.headless true --server.address 127.0.0.1 --server.port 8501
```
브라우저에서 http://127.0.0.1:8501 으로 접속합니다.

## 6. 사용 예시
- 샘플 셀렉트 박스에서 예시 코드를 고릅니다.
- Scan 버튼을 눌러 findings를 확인합니다.
- Evaluation 탭에서 정답셋 기준 성능을 확인합니다.

## 7. 평가 결과
최근 검증 결과:
- Precision: 1.00
- Recall: 1.00
- Accuracy: 1.00

## 8. 실태 분석 리포트 요약
- LLM05/06는 코드 구조만으로도 높은 신뢰도로 탐지 가능
- LLM01/02/03는 prompt/message 구조와 secret/PII 흐름을 기준으로 탐지 가능
- safe 샘플은 sanitizer가 분명하면 오탐 없이 처리 가능

## 9. 한계 및 Scope
- 실제 실행은 하지 않고 정적 분석만 수행합니다.
- 복잡한 데이터 흐름, 프롬프트 동적 생성, 외부 라이브러리의 내부 동작은 제한적으로만 반영됩니다.

## 10. 팀 구성
- 분석 엔진 / 샘플셋 설계 / 평가 파이프라인 구성
