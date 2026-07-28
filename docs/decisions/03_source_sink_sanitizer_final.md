# **1\. Source family 확정**

\=\> 우리 프로젝트에서는 모든 user input을 다 src로 보지 않고 LLM 앱 보안에서 의미있는 src만 사용한다. 

1\. external\_content: 외부 웹, 파일, PDF, RAG 문서, vector search 결과처럼 앱 외부에서 들어온 콘텐츠(LLM01 prompt injection의 핵심 src) 

* 적용 rule: LLM01\_EXTERNAL\_CONTENT\_TO\_LLM\_PROMPT  
* why? 외부 문서나 웹페이지 안에는 indirect prompt injection instruction이 포함될 수 있으므로 

2\. secret: API key, token, password, credential, DB URL 등 민감정보 후보 

* 적용 rule: LLM02\_SECRET\_TO\_LLM\_INPUT, LLM07\_SECRET\_IN\_SYSTEM\_PROMPT  
* why? secret이 prompt, messages 등에 들어가면 LLM API 요청, 로그, 디버깅 출력, prompt leakage 등을 통해 노출될 수 있으므로 

3\. llm\_output: llm이 생성한 응답값(LLM05 Impoper Output Handling의 핵심 src) 

* 적용 rule: LLM05\_LLM\_OUTPUT\_TO\_CODE\_EXECUTION, LLM05\_LLM\_OUTPUT\_TO\_SHELL, LLM05\_LLM\_OUTPUT\_TO\_SQL  
* why? LLM output은 신뢰 가능한 코드나 명령어가 아니므로 


4\. serialized\_artifact: pickle, joblib, torch 모델 파일처럼 역직렬화되는 객체 or 모델 artifact 

* 적용 rule: LLM03\_UNSAFE\_DESERIALIZATION  
* why? 직렬화된 객체는 로딩 과정에서 코드 실행 위험이 있을 수 있으므로 


5\. remote\_model: 외부 모델 저장소에서 불러오는 모델 or tokenizer 

* 적용 rule: LLM03\_TRUST\_REMOTE\_CODE\_TRUE  
* why? remote repository의 custom code를 신뢰하고 실행할 수 있으므로 


6\. tool\_capability

* 적용 rule: LLM06\_AGENT\_TOOL\_DESTRUCTIVE\_OR\_EXECUTION, LLM06\_AGENT\_TOOL\_EXTERNAL\_SIDE\_EFFECT  
* why? LLM06은 데이터 흐름이 아니라 권한 흐름인데, agent가 위험한 행위를 수행할 수 있는 권한을 갖게 되므로 


\<최종 source family 표\> 

| source\_kind | 의미 | 주요 rule |
| ----- | ----- | ----- |
| `external_content` | 웹, 파일, PDF, RAG, vector search 결과 | LLM01 |
| `secret` | API key, token, password, DB URL | LLM02, LLM07 |
| `llm_output` | LLM/chain/agent 응답값 | LLM05 |
| `serialized_artifact` | pickle/joblib/torch 로딩 대상 | LLM03 |
| `remote_model` | remote model repository | LLM03 |
| `tool_capability` | agent tool이 수행할 수 있는 위험 기능 | LLM06 |

---

# **2\. Sink family 확정**

\=\> scanner가 어떤 도착점을 위험 sink로 볼 것인가?   
1\. llm\_input: LLM prompt, messages, input, agent input처럼 LLM이 읽는 입력 위치 

* 적용 rule: LLM01\_EXTERNAL\_CONTENT\_TO\_LLM\_PROMPT, LLM02\_SECRET\_TO\_LLM\_INPUT   
* why? 외부 콘텐츠나 secret이 LLM 입력으로 들어가면 indirect prompt injection 또는 sensitive information disclosure 위험이 생길 수 있음


2\. system\_prompt: system role message, SystemMessage, system\_prompt 변수처럼 **모델의 상위 지시문 역할을 하는 prompt 위치**

* 적용 rule: LLM07\_SECRET\_IN\_SYSTEM\_PROMPT   
* why? API key, password, internal credential이 system prompt에 들어가면 prompt leakage, logging, debugging 과정에서 노출될 수 있음


3\. code\_execution: Python 코드 실행 sink

* 적용 rule: LLM05\_LLM\_OUTPUT\_TO\_CODE\_EXECUTION  
* why? LLM output이 eval 또는 exec로 들어가면 임의 Python 코드 실행 위험이 생김


4\. shell\_execution: OS 명령 또는 subprocess 실행 sink 

* 적용 rule: LLM05\_LLM\_OUTPUT\_TO\_SHELL   
* why? LLM output이 shell/process 실행으로 들어가면 명령 실행, 파일 조작, 네트워크 호출 등 시스템 수준 피해로 이어질 수 있음


5\. sql\_execution: SQL query 실행 sink 

* 적용 rule: LLM05\_LLM\_OUTPUT\_TO\_SQL   
* why? LLM output이 SQL query 구조를 만들고 그대로 실행되면 임의 query 실행, 데이터 변조, 삭제, 유출 위험이 생김


6\. unsafe\_deserialization: 직렬화된 객체나 모델 artifact를 위험하게 로딩하는 sink 

* 적용 rule: LLM03\_UNSAFE\_DESERIALIZATION  
* why? pickle, joblib, torch load 계열은 신뢰할 수 없는 artifact를 로딩할 경우 코드 실행 또는 공급망 침해 위험이 있음


7\. remote\_code\_trust: 외부 모델 저장소의 custom code를 신뢰하도록 설정하는 sink 

* 적용 rule: LLM03\_TRUST\_REMOTE\_CODE\_TRUE   
* why?  trust\_remote\_code=True는 remote repository의 custom code를 실행 가능하게 만들 수 있으므로 공급망 위험이 있음


8\. destructive\_or\_execution: agent에게 연결되었을 때 즉시 실행 또는 파괴가 가능한 capability

* 적용 rule: LLM06\_AGENT\_TOOL\_DESTRUCTIVE\_OR\_EXECUTION   
* why? 이 capability를 가진 tool이 agent에 연결되면 agent가 shell 실행, subprocess 실행, 파일 삭제 같은 critical action을 수행할 수 있음


9\. external\_side\_effect: agent가 외부 시스템에 상태 변경, 전송, 요청 같은 side effect를 만들 수 있는 capability 

* 적용 rule: LLM06\_AGENT\_TOOL\_EXTERNAL\_SIDE\_EFFECT  
* why? agent가 email send, DB write, external POST 같은 tool을 사용할 수 있으면 외부 시스템 상태를 바꾸거나 정보를 전송할 수 있음

\<최종 sink familty\>

| sink\_kind | 의미 | 대표 API/구조 | 주요 rule |
| ----- | ----- | ----- | ----- |
| `llm_input` | LLM 입력 | `llm.invoke`, `messages=`, `input=` | LLM01, LLM02 |
| `system_prompt` | system role prompt | `role="system"`, `SystemMessage` | LLM07 |
| `code_execution` | Python 코드 실행 | `eval`, `exec` | LLM05 |
| `shell_execution` | OS/process 실행 | `os.system`, `subprocess.run` | LLM05 |
| `sql_execution` | SQL 실행 | `cursor.execute`, `conn.execute` | LLM05 |
| `unsafe_deserialization` | 위험한 역직렬화/모델 로딩 | `pickle.load`, `torch.load`, `joblib.load` | LLM03 |
| `remote_code_trust` | remote code 신뢰 | `trust_remote_code=True` | LLM03 |
| `destructive_or_execution` | agent의 실행/파괴 capability | shell, file delete | LLM06 |
| `external_side_effect` | agent의 외부 side effect capability | DB write, email send, POST | LLM06 |

---

# **3\. Sanitizer MVP 정책 확정**

1) sanitizer 원칙   
   1\. sanitizer는 명확한 경우에만 인정한다.  
   2\. sanitizer가 명확하면 finding을 생성하지 않는다.  
   3\. 애매한 sanitizer는 인정하지 않고 finding을 생성한다.  
   4\. 단순 문자열 처리(strip, replace, lower, slicing)는 sanitizer로 인정하지 않는다.  
   5\. validate/sanitize라는 함수 이름만으로 sanitizer로 인정하지 않는다.  
   6\. LLM01, LLM03은 MVP에서 sanitizer를 인정하지 않는다.  
   7\. LLM02/LLM07은 명확한 \[REDACTED\], masking만 sanitizer로 본다.  
   8\. LLM05 SQL은 parameterized query value 사용을 non-trigger로 본다.  
   9\. LLM05 shell은 fixed allowlist command mapping만 non-trigger로 본다.  
   10\. LLM06은 human approval/permission check를 정밀 검증하지 않고, 위험 tool이 agent에 연결되면 finding을 낸다.  
     
     
   why? 정적분석에서 sanitizer 검증 자체가 어렵고 함수 이름만 보고 sanitizer로 믿으면 오탐이 아니라 미탐이 생길 수 있으므로 보수적으로 구현(해당 함수가 진짜 안전하고 검증하는 코드인지 실제로 확인해봐야 하므로)   
   

---

# **4\. Required rule별 source/sink/sanitizer 매핑표 확정**

| rule\_id | source\_kind | source family | sink\_kind | sink family | sanitizer / non-trigger 기준 |
| ----- | ----- | ----- | ----- | ----- | ----- |
| `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | `external_content` | `requests.get().text`, `open().read()`, `loader.load()`, `retriever.get_relevant_documents()`, `similarity_search()` | `llm_input` | `llm.invoke`, `chain.invoke`, `agent.run`, `messages=`, `input=`, `prompt=` | MVP에서는 sanitizer 인정하지 않음. 외부 콘텐츠가 LLM input으로 전달되면 finding |
| `LLM02_SECRET_TO_LLM_INPUT` | `secret` | `os.getenv`, `os.environ`, `api_key`, `token`, `password`, `credential`, `DATABASE_URL`, secret-like string | `llm_input` | `prompt`, `messages`, `input`, `llm.invoke`, `client.chat.completions.create` | 명확한 `[REDACTED]`, masking이면 non-trigger. system prompt는 LLM07 우선 |
| `LLM03_UNSAFE_DESERIALIZATION` | `serialized_artifact` | pickle/joblib/torch model or object artifact | `unsafe_deserialization` | `pickle.load`, `pickle.loads`, `joblib.load`, `torch.load` | sanitizer 인정하지 않음. 위험 load API 호출 자체로 finding |
| `LLM03_TRUST_REMOTE_CODE_TRUE` | `remote_model` | remote model repository | `remote_code_trust` | `from_pretrained(..., trust_remote_code=True)` | sanitizer 인정하지 않음. `trust_remote_code=True`면 finding |
| `LLM05_LLM_OUTPUT_TO_CODE_EXECUTION` | `llm_output` | `llm.invoke`, `chain.run`, `agent.run`, `client.responses.create`, `response.output_text` | `code_execution` | `eval`, `exec` | LLM output이 `eval/exec`에 도달하면 finding. 고정 allowlist action mapping은 non-trigger |
| `LLM05_LLM_OUTPUT_TO_SHELL` | `llm_output` | LLM/chain/agent response | `shell_execution` | `os.system`, `subprocess.run`, `subprocess.Popen`, `subprocess.call` | fixed allowlist command mapping이면 non-trigger. `strip`, `replace`, `shlex.quote` 단독은 sanitizer로 인정하지 않음 |
| `LLM05_LLM_OUTPUT_TO_SQL` | `llm_output` | LLM/chain/agent response | `sql_execution` | `cursor.execute`, `conn.execute`, `db.execute`, `session.execute` | parameterized query value로만 사용되면 non-trigger. LLM output이 query structure를 만들면 finding |
| `LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION` | `tool_capability` | `@tool` 함수, `Tool.from_function` 대상 함수 | `destructive_or_execution` | tool 내부의 `os.system`, `subprocess.*`, `os.remove`, `shutil.rmtree`, `Path.unlink` | 위험 capability가 있는 tool이 agent에 연결되면 finding. human approval은 MVP에서 sanitizer로 인정하지 않음 |
| `LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT` | `tool_capability` | `@tool` 함수, `Tool.from_function` 대상 함수 | `external_side_effect` | `smtp.sendmail`, `requests.post/put/delete`, DB write 계열 `execute` | read-only `GET`, 고정 `SELECT`는 non-trigger. write/send/post/delete 계열이면 finding |
| `LLM07_SECRET_IN_SYSTEM_PROMPT` | `secret` | `os.getenv`, `os.environ`, `api_key`, `token`, `password`, `credential`, secret-like string | `system_prompt` | `role="system"`, `SystemMessage`, `system_prompt`, `ChatPromptTemplate.from_messages([("system", ...)])` | 명확한 redaction/masking이면 non-trigger. 일반 user prompt의 secret은 LLM02로 처리 |

\<구현 관점\>  
scanner는 크게 3단계를 수행하면 됨. 

1\. Source marking  
   \- external\_content, secret, llm\_output, serialized\_artifact, remote\_model, tool\_capability 후보를 표시한다.

2\. Sink detection  
   \- llm\_input, system\_prompt, code\_execution, shell\_execution, sql\_execution, unsafe\_deserialization, remote\_code\_trust, destructive\_or\_execution, external\_side\_effect를 찾는다.

3\. Rule matching  
   \- source\_kind와 sink\_kind가 required rule table의 조합과 맞으면 finding을 생성한다.  
   \- 명확한 non-trigger 조건이 있으면 finding을 생성하지 않는다.

