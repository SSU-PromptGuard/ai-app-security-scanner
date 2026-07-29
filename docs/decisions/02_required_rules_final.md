# **1\. Rule metadata 필드 범위 결정**

\*\* scanner 구현과 evaluation 연결에 필요한 최소 정보만 포함 

| 필드 | 필요성 | 예시 |
| ----- | ----- | ----- |
| `rule_id` | rule을 고유하게 식별 | `LLM05_LLM_OUTPUT_TO_SHELL` |
| `category` | OWASP 6개 case 중 어디에 속하는지 | `LLM05:2025 Improper Output Handling` |
| `detection_type` | 어떤 방식으로 탐지할지 | `ast_taint` |
| `source_kind` | 어떤 종류의 source를 보는지 | `llm_output` |
| `sink_kind` | 어떤 종류의 sink를 보는지 | `shell_execution` |
| `status` | 해당 rule이 어떤 status를 갖는지 | `vulnerable` |
| `severity` | 해당 rule이 어떤 severity를 갖는지 | `critical` |

예시:  
{  
    "rule\_id": "LLM05\_LLM\_OUTPUT\_TO\_SHELL",  
    "category": "LLM05:2025 Improper Output Handling",  
    "detection\_type": "ast\_taint",  
    "source\_kind": "llm\_output",  
    "sink\_kind": "shell\_execution",  
    “status": "vulnerable",  
    "severity": "critical"  
}

---

# **2\. 탐지 방식 taxonomy 결정**

**Primary detection\_type:**  
**1\. ast\_search**  
**2\. ast\_taint**  
**3\. ast\_capability**

**Auxiliary mechanism:**  
**4\. regex\_assist**  
**5\. postprocess**

Optional: \-\> 근데 시간 없어서 못할 듯 함.   
6\. semgrep\_optional  
\*\* why? YAML rule 관리 필요, Semgrep CLI 설치 필요, Streamlit에서 subprocess 실행 또는 결과 JSON 파싱 필요, evaluation 기준이 AST와 Semgrep으로 나뉨 등의 파생 문제 발생 

1) ast\_search: AST에서 특정 함수 호출, keyword argument, decorator, import pattern 등을 직접 찾는 방식  
* when?: source→sink 흐름 추적이 필요 없고, **특정 API 사용 자체가 finding인 경우**에 사용   
* 적용 case: LLM03 Supply Chain   
* 예시: 

  pickle.load(...)

  pickle.loads(...)

  torch.load(...)

  joblib.load(...)

  from\_pretrained(..., trust\_remote\_code=True)


2) ast\_taint: 특정 source에서 시작한 값이 변수 할당, f-string, list, dict, function argument 등을 거쳐 sink로 전달되는지 추적하는 방식   
* when? “**어떤 값이 어디로 흘러갔는가?**”가 중요한 경우  
* 적용 case: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM07 System Prompt Leakage   
* 예시:

  LLM output → eval/exec/os.system/subprocess/SQL

  external content → prompt/messages → LLM call

  secret → prompt/messages/log/system prompt


3) ast\_capability: 일반적인 데이터 흐름이 아니라, **agent/tool에 어떤 capability가 연결되는지** 보는 방식  
* when? function, decorator, tool list, agent binding을 봐야 하는 경우(데이터가 sink로 흘러갔다기보다는 agent에게 위험한 권한이 주어졌는지 위주로)   
* 적용 case: LLM06 Excessive Agency  
* 예시: 

  @tool 함수 내부에 os.system 있음

  Tool.from\_function(run\_shell)

  initialize\_agent(tools=\[run\_shell\])

  AgentExecutor(..., tools=\[...\])

  create\_react\_agent(..., tools=\[...\])

   

4) regex\_assist: AST 분석 중 문자열 literal이나 변수명이 secret, internal URL, credential, PII 후보처럼 보이는지 보조적으로 판단하는 방식   
* when? regex\_assist로 secret 후보 식별 \+ ast\_taint로 prompt 도달 확인같은 방식으로 보조적으로 활용(regex\_assist 단독 탐지 x, 후보 식별용)   
* 적용 case: LLM02 Sensitive Information Disclosure, LLM07 System Prompt Leakage  
* 예시: 

  sk-

  xoxb-

  ghp\_

  postgres://

  mysql://

  \-----BEGIN PRIVATE KEY-----

  api\_key

  token

  secret

  password

  credential

  DATABASE\_URL


5) postprocess: AST가 탐지한 raw finding을 마지막에 정리하는 단계   
* 역할: 중복 finding 제거, LLM02/LLM07 우선순위 정리, severity 상향/하향, confidence 조정, 같은 line의 finding 병합  
* 적용 case: 전체   
* 예시: 

  api\_key \= os.getenv("OPENAI\_API\_KEY")

  messages \= \[

      {"role": "system", "content": f"API key: {api\_key}"}

  \]

  \=\> LLM02, 07에 해당하는 경우로 postprocess에서는 07을 우선으로 하고 02를 secondary로 표시하거나 아예 표시하지 않는다(hierarchical 고려) 


\=\> detection\_type ∈ {ast\_search, ast\_taint, ast\_capability}

---

# **3\. case별 detection strategy 매핑**

1) 전체 매핑 요약 

| OWASP case | Primary detection type | Auxiliary | 핵심 분석 대상 |
| ----- | ----- | ----- | ----- |
| LLM01 Prompt Injection | `ast_taint` | source/sink dictionary | 외부 콘텐츠가 prompt/messages/agent input으로 들어가는 흐름 |
| LLM02 Sensitive Information Disclosure | `ast_taint` | `regex_assist` | secret/PII 후보가 LLM input/log/output으로 들어가는 흐름 |
| LLM03 Supply Chain | `ast_search` | keyword arg check | unsafe loading API, `trust_remote_code=True` |
| LLM05 Improper Output Handling | `ast_taint` | sanitizer 후보 확인 | LLM output이 eval/shell/SQL sink로 들어가는 흐름 |
| LLM06 Excessive Agency | `ast_capability` | AST search | dangerous function/tool이 agent에 연결되는 구조 |
| LLM07 System Prompt Leakage | `ast_taint` | `regex_assist`, `postprocess` | secret/internal policy가 system prompt로 들어가는 흐름 |

2) 해당 매핑 근거  
* LLM01 Prompt Injection: 특정 함수가 있다는 사실만으로는 취약점이 되지 않으나, 특정 함수가 실행한 내용이 LLM prompt로 들어가는 등 src \-\> sink 흐름이 나타나는 것을 관찰해야 하므로 ast\_taint 사용 \+ src/sink dictionary   
- src 후보

  \=\> requests.get(...).text

  open(...).read()

  loader.load()

  PyPDFLoader(...)

  WebBaseLoader(...)

  retriever.get\_relevant\_documents(...)

  vectorstore.similarity\_search(...)


- sink 후보

  \=\> llm.invoke(...)

  chain.invoke(...)

  chain.run(...)

  agent.run(...)

  client.chat.completions.create(...)

  client.responses.create(...)

  messages=...

  input=...

  prompt=...


- mvp 전략

  \=\> external content source를 변수에 taint 표시

  → f-string, 문자열 결합, list, dict, messages 구조로 전파

  → LLM call 또는 agent.run에 전달되면 finding


* LLM02 Sensitive Information Disclosure 

  \=\> secret 변수가 있다는 것만으로 finding을 내서는 안되고 이 값이 LLM prompt나 print, response 등으로 흘러가는지까지 봐야 하므로 regex\_assist를 통해 secret 후보를 찾고 ast\_taint를 통해 그것이 LLM input으로 도달하는지까지 확인 

- src 후보

  \=\> os.getenv("...KEY...")

  os.environ\["...TOKEN..."\]

  변수명: api\_key, token, secret, password, credential, db\_url

  문자열: sk-..., ghp\_..., xoxb-..., postgres://..., mysql://...


- sink 후보 

  \=\> prompt/messages/input

  llm.invoke(...)

  client.chat.completions.create(...)

  print(...)

  logging.info(...)

  logging.warning(...)

  st.write(...)

  return {...}


- MVP 전략 

  \=\> secret 후보 식별

  → prompt/messages/LLM call/log/print로 전달되는지 shallow taint

  → 도달하면 finding


* LLM03 Supply Chain 

  \=\> 해당 취약점에서는 src-\>sink 흐름보다 특정 위험 API를 사용했냐는 여부 자체가 중요함. 별도의 taint 추적 없이도 사용 자체가 finding이 되므로 ast\_search를 사용하고 추가적으로 keyword argument check를 함. 

- API call 후보

  \=\> pickle.load(...)

  pickle.loads(...)

  torch.load(...)

  joblib.load(...)

  from\_pretrained(..., trust\_remote\_code=True)


- MVP 전략 

  \=\> AST에서 Call node 탐색

  → 함수명이 pickle.load / torch.load / joblib.load인지 확인

  → from\_pretrained 호출에서 trust\_remote\_code=True keyword 확인

  → 발견되면 finding


* LLM05 Improper Output Handling 

  \=\> 이 경우 역시 sink나 src만 따로보는 것이 아니라 LLM의 output이 위험한 sink로 흘러가는 흐름을 봐야하므로 ast\_taint에 추가적으로 sanitizer 후보를 확인하는 방식 사용 

- src 후보

  \=\> llm.invoke(...)

  chain.invoke(...)

  chain.run(...)

  agent.run(...)

  client.chat.completions.create(...)

  client.responses.create(...)


- sink 후보 

  \=\> eval(...)

  exec(...)

  os.system(...)

  subprocess.run(...)

  subprocess.Popen(...)

  subprocess.call(...)

  cursor.execute(...)

  conn.execute(...)

  db.execute(...)

  session.execute(...)


- MVP 전략 

  \=\> LLM call 반환값을 llm\_output source로 표시

  → 변수 재할당, f-string, 문자열 결합 일부 추적

  → eval/exec/shell/subprocess/SQL execute에 전달되면 finding


* LLM06 Excessive Agency

  \=\> LLM06은 데이터가 흐르는 문제가 아니라 agent에게 어떤 권한이 연결되었는지가 핵심이므로 ast\_capability \+ ast\_search 사용 

- Tool 후보

  \=\> @tool

  Tool.from\_function(...)

  StructuredTool.from\_function(...)

  tools=\[...\]


- Agent binding 후보

  \=\> initialize\_agent(...)

  AgentExecutor(...)

  create\_react\_agent(...)

  create\_openai\_functions\_agent(...)


- Dangerous Capability 후보 

  \=\> os.system

  subprocess.run

  subprocess.Popen

  shutil.rmtree

  os.remove

  Path.unlink

  cursor.execute

  conn.execute

  sendmail

  requests.post


- MVP 전략  

  \=\> @tool 함수 또는 Tool.from\_function 대상 함수 탐지

  → 함수 내부의 dangerous API 호출 탐지

  → 해당 tool이 agent tools list에 포함되는지 확인

  → 포함되면 finding


* LLM07 System Prompt Leakage 

  \=\> LLM07의 경우에는 LLM02와 src 식별 방식이 유사하다. 다만 가장 큰 차이점은 sink가 다르다는 것인데 LLM02는 secret \-\> prompt/messages/log/output이라면 LLM07은 secret/internal policy \-\> system prompt, 즉 구체적으로 system prompt로 흘러가는 흐름이 있는지를 관찰한다. 따라서 ast\_taink와 함께 regex\_assist \+ postprocess를 사용한다. (LLM02와 07 모두에 해당되는 경우에는 07을 우선표시하도록 postprocess) 

- src 후보

  \=\> secret

  token

  password

  credential

  internal\_url

  admin\_rule

  hidden\_policy

  do\_not\_reveal


- system prompt sink 후보 

  \=\> {"role": "system", "content": ...}

  SystemMessage(content=...)

  system\_prompt \= ...

  ChatPromptTemplate.from\_messages(\[("system", ...)\])


- MVP 전략 

  \=\> secret/internal source 후보 식별

  → system prompt 구조 탐지

  → source가 system prompt content에 포함되면 finding

  → LLM02와 중복되면 postprocess에서 LLM07 우선

---

# **4\. Rule 정의 단위 / granularity 결정**

\=\> 위험 성격이 다른(코드 실행, 명령 실행, DB 조작 등등) 것 위주로만 나누기   
rule metadata는 1번에서 정의한 것으로 고정하고, 실제 src, sink, line, flow, evidence는 코드 분석 후 finding result에서 채우기(API 이름만 다른 경우는 별도 rule로 나누지 않음)   
단, rule은 atomic risk family 단위로 정의한다. 

1) 별도 rule로 나누는 기준   
   1순위: sink\_kind / 위험 성격이 다른가?  
   2순위: detection\_type이 다른가?  
   3순위: source\_kind가 다른가?  
   4순위: status 또는 severity가 실질적으로 달라지는가?  
     
2) 같은 rule로 묶는 기준   
   1\. detection logic이 거의 같다.  
   2\. source\_kind와 sink\_kind가 같다.  
   3\. status와 severity가 같다.  
     
3) case별 granularity 방향   
   

| OWASP case | granularity 방향 |
| ----- | ----- |
| LLM01 | 외부 콘텐츠 source가 LLM input으로 들어가는 대표 흐름 1개로 시작 |
| LLM02 | secret → LLM input, sensitive data → log/output은 분리 가능 |
| LLM03 | unsafe deserialization과 trust\_remote\_code는 분리 |
| LLM05 | code execution, shell execution, SQL execution은 분리 |
| LLM06 | shell/file delete 계열과 DB write/email send 계열은 분리 가능 |
| LLM07 | secret → system prompt, internal policy/url → system prompt는 분리 가능 |

\*\* 별도 rule로 나누는 기준 보충 설명 

1) detection\_type이 다른가?   
   \=\> 예를 들어 같은 LLM03 Supply Chain이더라도 pickle.load는 ast\_search로 위험 API 호출을 탐지하며 unsafe deserialization에 해당하지만,  
   trust\_remote\_code=True는 같은 ast\_search이지만 keyword argument를 확인함으로써 remote code trust 여부를 보는 것임. 즉 탐지 방식과 의미가 다르므로 별도의 rule로 구분   
2) source\_kind가 다른가?  
   \=\> llm\_output인지, external\_content인지, secret인지, tool\_capability인지 등 위험 흐름의 시작에 따라서도 rule을 구분함.   
3) sink\_kind가 다른가?  
   \=\> 다음과 같이 LLM의 output이 어디로 가느냐에 따라서도 위험 성격이 달라짐.   
   이런 경우에는 분리하되, 같은 sink family 안에서는 묶음.   
   LLM output → eval/exec       \= code execution  
   LLM output → os.system       \= shell execution  
   LLM output → cursor.execute  \= SQL execution  
   LLM output → st.markdown     \= UI rendering  
     
4) status 또는 severity가 다른가?  
   \=\> 같은 OWASP category 안에서도 status/severity가 달라질 정도로 위험 성격이 다른 경우에는 별도 rule로 구분하는데, 예를 들어 LLM06에서 agent에 file delete tool이 연결되어 있는 경우에는 risky/critical로 분류할 수 있으나 read-only tool이 연결되어 있는 경우에는 risky/low\~medium 으로 분류될 수 있다. 따라서 이러한 경우에는 나눈다.  

---

# **5\. case별 required / optional rule 후보 결정**

Required rule은 10개로 둔다.

LLM01:  
\- LLM01\_EXTERNAL\_CONTENT\_TO\_LLM\_PROMPT

LLM02:  
\- LLM02\_SECRET\_TO\_LLM\_INPUT

LLM03: (sink\_kind, 위험성격이 다르므로 구분)   
\- LLM03\_UNSAFE\_DESERIALIZATION  
\- LLM03\_TRUST\_REMOTE\_CODE\_TRUE

LLM05: (sink\_kind, 위험성격이 다르므로 구분)   
\- LLM05\_LLM\_OUTPUT\_TO\_CODE\_EXECUTION  
\- LLM05\_LLM\_OUTPUT\_TO\_SHELL  
\- LLM05\_LLM\_OUTPUT\_TO\_SQL

LLM06: (severity 기준으로 구분)   
\- LLM06\_AGENT\_TOOL\_DESTRUCTIVE\_OR\_EXECUTION  
\- LLM06\_AGENT\_TOOL\_EXTERNAL\_SIDE\_EFFECT

LLM07:  
\- LLM07\_SECRET\_IN\_SYSTEM\_PROMPT

Optional rule은 다음으로 둔다. \=\> 시간상 아마 optional rule은 구현하지 않을 것 같음.   
\- LLM02\_SENSITIVE\_DATA\_TO\_LOG\_OR\_OUTPUT  
\- LLM05\_LLM\_OUTPUT\_TO\_HTML\_RENDERING  
\- LLM06\_AGENT\_TOOL\_BROAD\_DYNAMIC\_LIST  
\- LLM06\_AGENT\_TOOL\_READ\_FILE\_ACCESS  
\- LLM07\_INTERNAL\_POLICY\_IN\_SYSTEM\_PROMPT  
\- LLM01\_EXTERNAL\_CONTENT\_TO\_SYSTEM\_PROMPT

1) required rule 기준(반드시 구현해야 하는 MVP)  
   1\. OWASP 6개 case 커버리지에 필요하다.  
   2\. 정적 분석으로 비교적 명확하게 탐지할 수 있다.  
   3\. 데모에서 보여주기 좋다.  
   4\. 샘플셋을 만들기 쉽다.  
   5\. 오탐이 지나치게 많지 않다.  
   6\. 구현 난이도가 4일 MVP 안에 감당 가능하다.  
     
2) optional rule 기준(시간 남으면 넣는 확장 rule)   
   1\. 있으면 좋지만 MVP 완성에 필수는 아니다.  
   2\. keyword/regex 의존도가 높아 오탐 가능성이 크다.  
   3\. 다른 required rule과 어느 정도 겹친다.  
   4\. 구현은 가능하지만 테스트/디버깅 시간이 더 필요하다.  
   5\. 발표에서 핵심 데모로 쓰기에는 임팩트가 낮다.  
     
3) required rule table  
    | No | rule\_id                                     | category | detection\_type   | source\_kind           | sink\_kind                  | status       | severity   |  
   | \-: | \------------------------------------------- | \-------- | \---------------- | \--------------------- | \-------------------------- | \------------ | \---------- |  
   |  1 | \`LLM01\_EXTERNAL\_CONTENT\_TO\_LLM\_PROMPT\`      | LLM01    | \`ast\_taint\`      | \`external\_content\`    | \`llm\_input\`                | \`risky\`      | \`medium\`   |  
   |  2 | \`LLM02\_SECRET\_TO\_LLM\_INPUT\`                 | LLM02    | \`ast\_taint\`      | \`secret\`              | \`llm\_input\`                | \`vulnerable\` | \`high\`     |  
   |  3 | \`LLM03\_UNSAFE\_DESERIALIZATION\`              | LLM03    | \`ast\_search\`     | \`serialized\_artifact\` | \`unsafe\_deserialization\`   | \`risky\`      | \`high\`     |  
   |  4 | \`LLM03\_TRUST\_REMOTE\_CODE\_TRUE\`              | LLM03    | \`ast\_search\`     | \`remote\_model\`        | \`remote\_code\_trust\`        | \`risky\`      | \`high\`     |  
   |  5 | \`LLM05\_LLM\_OUTPUT\_TO\_CODE\_EXECUTION\`        | LLM05    | \`ast\_taint\`      | \`llm\_output\`          | \`code\_execution\`           | \`vulnerable\` | \`critical\` |  
   |  6 | \`LLM05\_LLM\_OUTPUT\_TO\_SHELL\`                 | LLM05    | \`ast\_taint\`      | \`llm\_output\`          | \`shell\_execution\`          | \`vulnerable\` | \`critical\` |  
   |  7 | \`LLM05\_LLM\_OUTPUT\_TO\_SQL\`                   | LLM05    | \`ast\_taint\`      | \`llm\_output\`          | \`sql\_execution\`            | \`vulnerable\` | \`critical\` |  
   |  8 | \`LLM06\_AGENT\_TOOL\_DESTRUCTIVE\_OR\_EXECUTION\` | LLM06    | \`ast\_capability\` | \`tool\_capability\`     | \`destructive\_or\_execution\` | \`risky\`      | \`critical\` |  
   |  9 | \`LLM06\_AGENT\_TOOL\_EXTERNAL\_SIDE\_EFFECT\`     | LLM06    | \`ast\_capability\` | \`tool\_capability\`     | \`external\_side\_effect\`     | \`risky\`      | \`high\`     |  
   | 10 | \`LLM07\_SECRET\_IN\_SYSTEM\_PROMPT\`             | LLM07    | \`ast\_taint\`      | \`secret\`              | \`system\_prompt\`            | \`vulnerable\` | \`high\`     |  
     
     
4) optional rule 후보   
   

| rule\_id | category | detection\_type | 이유 |
| ----- | ----- | ----- | ----- |
| `LLM02_SENSITIVE_DATA_TO_LOG_OR_OUTPUT` | LLM02 | `ast_taint` | PII/logging 탐지 보강용. 오탐 가능성 있음 |
| `LLM05_LLM_OUTPUT_TO_HTML_RENDERING` | LLM05 | `ast_taint` | Streamlit/HTML rendering 위험. MVP 핵심은 아님 |
| `LLM06_AGENT_TOOL_BROAD_DYNAMIC_LIST` | LLM06 | `ast_capability` | 동적 tool list 탐지. noisy할 수 있음 |
| `LLM06_AGENT_TOOL_READ_FILE_ACCESS` | LLM06 | `ast_capability` | read-only라도 민감 파일 접근 가능. 위험도 판단 어려움 |
| `LLM07_INTERNAL_POLICY_IN_SYSTEM_PROMPT` | LLM07 | `ast_taint` or `ast_search` | 내부 URL/hidden policy 탐지. keyword 기반이라 FP 가능성 있음 |
| `LLM01_EXTERNAL_CONTENT_TO_SYSTEM_PROMPT` | LLM01 | `ast_taint` | 외부 콘텐츠가 system prompt로 들어가는 강한 패턴. 드물지만 의미 있음 |

---

# **6\. 각 rule별 trigger / non-trigger 조건 정의**

trigger / non-trigger 의미와 공통 원칙 

* trigger: scanner가 finding을 생성해야 하는 조건   
* non-trigger: 비슷해보이지만 finding을 내지 않아야 하는 조건   
* MVP 공통 제한:

\- single-file 기준  
\- shallow taint 기준  
\- 변수 할당, f-string, 문자열 결합, list/dict 정도만 추적  
\- 함수 간 복잡한 inter-procedural taint는 제외  
\- sanitizer는 명확히 보이는 경우만 인정 

1) LLM01\_EXTERNAL\_CONTENT\_TO\_LLM\_PROMPT  
* Rule

  \=\> external\_content \-\> llm\_input 


* Trigger

  다음 조건을 모두 만족해야 finding 

  1\. external\_content source가 존재한다.

  2\. 그 source가 prompt/messages/input 변수에 포함된다.

  3\. 해당 prompt/messages/input이 LLM call 또는 agent input으로 전달된다. 


* Source Family

  requests.get(...).text

  requests.post(...).text

  open(...).read()

  Path(...).read\_text()

  loader.load()

  PyPDFLoader(...).load()

  WebBaseLoader(...).load()

  retriever.get\_relevant\_documents(...)

  vectorstore.similarity\_search(...) 


* Sink Family

  llm.invoke(...)

  chain.invoke(...)

  chain.run(...)

  agent.run(...)

  client.chat.completions.create(...)

  client.responses.create(...)

  messages=...

  input=...

  prompt=... 


* Non-trigger

  1\. 외부 콘텐츠를 가져오지만 LLM call로 전달하지 않는 경우

  2\. 외부 콘텐츠를 저장하거나 길이만 확인하는 경우

  3\. 일반 user\_input만 LLM에 전달되는 경우

  4\. prompt 문자열 자체가 공격문인지 의미 분석이 필요한 경우

  5\. external content가 명확히 quoted/reference data로만 처리되고 tool/action 결정에 쓰이지 않는지까지는 MVP에서 정밀 판단하지 않음 


2) LLM02\_SECRET\_TO\_LLM\_INPUT  
* Rule

  \=\> secret \-\> llm\_input 


* Trigger

  다음 조건을 모두 만족해야 Finding 

  1\. secret source 후보가 존재한다.

  2\. secret source가 prompt/messages/input에 포함된다.

  3\. 해당 prompt/messages/input이 LLM call로 전달된다.

  4\. sink가 명확한 system prompt인 경우는 LLM07로 우선 처리한다. 


* Source Family

  os.getenv("...KEY...")

  os.getenv("...TOKEN...")

  os.getenv("...PASSWORD...")

  os.environ\["...SECRET..."\]

  api\_key

  token

  secret

  password

  credential

  DATABASE\_URL

  DB\_PASSWORD

  문자열 패턴: sk-, ghp\_, xoxb-, postgres://, mysql://, \-----BEGIN PRIVATE KEY----- 


* Sink Family

  llm.invoke(...)

  chain.invoke(...)

  chain.run(...)

  agent.run(...)

  client.chat.completions.create(...)

  client.responses.create(...)

  messages=...

  input=...

  prompt=... 


* Non-trigger

  1\. secret 변수가 선언만 되고 LLM input으로 전달되지 않는 경우

  2\. secret이 redaction/masking된 값으로 대체된 것이 명확한 경우

  3\. placeholder 값이 명확하고 실제 LLM input으로 전달되지 않는 경우

  4\. system prompt에 secret이 들어가는 경우는 LLM02가 아니라 LLM07로 우선 분류

  5\. 변수명은 secret처럼 보이지만 실제 값이 없고 sink로도 가지 않는 경우 

3) LLM03\_UNSAFE\_DESERIALIZATION  
* Rule

  \=\> serialized\_artifact \-\> unsafe\_deserialization


* Trigger

  다음 API 호출이 있으면 finding

  pickle.load(...)

  pickle.loads(...)

  joblib.load(...)

  torch.load(...) 

  \*\* 인자가 사용자 입력인지까지는 추적하지 않고 위험 loading API 사용 자체를 finding으로 판단


* Non-trigger 

  1\. pickle/joblib/torch를 import만 하고 load 호출은 없는 경우

  2\. json.load, yaml.safe\_load 등 이 rule의 대상이 아닌 API를 사용하는 경우

  3\. torch.save, pickle.dump처럼 저장 API만 사용하는 경우


4) LLM03\_TRUST\_REMOTE\_CODE\_TRUE  
* Rule

  \=\> remote\_model \-\> remote\_code\_trust 


* Trigger

  다음 조건을 만족하면 finding 

  1\. from\_pretrained(...) 호출이 있다.

  2\. keyword argument에 trust\_remote\_code=True가 있다. 


* 대상 함수 family 

  AutoModel.from\_pretrained(...)

  AutoTokenizer.from\_pretrained(...)

  AutoModelForCausalLM.from\_pretrained(...)

  pipeline(...)

  기타 \*.from\_pretrained(...) 

* Non-trigger 

  1\. trust\_remote\_code=False

  2\. trust\_remote\_code 인자가 없음

  3\. from\_pretrained가 아닌 일반 함수 호출

  4\. 주석으로 "trusted"라고 써 있는 경우는 sanitizer로 인정하지 않음 


5) LLM05\_LLM\_OUTPUT\_TO\_CODE\_EXECUTION  
* Rule

  \=\> llm\_output \-\> code\_execution


* Trigger

  다음 조건을 모두 만족하면 finding 

  1\. LLM output source가 존재한다.

  2\. 해당 output이 변수에 저장되거나 직접 사용된다.

  3\. 그 값이 eval(...) 또는 exec(...)로 전달된다.

  4\. 중간에 명확한 allowlist/schema validation/action mapping이 없다.


* Source Family

  llm.invoke(...)

  chain.invoke(...)

  chain.run(...)

  agent.run(...)

  client.chat.completions.create(...)

  client.responses.create(...)

  response.choices\[0\].message.content

  response.output\_text


* Sink Family 

  eval(...)

  exec(...)


* Non-trigger

  1\. eval/exec가 LLM output과 무관한 고정 문자열에만 사용되는 경우

  2\. LLM output이 print 또는 UI 출력으로만 사용되는 경우

  3\. LLM output을 JSON으로 파싱한 뒤, allowlisted action enum만 사용하는 구조가 명확한 경우

  4\. eval/exec가 등장하지만 인자가 tainted llm\_output이 아닌 경우


6) LLM05\_LLM\_OUTPUT\_TO\_SHELL  
* Rule

  \=\> llm\_output \-\> shell\_execution


* Trigger

  다음 조건을 모두 만족하면 finding 

  1\. LLM output source가 존재한다.

  2\. 해당 output이 shell/process command 또는 command argument에 포함된다.

  3\. 그 값이 os.system, subprocess.run, subprocess.Popen, subprocess.call 등에 전달된다. 


* Sink Family

  os.system(...)

  subprocess.run(...)

  subprocess.Popen(...)

  subprocess.call(...) 


* Non-trigger 

  1\. subprocess가 고정 command만 실행하고 LLM output이 포함되지 않는 경우

  2\. LLM output이 단순 설명으로만 출력되는 경우

  3\. LLM output을 allowlist된 command name으로만 mapping하는 구조가 명확한 경우

  4\. shell/process API가 등장하지만 tainted llm\_output이 인자에 포함되지 않는 경우 


7) LLM05\_LLM\_OUTPUT\_TO\_SQL  
* Rule

  \=\> llm\_output \-\> sql\_execution


* Trigger

  다음 조건을 모두 만족해야 finding 

  1\. LLM output source가 존재한다.

  2\. 해당 output이 SQL query 문자열 또는 query 일부에 포함된다.

  3\. 그 값이 execute 계열 SQL sink의 첫 번째 인자로 전달된다. 


* Sink Family

  cursor.execute(...)

  conn.execute(...)

  db.execute(...)

  session.execute(...)

  engine.execute(...) 


* Non-trigger

  1\. SQL query가 고정 문자열이고 LLM output이 포함되지 않는 경우

  2\. parameterized query에서 LLM output이 value parameter로만 들어가는 경우

  3\. LLM output이 SQL 설명으로만 사용되고 실행되지 않는 경우

  4\. execute가 등장하지만 tainted llm\_output이 첫 번째 query 인자로 들어가지 않는 경우 


8) LLM06\_AGENT\_TOOL\_DESTRUCTIVE\_OR\_EXECUTION  
* Rule

  \=\> tool\_capability \-\> destructive\_or\_execution agent binding


* Trigger

  다음 조건을 모두 만족하면 finding 

  1\. tool로 등록되는 함수가 존재한다.

  2\. 해당 함수 내부에 destructive\_or\_execution capability가 있다.

  3\. 해당 tool이 agent tools list 또는 agent initialization에 연결된다. 


* Tool Registration Family

  @tool

  Tool.from\_function(...)

  StructuredTool.from\_function(...)

  tools=\[...\] 


* Agent Binding Family

  initialize\_agent(...)

  AgentExecutor(...)

  create\_react\_agent(...)

  create\_openai\_functions\_agent(...) 


* Critical Capability Family

  os.system(...)

  subprocess.run(...)

  subprocess.Popen(...)

  subprocess.call(...)

  os.remove(...)

  shutil.rmtree(...)

  Path.unlink(...) 


* Non-trigger 

  1\. dangerous function이 있지만 tool로 등록되지 않은 경우

  2\. tool 함수가 있지만 agent에 연결되지 않은 경우

  3\. agent가 있지만 tools list가 비어 있는 경우

  4\. tool 내부가 read-only 작업만 수행하는 경우

  5\. human approval이 명확히 강제되는 구조는 MVP에서는 일단 non-trigger 또는 낮은 우선순위로 처리 가능


9) LLM06\_AGENT\_TOOL\_EXTERNAL\_SIDE\_EFFECT  
* Rule

  \=\> tool\_capability \-\> high\_impact\_external\_side\_effect agent binding


* Trigger

  다음 조건을 모두 만족하면 finding 

  1\. tool로 등록되는 함수가 존재한다.

  2\. 해당 함수 내부에 외부 side effect capability가 있다.

  3\. 해당 tool이 agent tools list 또는 agent initialization에 연결된다. 


* External side effect capability family

   smtp.sendmail(...)

  send\_email(...)

  requests.post(...)

  requests.put(...)

  requests.delete(...)

  cursor.execute(...)

  conn.execute(...)

  db.execute(...)

  session.execute(...)


  \*\* 단, SQL execute의 경우에는 모든 execute를 DB write로 단정하면 오탐이 많으므로 INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, 함수명에 관련 키워드 포함 등일 때 우선 trigger로 고려하기. 


* Non-trigger

  1\. 외부 요청이 GET만 수행하고 상태 변경이 명확하지 않은 경우

  2\. DB query가 고정 SELECT read-only로 보이는 경우

  3\. function이 agent tool로 연결되지 않은 경우

  4\. tool로 연결되어도 read-only lookup만 수행하는 경우

  5\. execute가 있지만 write/update/delete 계열인지 판단할 근거가 없는 경우는 보수적으로 제외하거나 낮은 confidence 후보로만 둠


10) LLM07\_SECRET\_IN\_SYSTEM\_PROMPT  
* Rule

  \=\> secret \-\> system\_prompt 


* Trigger

  다음 조건을 모두 만족하면 finding 

  1\. secret source 후보가 존재한다.

  2\. 해당 secret이 system prompt sink에 포함된다.

  3\. system prompt가 LLM messages, prompt template, SystemMessage 등으로 사용된다. 


* Source Family 

  os.getenv("...KEY...")

  os.environ\["...TOKEN..."\]

  api\_key

  token

  secret

  password

  credential

  DATABASE\_URL 


* System prompt sink family 

  {"role": "system", "content": ...}

  SystemMessage(content=...)

  system\_prompt \= ...

  ChatPromptTemplate.from\_messages(\[("system", ...)\]) 


* Non-trigger 

  1\. system prompt에 일반 역할 설명만 있는 경우

  2\. secret 변수가 system prompt에 포함되지 않는 경우

  3\. secret이 redacted/masked 처리된 것이 명확한 경우

  4\. 일반 user message에 secret이 들어가는 경우는 LLM07이 아니라 LLM02로 처리

  5\. 내부 정책명이나 내부 URL만 있는 경우는 optional rule로 미룸 


  
---

# **7\. 각 rule별 status / severity 결정**

| rule\_id | status | severity | 판단 이유 |
| ----- | ----- | ----- | ----- |
| `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | `risky` | `medium` | 외부 콘텐츠가 LLM 입력에 들어가지만, 실제 악성 instruction 포함 여부나 피해 발생은 단정 불가 |
| `LLM02_SECRET_TO_LLM_INPUT` | `vulnerable` | `high` | secret이 LLM 입력으로 전달되는 흐름이 명확하며, 유출 시 영향이 큼 |
| `LLM03_UNSAFE_DESERIALIZATION` | `risky` | `high` | 위험한 로딩 API 사용은 확인되지만, 실제 artifact가 악성인지는 모름 |
| `LLM03_TRUST_REMOTE_CODE_TRUE` | `risky` | `high` | remote code 신뢰 설정은 위험하지만, 실제 remote repo가 악성인지는 모름 |
| `LLM05_LLM_OUTPUT_TO_CODE_EXECUTION` | `vulnerable` | `critical` | LLM output이 `eval/exec`로 들어가 코드 실행 가능 |
| `LLM05_LLM_OUTPUT_TO_SHELL` | `vulnerable` | `critical` | LLM output이 shell/process 실행으로 이어짐 |
| `LLM05_LLM_OUTPUT_TO_SQL` | `vulnerable` | `critical` | LLM output이 SQL query 구조로 실행될 수 있음 |
| `LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION` | `risky` | `critical` | agent가 실제 호출했는지는 모르지만, shell 실행/파일 삭제 권한이 연결됨 |
| `LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT` | `risky` | `high` | agent가 실제 호출했는지는 모르지만, DB write/email/API action 권한이 연결됨 |
| `LLM07_SECRET_IN_SYSTEM_PROMPT` | `vulnerable` | `high` | secret이 system prompt에 포함되는 구조가 명확함 |

\*\* 해당 rule이 trigger되었을 때 finding에 부여하는 기본 status와 severity이다.   
단, 명확한 sanitizer가 있는 경우에는 finding 자체를 생성하지 않으며 다른 downstream sink와 결합되는 경우에는 기존 finding의 severity를 수정하지 않고, 별도 rule finding 또는 compount note로 표현한다.   
---

# **8\. confidence 사용 여부와 기본 정책 결정**

1) confidence  
   \=\> 이 finding이 정적 분석 근거상 얼마나 확실한가를 나타내는 값   
   즉 구분하자면,   
   status     \= 취약 흐름으로 볼 수 있는가?  
   severity   \= 악용되면 얼마나 위험한가?  
   confidence \= 이 탐지 결과를 얼마나 믿을 수 있는가?  
     
   \*\* 단, confidence는 rule metadata에 포함시키지 않는다. confidence는 rule 자체보다는 실제 탐지 evidence의 강도에 따라 달라지기 때문임.   
     
2) confidence 가능한 값의 집합   
   \=\> confidence ∈ {0.9, 0.75, 0.6}  
* 0.9: source와 sink가 AST상 명확하게 연결됨  
* 0.75: 흐름은 보이나 regex/변수명/간접 구조에 일부 의존함  
* 0.6: keyword heuristic이 강하고 오탐 가능성이 있음 


3) 판정 기준   
* 0.9 \- high confidence

  \- AST에서 source→sink 흐름이 명확함

  \- 위험 API 호출이 정확히 탐지됨

  \- tool registration \+ agent binding \+ dangerous capability가 모두 확인됨


* 0.75 \- medium confidence

  \- source→sink 흐름은 보이지만 일부가 변수명/regex에 의존함

  \- secret 후보 판단이 변수명 또는 문자열 패턴 기반임

  \- LLM response object에서 실제 content 추출 형태가 다양해 완전히 확정하기 어려움


* 0.6 \- low confidence 

  \- secret인지 placeholder인지 불명확함

  \- internal policy인지 일반 설명인지 keyword만으로 판단함

  \- broad/dynamic tool list처럼 실제 capability를 확인하지 못함


4) confidence 사용 지점(이유)  
   \=\> confidence는 precision이나 recall 계산에 활용하지 않고 UI에서 사용자가 finding의 신뢰도를 이해하는 보조 정보로만 활용한다.   
      
5) required rule별 기본 confidence 정책   
   

| rule\_id | 기본 confidence | 이유 |
| ----- | ----- | ----- |
| `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | `0.75` | external content 흐름은 보이지만 실제 prompt injection 여부는 모름 |
| `LLM02_SECRET_TO_LLM_INPUT` | `0.75` | secret 판단에 regex/변수명 heuristic이 포함됨 |
| `LLM03_UNSAFE_DESERIALIZATION` | `0.9` | 위험 API 호출 자체가 명확함 |
| `LLM03_TRUST_REMOTE_CODE_TRUE` | `0.9` | keyword argument가 명확함 |
| `LLM05_LLM_OUTPUT_TO_CODE_EXECUTION` | `0.9` | LLM output → eval/exec 흐름이 명확함 |
| `LLM05_LLM_OUTPUT_TO_SHELL` | `0.9` | LLM output → shell sink 흐름이 명확함 |
| `LLM05_LLM_OUTPUT_TO_SQL` | `0.9` | LLM output → SQL execute 흐름이 명확함 |
| `LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION` | `0.9` | tool 등록 \+ agent binding \+ dangerous capability가 모두 보이면 명확함 |
| `LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT` | `0.75` | DB write 여부 판단에 함수명/SQL keyword heuristic이 일부 들어갈 수 있음 |
| `LLM07_SECRET_IN_SYSTEM_PROMPT` | `0.75` | secret 판단에 regex/변수명 heuristic이 포함됨 |

   

---

# **9\. rule 간 중복 처리 기준 결정(severity 기준 / 우선순위 기준 결정)** 

목표: 여러 rule이 같은 코드 조각을 동시에 잡은 경우, 결과 카드가 중복으로 과하게 뜨지 않도록 최소 기준을 정한다. 

1) 기본 원칙   
   1\. 같은 source와 같은 sink를 가리키는 finding이 여러 개면 더 구체적인 rule을 우선한다.  
   2\. 서로 다른 보안 의미를 가진 finding이면 둘 다 남긴다.  
   3\. 같은 rule이 같은 line에서 여러 번 잡히면 하나로 병합한다.  
   4\. LLM02와 LLM07이 겹치면 LLM07을 우선한다.  
   5\. LLM01, LLM05, LLM06은 의미가 다르면 동시에 표시한다.  
     
2) 가장 중요한 중복: LLM02 VS LLM07   
   예를 들어..   
   api\_key \= os.getenv("OPENAI\_API\_KEY")  
     
   messages \= \[  
       {  
           "role": "system",  
           "content": f"Internal API key: {api\_key}"  
       }  
   \]  
     
   \=\> 이 경우는 LLM02: secret \-\> LLM input 으로도 볼 수 있고  
   LLM07: secret \-\> system prompt 로도 볼 수 있음.   
   하지만 system prompt는 LLM input 중에서도 더 구체적인 sink이므로   
   secret → system prompt  
   \= LLM07\_SECRET\_IN\_SYSTEM\_PROMPT 우선 표시  
   \= LLM02\_SECRET\_TO\_LLM\_INPUT은 중복이면 숨김  
     
3) LLM01과 LLM05   
   예를 들어..  
   docs \= retriever.get\_relevant\_documents(query)  
   prompt \= f"Use these docs: {docs}"  
     
   cmd \= llm.invoke(prompt)  
   os.system(cmd)  
     
   \=\> 여기서는 두 finding이 모두 각각 나름의 의미가 있음   
   LLM01: external content → LLM prompt  
   LLM05: LLM output → shell execution  
   이건 중복이 아닌 이유는 하나는 입력쪽의 위험이고 하나는 출력 처리쪽 위험이기 때문에 이러한 case는 둘 다 표시한다.   
     
4) LLM06과 LLM05   
   예를 들어..  
   @tool  
   def run\_shell(cmd: str):  
       return os.system(cmd)  
     
   agent \= initialize\_agent(\[run\_shell\], llm)  
     
   cmd \= llm.invoke(prompt)  
   os.system(cmd)  
     
   \=\> 여기서는 두 finding이 모두 가능한데 LLM06은 agent에게 shell tool이 연결된 것이고 LLM05는 LLM output이 os.system으로 직접 전달된 것임. 따라서 둘은 다른 문제이므로 둘 다 표시   
5) 같은 rule 같은 line 중복은 병합   
   \=\> 중복 판단 key: (file, rule\_id, line, sink)   
   즉, 같은 파일, 같은 rule, 같은 line, 같은 sink면 하나로 병합   
     
6) 같은 source가 여러 sink로 가면 각각 표시  
     
7) 같은 sink family 안의 concrete API는 하나의 rule로 표시   
     
8) 최종 중복 처리 정책 정리본  
   1\. 동일 finding 병합  
   \- key \= file \+ rule\_id \+ line \+ sink  
     
   2\. LLM07 우선  
   \- secret → system prompt가 잡히면 같은 source/sink의 LLM02 finding은 제거  
     
   3\. 서로 다른 sink\_kind는 모두 유지  
   \- code\_execution, shell\_execution, sql\_execution은 각각 표시  
     
   4\. 서로 다른 OWASP 의미는 모두 유지  
   \- LLM01 \+ LLM05  
   \- LLM01 \+ LLM06  
   \- LLM05 \+ LLM06  
     
   5\. compound risk로 severity를 바꾸지 않음  
   \- MVP에서는 개별 finding의 status/severity를 유지  
   

---

# **10\. 최종 minimum rule table 확정**

| No | rule\_id | category | detection\_type | source\_kind | sink\_kind | status | severity |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| 1 | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | `LLM01:2025 Prompt Injection` | `ast_taint` | `external_content` | `llm_input` | `risky` | `medium` |
| 2 | `LLM02_SECRET_TO_LLM_INPUT` | `LLM02:2025 Sensitive Information Disclosure` | `ast_taint` | `secret` | `llm_input` | `vulnerable` | `high` |
| 3 | `LLM03_UNSAFE_DESERIALIZATION` | `LLM03:2025 Supply Chain` | `ast_search` | `serialized_artifact` | `unsafe_deserialization` | `risky` | `high` |
| 4 | `LLM03_TRUST_REMOTE_CODE_TRUE` | `LLM03:2025 Supply Chain` | `ast_search` | `remote_model` | `remote_code_trust` | `risky` | `high` |
| 5 | `LLM05_LLM_OUTPUT_TO_CODE_EXECUTION` | `LLM05:2025 Improper Output Handling` | `ast_taint` | `llm_output` | `code_execution` | `vulnerable` | `critical` |
| 6 | `LLM05_LLM_OUTPUT_TO_SHELL` | `LLM05:2025 Improper Output Handling` | `ast_taint` | `llm_output` | `shell_execution` | `vulnerable` | `critical` |
| 7 | `LLM05_LLM_OUTPUT_TO_SQL` | `LLM05:2025 Improper Output Handling` | `ast_taint` | `llm_output` | `sql_execution` | `vulnerable` | `critical` |
| 8 | `LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION` | `LLM06:2025 Excessive Agency` | `ast_capability` | `tool_capability` | `destructive_or_execution` | `risky` | `critical` |
| 9 | `LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT` | `LLM06:2025 Excessive Agency` | `ast_capability` | `tool_capability` | `external_side_effect` | `risky` | `high` |
| 10 | `LLM07_SECRET_IN_SYSTEM_PROMPT` | `LLM07:2025 System Prompt Leakage` | `ast_taint` | `secret` | `system_prompt` | `vulnerable` | `high` |

