# **\<핵심 결정 요약\>**

1) OWASP case 10가지 중 6가지로 확정   
- LLM01 Prompt Injection(정확히는 Indirect)  
- LLM02 Sensitive Information Disclosure  
- LLM03 Supply Chain  
- LLM05 Improper Output Handling   
- LLM06 Excessive Agency  
- LLM07 System Prompt Leakage


2) status / severity 정의   
- status: 정적 분석에서 확신할 수 있는 결과  
* status ∈ {vulnerable, risky, safe}  
- severity: 실제 악용시 위험도   
* severity ∈ {critical, high, medium, low}

---

# **1\. 6개 case별 탐지 범위 확정안**

| OWASP case | 이번 프로젝트에서 탐지할 것 | 이번 프로젝트에서 탐지하지 않을 것 |
| ----- | ----- | ----- |
| LLM01 Prompt Injection | 외부 웹/파일/RAG 문서 내용이 prompt/messages에 들어가 LLM call로 전달되는 구조 | prompt 텍스트 자체가 공격문인지 판단, 실제 injection 성공 여부 |
| LLM02 Sensitive Information Disclosure | API key, token, password, DB URL, env secret, 개인정보 후보가 prompt/log/print/response에 들어가는 구조 | 실제 개인정보 여부의 완전 판별, DB 내부 데이터 추론 |
| LLM03 Supply Chain | `pickle.load`, `pickle.loads`, `torch.load`, `joblib.load`, `trust_remote_code=True` | 전체 dependency audit, pip package CVE 조회, 모델 파일 무결성 검증 |
| LLM05 Improper Output Handling | LLM output이 검증 없이 `eval`, `exec`, `subprocess`, `os.system`, SQL execute로 전달되는 구조 | 실제 명령 실행 여부, runtime permission 확인 |
| LLM06 Excessive Agency | agent/tool에 shell, file delete, DB write, email send 등 고위험 capability가 연결된 구조 | agent가 실제로 그 tool을 호출하는지, 권한 정책 전체 분석 |
| LLM07 System Prompt Leakage | system prompt에 secret, internal URL, admin rule, hidden policy가 포함되는 구조 | 모델이 실제로 system prompt를 유출하는지 실험 |

---

# **2\. 각 case별 범위 상세 결정**

## **LLM01:2025 Prompt Injection**

OWASP 2025 설명에서 prompt injection은 사용자의 입력 또는 외부 입력이 LLM의 동작이나 출력을 의도하지 않은 방식으로 바꾸는 문제이며, 특히 간접 prompt injection은 웹사이트나 파일 같은 외부 소스에서 입력을 수락할 때 발생한다고 설명됩니다.

우리 프로젝트에서는 **직접 prompt injection이 아니라 indirect prompt injection 가능 구조**만 봅니다.

### **탐지 대상**

external content source  
→ prompt/messages  
→ LLM call

### **source 예시**

requests.get(url).text  
open("doc.txt").read()  
PyPDFLoader(...)  
WebBaseLoader(...)  
loader.load()  
retriever.get\_relevant\_documents(...)  
vectorstore.similarity\_search(...)

### **sink 예시**

client.chat.completions.create(messages=...)  
client.responses.create(input=...)  
llm.invoke(prompt)  
chain.invoke(...)

### **탐지 조건**

다음 중 하나라도 만족하면 LLM01 finding으로 봅니다.

1\. requests/open/loader/retriever 결과가 prompt 변수에 들어감  
2\. 해당 prompt 변수가 LLM call의 input/messages/prompt에 들어감  
3\. messages 배열 안에 external content 변수가 포함됨  
4\. f-string으로 external content가 prompt에 합쳐짐

### **제외 범위**

\- 사용자가 직접 입력한 일반 질문만 LLM에 넣는 경우  
\- prompt 내용에 “ignore previous instruction” 같은 문장이 있는지 의미 분석  
\- 실제 공격 성공 여부 테스트

### **최종 status**

risky

---

## **LLM02:2025 Sensitive Information Disclosure**

이번 프로젝트에서는 “LLM이 민감정보를 출력했다”보다 **개발자가 민감정보를 LLM prompt, log, print, response에 넣는 구조**를 봅니다.

### **탐지 대상**

secret / PII / internal data  
→ prompt / messages / log / print / response

### **source 예시**

os.getenv("OPENAI\_API\_KEY")  
os.environ\["DB\_PASSWORD"\]  
api\_key \= "sk-..."  
password \= "..."  
token \= "..."  
DATABASE\_URL \= "postgres://..."  
user\_email \= ...  
phone\_number \= ...  
resident\_id \= ...

### **sink 예시**

messages=\[...\]  
prompt \= ...  
client.chat.completions.create(...)  
llm.invoke(...)  
print(...)  
logging.info(...)  
st.write(...)  
return {...}

### **탐지 조건**

1\. 변수명에 key/token/secret/password/credential 등이 포함됨  
2\. 문자열 literal이 API key, DB URL, JWT, private key처럼 보임  
3\. 해당 값이 prompt/messages/LLM call/log/print에 들어감

### **제외 범위**

\- 실제 개인정보인지 정확한 식별  
\- 암호화 저장 여부  
\- DB 내부 field-level privacy 분석  
\- LLM 응답 내용의 실제 유출 여부

### **최종 status**

vulnerable

단, 단순히 secret 변수가 존재만 하고 어디에도 전달되지 않으면 finding을 내지 않습니다.

---

## **LLM03:2025 Supply Chain**

OWASP 2025에서는 LLM supply chain이 다양한 취약점에 노출될 수 있다고 설명하지만, 4일 MVP에서는 전체 supply chain 검증이 아니라 **정적 분석으로 확실히 보이는 위험 loading pattern**만 다룹니다. ([OWASP Gen AI Security Project](https://genai.owasp.org/llm-top-10/))

### **탐지 대상**

unsafe model/object loading pattern

### **직접 탐지 sink**

pickle.load(...)  
pickle.loads(...)  
torch.load(...)  
joblib.load(...)  
from\_pretrained(..., trust\_remote\_code=True)  
AutoModel.from\_pretrained(..., trust\_remote\_code=True)  
AutoTokenizer.from\_pretrained(..., trust\_remote\_code=True)

### **탐지 조건**

1\. pickle/joblib/torch load 계열 호출이 있음  
2\. Hugging Face from\_pretrained 호출에서 trust\_remote\_code=True 사용  
3\. 외부 URL 또는 사용자 입력 파일 경로와 결합되면 confidence 상승

### **제외 범위**

\- pip dependency CVE 조회  
\- requirements.txt 전체 감사  
\- 모델 파일 해시 검증  
\- Hugging Face repo 신뢰도 평가  
\- 실제 malicious pickle 실행 여부

### **최종 status**

risky

---

## **LLM05:2025 Improper Output Handling**

OWASP 2025에서 Improper Output Handling은 LLM output에 대한 validation, sanitization, handling이 부족한 문제로 설명됩니다. ([OWASP Gen AI Security Project](https://genai.owasp.org/llm-top-10/))

이번 프로젝트의 **가장 중요한 핵심 rule**입니다.

### **탐지 대상**

LLM output  
→ dangerous execution sink

### **source 예시**

response \= client.chat.completions.create(...)  
result \= llm.invoke(...)  
answer \= chain.run(...)  
output \= agent.run(...)

### **sink 예시**

eval(response)  
exec(response)  
os.system(response)  
subprocess.run(response, shell=True)  
subprocess.Popen(response, shell=True)  
cursor.execute(response)  
conn.execute(response)

### **탐지 조건**

1\. LLM call 결과가 변수에 저장됨  
2\. 그 변수가 dangerous sink에 전달됨  
3\. 중간에 명확한 sanitizer가 없으면 finding

### **sanitizer 후보**

json.loads(...)  
pydantic\_model.model\_validate(...)  
schema.validate(...)  
allowlist\_check(...)  
shlex.quote(...)  
parameterized SQL

단, Day 1 기준에서는 sanitizer를 “문서상 후보”로만 두고, 구현은 아주 보수적으로 갑니다.

### **제외 범위**

\- 실제 명령어가 위험한지 내용 분석  
\- LLM output 자연어 의미 분석  
\- 복잡한 inter-procedural taint  
\- 여러 파일을 건너가는 흐름

### **최종 status**

vulnerable

### **severity**

critical

---

## **LLM06:2025 Excessive Agency**

OWASP 2025에서는 LLM 기반 시스템이 agent 또는 plugin 구조에서 더 큰 자율성을 부여받으면서, 검증되지 않은 권한이 위험한 작업으로 이어질 수 있다고 설명합니다.

우리 프로젝트에서는 **agent가 실제로 뭘 했는지**가 아니라, **agent에게 어떤 tool/capability가 연결되었는지**를 봅니다.

### **탐지 대상**

agent / tool binding  
→ dangerous capability

### **dangerous capability 예시**

os.system  
subprocess.run  
subprocess.Popen  
shutil.rmtree  
os.remove  
Path.unlink  
cursor.execute  
conn.execute  
send\_email  
smtp.sendmail  
requests.post

### **agent/tool binding 예시**

@tool  
def run\_shell(cmd):  
    return os.system(cmd)

Tool.from\_function(...)  
initialize\_agent(tools=\[...\])  
create\_react\_agent(..., tools=\[...\])  
AgentExecutor(..., tools=\[...\])

### **탐지 조건**

1\. @tool 함수 내부에 dangerous capability가 있음  
2\. Tool.from\_function으로 dangerous function이 tool화됨  
3\. tools=\[...\]에 dangerous tool이 들어감  
4\. agent 생성 함수에 dangerous tool list가 전달됨

### **제외 범위**

\- agent runtime 행동 분석  
\- 사용자가 승인했는지 여부  
\- 실제 권한 정책 분석  
\- tool별 authorization decorator 정밀 분석

### **최종 status**

risky

### **severity**

high

---

## **LLM07:2025 System Prompt Leakage**

OWASP 2025에는 System Prompt Leakage가 별도 항목으로 포함되어 있고, system prompt가 안전하게 격리된다고 가정해서는 안 된다는 문제의식이 반영되어 있습니다. ([OWASP Gen AI Security Project](https://genai.owasp.org/llm-top-10/))

우리 프로젝트에서는 **system prompt에 민감한 내용을 넣는 코드 구조**를 봅니다.

### **탐지 대상**

secret / internal policy / admin rule  
→ system prompt

### **source 예시**

api\_key \= ...  
admin\_password \= ...  
internal\_url \= "http://internal..."  
policy \= "Do not reveal..."  
hidden\_rule \= ...

### **sink 예시**

{"role": "system", "content": ...}  
SystemMessage(content=...)  
system\_prompt \= ...  
ChatPromptTemplate.from\_messages(\[  
    ("system", ...)  
\])

### **탐지 조건**

1\. system role message에 secret 변수가 들어감  
2\. system prompt 문자열에 key/token/password/internal/admin 등이 포함됨  
3\. 내부 URL, 관리자 규칙, hidden policy로 보이는 내용이 system prompt에 포함됨

### **LLM02와의 구분**

LLM02:  
민감정보가 prompt/log/response 등으로 흘러가는 일반적인 정보 노출 위험

LLM07:  
그 민감정보 또는 내부 정책이 system prompt에 들어가는 특수한 구조

즉, 같은 코드에서 둘 다 뜰 수 있습니다. 다만 UI에서는 중복이 과하면 LLM07을 우선 표시하고, LLM02는 secondary finding으로 낮춰도 됩니다.

### **제외 범위**

\- 실제 system prompt를 모델이 유출하는지 테스트  
\- jailbreak 성공 여부  
\- system prompt 내용의 정책적 적절성 평가

### **최종 status**

vulnerable

---

# **3\. status vs severity 정의** 

1) status: **정적 분석 결과**의 확실성/해석 수준\[“이 finding을 얼마나 취약점에 가깝게 볼 것인가?”\]   
- 총 가능한 값의 집합: **{vulnerable, risky, safe}**   
* vulnerable: 취약한 코드 흐름이 정적으로 확인됨.   
* risky: 위험 가능성이 있는 패턴이 확인되나 취약하다고 단정하기는 어려움.   
* safe: 해당 샘플에서 위험 흐름이 확인되지 않음.   
- Finding status 집합: {vulnerable, risky} (safe는 어짜피 finding에 안보여줌)   
- sample label 집합: {vulnerable, risky, safe}   
- status 예시   
* **status \= vulnerable** 


  llm\_output \= llm.invoke(user\_prompt)

  eval(llm\_output)

  \=\> 이 경우 llm의 output이 검증없이 그대로 eval()로 가므로 코드 구조상 위험 흐름이 명백하므로 status \= vulnerable 

* **status \= risky** 


  web\_text \= requests.get(url).text

  prompt \= f"Summarize this page: {web\_text}"

  llm.invoke(prompt)

  \=\> 이 경우 외부 웹페이지의 내용이 프롬프트에 들어가지만 해당 웹페이지에 실제 prompt injection(indirect) 문구가 있을지까지는 알 수 없으므로 status \= risky 


2) severity: 문제가 실제로 **악용되었을 때**의 영향도\[“이 finding이 실제 문제가 되었을 때 영향이 얼마나 큰가?”\]  
- 총 가능한 값의 집합: **{critical, high, medium, low}**   
* critical: 시스템 실행권한, 명령 실행, 치명적 DB 조작 등 즉각적이고 큰 피해  
* high: 민감정보 노출, 위험 tool 권한, remote code 신뢰 등 심각한 피해   
* medium: 외부 콘텐츠가 LLM prompt로 들어가거나 제한적 정보 노출이 가능한 경우처럼 검토가 필요한 경우   
* low: 직접적인 보안 영향은 제한적이지만 안전한 설계 관점에서 개선이 필요한 경우  


  \*\* critical vs high: “**즉시 실행, 파괴, 변조 가능한 sink인가?**”를 기준으로 critical과 high를 구분함. 

  예를 들어 LLM이 DB를 날려버리는 즉각적인 행위가 실행 가능한 상태라면 critical이지만, 민감정보 노출처럼 충분히 위험한 보안상 취약점이지만 어찌됐든 그 노출된 민감정보를 갖고 누군가가 악용을 해야 하는 “한 단계”의 추가적인 action이 있는 경우라면 high 


  \*\* status \= safe인 경우에는 severity는 null로 정의. 즉, severity는 정적 분석 결과상 위험이 있다고 판단되는, findings에 보여줄 대상을 기준으로만 정의되므로 애초에 status가 safe라면 severity는 표시하지 않는다. 


- severity 예시   
* Agent tool에 파일 삭제 기능 연결하는 case

  \[**severity \= critical** / status \= risky\] 


  @tool

  def delete\_file(path):

      os.remove(path)


  agent \= initialize\_agent(\[delete\_file\], llm)

  \=\> 실제로 해당 tool이 사용되었는지는 알 수 없으므로 status \= risky이지만, 만약 agent가 호출하면 파일 삭제가 가능하므로 영향도는 critical로 판단


* secret → system prompt인 case

  \[**severity \= high** / status \= vulnerable\]


  api\_key \= os.getenv("OPENAI\_API\_KEY")


  messages \= \[

      {

          "role": "system",

          "content": f"You are an admin assistant. API key: {api\_key}"

      },

      {

          "role": "user",

          "content": user\_input

      }

  \]

  \=\> 정적 분석만으로 API\_KEY값(secret)이 시스템 프롬프트 안으로 들어가는 흐름이 명백하게 탐지되므로 status \= vulnerable임. 시스템 프롬프트 안에 중요한 민감 정보가 포함되는 경우 logging이나 prompt leakage 등으로 얼마든지 노출될 가능성이 있으므로 severity를 high로 판단 


* PDF/RAG 문서 \-\> prompt인 case 

  \[**severity \= medium** / status \= risky\] 


  docs \= retriever.get\_relevant\_documents(query)

  prompt \= f"Answer using these documents: {docs}"

  llm.invoke(prompt)

  \=\> 문서 내부의 악성 instruction이 LLM의 행동에 영향을 줄 가능성이 있으나 실제 문서 내부에 해당 instruction이 포함되어 있는지 여부까지는 알 수 없으므로 status \= risky로 판정. 이어서 이러한 악성 instruction은 LLM의 행동에 “영향”을 줄 수는 있으나 그 흐름만으로 곧바로 시스템에 피해가 간다고 단정지을 수 없으므로 severity \= medium으로 판단 


* secret처럼 보이는 변수명이 있지만 실제 값은 placeholder인 case 

  \[**severity \= low** / status \= risky\]


  api\_key \= "YOUR\_API\_KEY\_HERE"

  prompt \= f"Use this key: {api\_key}"

  \=\> 실제 secret이 아닌 placeholder일 가능성이 큰 코드이므로 현재 코드 기준으로는 severity \= low임. 단, api\_key가 프롬프트에 직접 들어가는 구조이므로 구현 설계상으로는 risky한 코드임. (애초에 이렇게 코딩하는 습관 자체도 매우 위험한 습관) 


\*\* 주의사항    
하지만 이렇게 단적으로 확정지을 수는 없는 것이, 뒤에 downstream sink가 어떤 것이 오느냐에 따라 또 severity는 달라질 수 있음. 또한 실제 코드는 하나의 LLM 취약점이 독자적으로 나타난다기보다는 여러 개의 취약점이 결합되어 발생될 확률이 높음.   
\=\> 즉, 실제 판단은 source \-\> sink의 흐름 & sanitizer의 유무와 적용 방식까지 종합적으로 고려할 수 있어야 함. 

ex) severity \= medium이었던 PDF/RAG 문서 \-\> prompt인 case 재조명 

External/RAG content → LLM prompt only  
\= LLM01 risky, **severity medium**

External/RAG content → LLM/agent decision → dangerous tool  
\= LLM01 \+ LLM06 risky, **severity high or critical**

External/RAG content → LLM output → dangerous execution sink  
\= LLM01 \+ LLM05 vulnerable, **severity critical**

