# Layer A Real-World Pattern Matrix

기준 브랜치: `fix/layer-a-report-alignment`  
기준 커밋: `fd0f8c656e22bf1deefadb95509dec9515e0df8d`

이 표는 공개 Finding/ScanResult Schema를 확장하지 않고 내부 role 및 shallow taint로 판정하는 패턴을 정리한다. Confidence는 rule 기본값과 source/role evidence cap 중 낮은 값이다.

| Framework/Pattern | Example | Internal role | Source/Sink | Expected rule | Confidence | Negative control |
| ----------------- | ------- | ------------- | ----------- | ------------- | ---------- | ---------------- |
| OpenAI Responses SDK | `client.responses.create(input=external)` | `openai_client`/exact API | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | 0.75 | `fakeclient.responses.create(...)` |
| OpenAI Chat Completions SDK | `service.client.chat.completions.create(messages=[external])` | exact API | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | 0.75 | `not_client.chat.completions.create(...)` |
| LangChain model | `model = ChatOpenAI(); model.invoke(external)` | `llm_model` | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | 0.75 | `workflow.invoke(external)` |
| Weak model-name fallback | `self.model.ainvoke(external)` | `llm_model` (name fallback) | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | 0.6 | `pipeline.ainvoke(external)` |
| LCEL composition | `chain = prompt \| model \| parser` | `llm_chain` | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | 0.75 | ordinary bitwise OR without role evidence |
| Agent factory | `agent = create_agent(model, tools=tools)` | `agent` | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | 0.75 | `task.invoke(external)` |
| Async model | `await model.ainvoke(prompt)` | `llm_model` | LLM output | downstream `LLM05_*` | 0.9 | unrelated awaited call |
| Streaming model | `model.stream(prompt)` / `model.astream(prompt)` | `llm_model` | LLM output | downstream `LLM05_*` | 0.9 | `task.stream(prompt)` |
| Loader | `loader = PyPDFLoader(path); loader.load()` | `loader` | external content source | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` at LLM sink | 0.75 | unrelated `.load()` receiver |
| LlamaIndex reader | `reader = SimpleDirectoryReader(path); reader.load_data()` | `loader` | external content source | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` at LLM sink | 0.75 | unrelated `.load_data()` receiver |
| Retriever | `retriever.invoke(question)` | `retriever` | external content source | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` at model sink | 0.6 name fallback / 0.75 exact | model output classification |
| Vector store | `vector_store.similarity_search(question)` | `vector_store` | external content source | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` at model sink | 0.6 name fallback / 0.75 exact | unrelated similarity method |
| Query engine | `index.as_query_engine().query(question)` | `query_engine` | LLM output source | downstream `LLM05_*` | 0.9 | classify as LLM01 external content |
| Output extraction | `response.choices[0].message.content` | inherited parent role | LLM output source | downstream `LLM05_*` | inherited | `unrelated.output_text` |
| Document extraction | `document.page_content` / `node.get_content()` | inherited external source | external content source | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` at LLM sink | inherited | untainted parent |
| Secret attribute | `self.token = os.getenv("ADMIN_TOKEN")` | canonical key `self.token` | secret → LLM input | `LLM02_SECRET_TO_LLM_INPUT` | 0.75 | masked literal |
| Secret subscript | `state["token"] = os.getenv("ADMIN_TOKEN")` | canonical key `state['token']` | secret → LLM input | `LLM02_SECRET_TO_LLM_INPUT` | 0.75 | dynamic subscript key (unsupported) |
| Container mutation | `items.append(model.invoke(prompt))` | function-local container taint | LLM output → eval/shell/SQL | `LLM05_*` | inherited | untainted append |
| Comprehension/generator | `[item for item in [external]]` | comprehension-local binding | external → LLM input | `LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT` | inherited | untainted iterable |
| Walrus/AugAssign | `result := model.invoke(...)`, `prompt += external` | function-local binding | inherited flow | appropriate LLM01/LLM05 | inherited | untainted RHS |
| Receiver-aware SQL | `service.session.execute(text(query))` | `sql_connection` | LLM output → SQL structure | `LLM05_LLM_OUTPUT_TO_SQL` | 0.9 | `workflow.execute(query)` |
| Parameterized SQL value | `session.execute("... id=:id", {"id": output})` | `sql_connection` | value only | no finding | — | query structure taint triggers |
| Fixed shell allowlist | `subprocess.run(commands["status"])` | immutable literal mapping | fixed command | no finding | — | mutation invalidates safe state |
| Mutated allowlist | `commands["chosen"] = model.invoke(...)` | invalidated mapping | LLM output → shell | `LLM05_LLM_OUTPUT_TO_SHELL` | 0.9 | untouched fixed mapping |
| Responses instructions | `client.responses.create(instructions=secret)` | exact Responses API | secret → system prompt | `LLM07_SECRET_IN_SYSTEM_PROMPT` | 0.75 | unrelated `instructions=` call |
| Developer message | `{"role": "developer", "content": secret}` | privileged message flow | secret → system prompt | `LLM07_SECRET_IN_SYSTEM_PROMPT` | 0.75 | user-role secret → LLM02 |
| Agent system prompt | `create_agent(system_prompt=secret)` | `agent` factory | secret → system prompt | `LLM07_SECRET_IN_SYSTEM_PROMPT` | 0.75 | unrelated `system_prompt=` call |
| Destructive agent tool | `@tool` function with `os.remove`, bound to agent | registered/bound tool | capability → destructive execution | `LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION` | 0.9 | registered but unbound tool |
| Side-effect agent tool | `FunctionTool.from_defaults(fn=send_email)`, then `from_tools` | registered/bound tool | capability → external side effect | `LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT` | 0.75 | `model.bind_tools` only |
| Nested unused helper | destructive call only inside unused nested function | excluded nested scope | no outer capability | no finding | — | direct destructive call in tool body |
| Hugging Face remote code | `pipeline(..., trust_remote_code=True)` | exact keyword | remote model → remote code trust | `LLM03_TRUST_REMOTE_CODE_TRUE` | 0.9 | false/absent keyword |
| Direct import alias | `import subprocess as sp; sp.run(output)` | alias-resolved API | LLM output → shell | `LLM05_LLM_OUTPUT_TO_SHELL` | 0.9 | undeclared alias |

