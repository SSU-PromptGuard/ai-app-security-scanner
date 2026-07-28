from __future__ import annotations

import unittest

from scanner import scan_code


class LayerARealWorldPatternTests(unittest.TestCase):
    def scan(self, code: str):
        result = scan_code(code, "real_world.py")
        self.assertTrue(result.ok, result.parse_error)
        return result.findings

    def assert_one(
        self,
        code: str,
        rule_id: str,
        source_kind: str,
        sink_kind: str,
        confidence: float,
    ):
        findings = self.scan(code)
        self.assertEqual([finding.rule_id for finding in findings], [rule_id])
        finding = findings[0]
        self.assertEqual(finding.source_kind, source_kind)
        self.assertEqual(finding.sink_kind, sink_kind)
        self.assertEqual(finding.confidence, confidence)
        return finding

    def assert_no_findings(self, code: str):
        self.assertEqual(self.scan(code), [])

    def test_sdk_segment_boundary_positive_and_negative(self):
        positives = (
            "client.responses.create(input=external)",
            "self.client.responses.create(input=external)",
            "service.client.chat.completions.create(messages=[external])",
        )
        for call in positives:
            with self.subTest(call=call):
                self.assert_one(
                    f"external = requests.get(url).text\n{call}\n",
                    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                    "external_content",
                    "llm_input",
                    0.75,
                )

        negatives = (
            "fakeclient.responses.create(input=external)",
            "not_client.chat.completions.create(messages=[external])",
        )
        for call in negatives:
            with self.subTest(call=call):
                self.assert_no_findings(
                    f"external = requests.get(url).text\n{call}\n"
                )

    def test_known_llm_call_family_keeps_exact_receiver_boundaries(self):
        positives = (
            "llm.invoke(external)",
            "self.llm.invoke(external)",
            "service.chain.invoke(external)",
            "context.chain.run(external)",
            "self.agent.run(external)",
            "self.client.responses.create(input=external)",
            "service.client.chat.completions.create(messages=[external])",
        )
        for call in positives:
            with self.subTest(call=call):
                self.assert_one(
                    f"external = requests.get(url).text\n{call}\n",
                    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                    "external_content",
                    "llm_input",
                    0.75,
                )
        for call in (
            "workflow.invoke(external)",
            "pipeline.invoke(external)",
            "callback.invoke(external)",
            "not_llm.invoke(external)",
            "supply_chain.run(external)",
            "workflow.chain_run(external)",
        ):
            with self.subTest(call=call):
                self.assert_no_findings(
                    f"external = requests.get(url).text\n{call}\n"
                )

    def test_only_explicit_masking_literals_sanitize_secrets(self):
        transformations = (
            "mask_badly(token)",
            "redact_badly(token)",
            "validate(token)",
            "sanitize(token)",
            "token.strip()",
            "token.replace('A', 'B')",
            "re.sub(r'.', '*', token)",
            "re.sub(r'.', '*', token, count=1)",
            "re.sub(r'^.', '*', token)",
            "re.sub(pattern, replacement, token)",
        )
        for expression in transformations:
            with self.subTest(expression=expression):
                self.assert_one(
                    "token = os.getenv('ADMIN_TOKEN')\n"
                    f"candidate = {expression}\n"
                    "llm.invoke(candidate)\n",
                    "LLM02_SECRET_TO_LLM_INPUT",
                    "secret",
                    "llm_input",
                    0.75,
                )
        for literal in ("'[REDACTED]'", "'<REDACTED>'", "'********'"):
            with self.subTest(literal=literal):
                self.assert_no_findings(
                    "token = os.getenv('ADMIN_TOKEN')\n"
                    f"masked = {literal}\n"
                    "llm.invoke(masked)\n"
                )

    def test_model_chain_agent_roles_and_unrelated_calls(self):
        positives = (
            "model = ChatOpenAI()\nmodel.invoke(external)",
            "self.model.ainvoke(external)",
            "model = ChatOpenAI()\nchain = prompt | model\nchain.stream(external)",
            "agent = create_agent(ChatOpenAI(), tools=[])\nagent.invoke(external)",
            "rag_chain.invoke(external)",
        )
        expected_confidence = (0.75, 0.6, 0.75, 0.75, 0.6)
        for body, confidence in zip(positives, expected_confidence):
            with self.subTest(body=body):
                self.assert_one(
                    f"external = requests.get(url).text\n{body}\n",
                    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                    "external_content",
                    "llm_input",
                    confidence,
                )

        for call in (
            "workflow.invoke(external)",
            "pipeline.run(external)",
            "task.stream(external)",
        ):
            with self.subTest(call=call):
                self.assert_no_findings(
                    f"external = requests.get(url).text\n{call}\n"
                )

    def test_retriever_loader_and_vector_store_are_external_sources(self):
        cases = (
            (
                "retrieved = retriever.invoke(question)",
                "model = ChatOpenAI()\nmodel.invoke(retrieved)",
                0.6,
            ),
            (
                "retrieved = self.retriever.ainvoke(question)",
                "model = ChatOpenAI()\nmodel.invoke(retrieved)",
                0.6,
            ),
            (
                "vector_store = FAISS()\nretrieved = vector_store.similarity_search(question)",
                "model = ChatOpenAI()\nmodel.invoke(retrieved)",
                0.75,
            ),
            (
                "loader = PyPDFLoader(path)\ndocs = loader.load()",
                "model = ChatOpenAI()\nmodel.invoke(docs)",
                0.75,
            ),
            (
                "reader = SimpleDirectoryReader(path)\ndocs = reader.load_data()",
                "model = ChatOpenAI()\nmodel.invoke(docs)",
                0.75,
            ),
        )
        for source, sink, confidence in cases:
            with self.subTest(source=source):
                self.assert_one(
                    f"{source}\n{sink}\n",
                    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                    "external_content",
                    "llm_input",
                    confidence,
                )

    def test_query_engine_result_is_llm_output_not_external_content(self):
        findings = self.scan(
            "index = object()\n"
            "query_engine = index.as_query_engine()\n"
            "answer = query_engine.query(question)\n"
            "eval(answer)\n"
        )
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["LLM05_LLM_OUTPUT_TO_CODE_EXECUTION"],
        )
        self.assertEqual(findings[0].source_kind, "llm_output")
        self.assertEqual(findings[0].sink_kind, "code_execution")
        self.assertEqual(findings[0].confidence, 0.9)

    def test_output_extraction_requires_tainted_parent(self):
        cases = (
            "model = ChatOpenAI()\nresponse = model.invoke(prompt)\neval(response.output_text)",
            "model = ChatOpenAI()\nresponse = model.invoke(prompt)\neval(response.content)",
            "response = client.chat.completions.create(messages=[])\n"
            "eval(response.choices[0].message.content)",
            "agent = create_agent(ChatOpenAI(), tools=[])\n"
            "result = agent.invoke({'messages': []})\n"
            "eval(result['messages'][-1].content)",
        )
        for code in cases:
            with self.subTest(code=code):
                self.assert_one(
                    code,
                    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
                    "llm_output",
                    "code_execution",
                    0.9,
                )
        self.assert_no_findings("eval(unrelated.output_text)\n")

    def test_async_stream_for_and_generator_propagation(self):
        cases = (
            "model = ChatOpenAI()\n"
            "async def f():\n"
            "    result = await model.ainvoke(prompt)\n"
            "    eval(result)\n",
            "model = ChatOpenAI()\n"
            "chunks = model.stream(prompt)\n"
            "text = ''.join(chunk.content for chunk in chunks)\n"
            "eval(text)\n",
            "model = ChatOpenAI()\n"
            "async def f():\n"
            "    async for chunk in model.astream(prompt):\n"
            "        eval(chunk.content)\n",
        )
        for code in cases:
            with self.subTest(code=code):
                self.assert_one(
                    code,
                    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
                    "llm_output",
                    "code_execution",
                    0.9,
                )

    def test_attribute_and_constant_subscript_assignments(self):
        cases = (
            "self.token = os.getenv('ADMIN_TOKEN')\nllm.invoke(self.token)",
            "state['token'] = os.getenv('ADMIN_TOKEN')\nllm.invoke(state['token'])",
            "secret = os.getenv('ADMIN_TOKEN')\n"
            "config.secret = secret\n"
            "model = ChatOpenAI()\n"
            "model.invoke(config.secret)",
            "state[0] = os.getenv('ADMIN_TOKEN')\nllm.invoke(state[0])",
        )
        for code in cases:
            with self.subTest(code=code):
                self.assert_one(
                    code,
                    "LLM02_SECRET_TO_LLM_INPUT",
                    "secret",
                    "llm_input",
                    0.75,
                )

    def test_containers_unpacking_walrus_augassign_and_comprehensions(self):
        cases = (
            "model = ChatOpenAI()\nitems = []\nitems.append(model.invoke(prompt))\neval(items[0])",
            "model = ChatOpenAI()\nitems = []\nitems.extend([model.invoke(prompt)])\neval(items[0])",
            "model = ChatOpenAI()\nmapping = {}\nmapping.update({'x': model.invoke(prompt)})\neval(mapping['x'])",
            "model = ChatOpenAI()\nvalues = [model.invoke(prompt)]\na, b = values\neval(a)",
            "model = ChatOpenAI()\nif result := model.invoke(prompt):\n    eval(result)",
            "external = requests.get(url).text\nprompt = ''\nprompt += external\nllm.invoke(prompt)",
            "external = requests.get(url).text\nllm.invoke([item for item in [external]])",
            "external = requests.get(url).text\nllm.invoke(''.join(item for item in [external]))",
        )
        expected = (
            "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
            "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
            "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
            "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
            "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
            "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
            "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
            "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
        )
        for code, rule_id in zip(cases, expected):
            with self.subTest(code=code):
                finding = self.assert_one(
                    code,
                    rule_id,
                    "llm_output" if rule_id.startswith("LLM05") else "external_content",
                    "code_execution" if rule_id.startswith("LLM05") else "llm_input",
                    0.9 if rule_id.startswith("LLM05") else 0.75,
                )
                self.assertEqual(len(self.scan(code)), 1)

    def test_for_loop_propagates_loader_taint(self):
        self.assert_one(
            "loader = PyPDFLoader(path)\n"
            "docs = loader.load()\n"
            "model = ChatOpenAI()\n"
            "for doc in docs:\n"
            "    model.invoke(doc)\n",
            "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
            "external_content",
            "llm_input",
            0.75,
        )

    def test_sql_receivers_wrappers_and_negative_controls(self):
        positives = (
            "cursor.execute(query)",
            "self.cursor.executemany(query)",
            "service.session.execute(text(query))",
            "conn.exec_driver_sql(query)",
        )
        for call in positives:
            with self.subTest(call=call):
                self.assert_one(
                    f"query = llm.invoke(prompt)\n{call}\n",
                    "LLM05_LLM_OUTPUT_TO_SQL",
                    "llm_output",
                    "sql_execution",
                    0.9,
                )
        for call in ("executor.execute(query)", "workflow.execute(query)", "task.execute(query)"):
            with self.subTest(call=call):
                self.assert_no_findings(f"query = llm.invoke(prompt)\n{call}\n")
        self.assert_no_findings(
            "value = llm.invoke(prompt)\n"
            "session.execute('SELECT * FROM t WHERE id=:id', {'id': value})\n"
        )

    def test_fixed_allowlist_invalidates_on_every_supported_mutation(self):
        mutations = (
            "commands['chosen'] = llm.invoke(prompt)",
            "commands.update({'chosen': llm.invoke(prompt)})",
            "commands.setdefault('chosen', llm.invoke(prompt))",
            "commands |= {'chosen': llm.invoke(prompt)}",
            "del commands['status']\ncommands['chosen'] = llm.invoke(prompt)",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_one(
                    "commands = {'status': ['git', 'status']}\n"
                    f"{mutation}\n"
                    "subprocess.run(commands['chosen'])\n",
                    "LLM05_LLM_OUTPUT_TO_SHELL",
                    "llm_output",
                    "shell_execution",
                    0.9,
                )
        self.assert_no_findings(
            "commands = {'status': ['git', 'status']}\n"
            "subprocess.run(commands['status'])\n"
        )

    def test_llm02_llm07_suppression_uses_secret_identity_and_role(self):
        findings = self.scan(
            "system_token = os.getenv('SYSTEM_TOKEN')\n"
            "user_token = os.getenv('USER_TOKEN')\n"
            "messages = [\n"
            "    {'role': 'system', 'content': system_token},\n"
            "    {'role': 'user', 'content': user_token},\n"
            "]\n"
            "llm.invoke(messages)\n"
        )
        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "LLM07_SECRET_IN_SYSTEM_PROMPT",
                "LLM02_SECRET_TO_LLM_INPUT",
            ],
        )
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertIn("SYSTEM_TOKEN", by_rule["LLM07_SECRET_IN_SYSTEM_PROMPT"].source)
        self.assertIn("USER_TOKEN", by_rule["LLM02_SECRET_TO_LLM_INPUT"].source)
        self.assertEqual(by_rule["LLM07_SECRET_IN_SYSTEM_PROMPT"].sink_kind, "system_prompt")
        self.assertEqual(by_rule["LLM02_SECRET_TO_LLM_INPUT"].sink_kind, "llm_input")
        self.assertEqual({finding.confidence for finding in findings}, {0.75})

        same_secret = self.scan(
            "token = os.getenv('SYSTEM_TOKEN')\n"
            "messages = [{'role': 'system', 'content': token}]\n"
            "llm.invoke(messages)\n"
        )
        self.assertEqual(
            [finding.rule_id for finding in same_secret],
            ["LLM07_SECRET_IN_SYSTEM_PROMPT"],
        )

    def test_developer_instructions_and_system_prompt_are_llm07(self):
        cases = (
            "secret = os.getenv('ADMIN_TOKEN')\n"
            "llm.invoke([{'role': 'developer', 'content': secret}])",
            "secret = os.getenv('ADMIN_TOKEN')\n"
            "client.responses.create(input='hello', instructions=secret)",
            "secret = os.getenv('ADMIN_TOKEN')\n"
            "create_agent(model, tools=[], system_prompt=secret)",
            "secret = os.getenv('ADMIN_TOKEN')\n"
            "ChatPromptTemplate.from_messages([('system', secret)])",
            "secret = os.getenv('ADMIN_TOKEN')\nSystemMessage(content=secret)",
        )
        for code in cases:
            with self.subTest(code=code):
                self.assert_one(
                    code,
                    "LLM07_SECRET_IN_SYSTEM_PROMPT",
                    "secret",
                    "system_prompt",
                    0.75,
                )
        self.assert_no_findings(
            "secret = os.getenv('ADMIN_TOKEN')\n"
            "workflow.run(instructions=secret)\n"
        )

    def test_mutated_privileged_message_container_suppresses_only_same_flow(self):
        for mutation in (
            "messages.append({'role': 'system', 'content': secret})",
            "messages[0] = {'role': 'developer', 'content': secret}",
            "messages += [{'role': 'system', 'content': secret}]",
        ):
            with self.subTest(mutation=mutation):
                findings = self.scan(
                    "secret = os.getenv('ADMIN_TOKEN')\n"
                    "messages = []\n"
                    f"{mutation}\n"
                    "llm.invoke(messages)\n"
                )
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    ["LLM07_SECRET_IN_SYSTEM_PROMPT"],
                )

    def test_agent_tool_registration_binding_and_nested_scope(self):
        self.assert_one(
            "@tool\n"
            "def remove_file(path):\n"
            "    os.remove(path)\n"
            "agent = create_agent(model, tools=[remove_file])\n",
            "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
            "tool_capability",
            "destructive_or_execution",
            0.9,
        )
        self.assert_one(
            "def send_email(message):\n"
            "    requests.post(url, data=message)\n"
            "mail_tool = FunctionTool.from_defaults(fn=send_email)\n"
            "agent = SomeAgent.from_tools([mail_tool])\n",
            "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
            "tool_capability",
            "external_side_effect",
            0.75,
        )
        negatives = (
            "def remove_file(path):\n    os.remove(path)\n",
            "@tool\ndef remove_file(path):\n    os.remove(path)\n",
            "@tool\n"
            "def remove_file(path):\n"
            "    os.remove(path)\n"
            "model.bind_tools([remove_file])\n",
            "@tool\n"
            "def safe_tool(path):\n"
            "    def unused():\n"
            "        os.remove(path)\n"
            "    return path\n"
            "agent = create_agent(model, tools=[safe_tool])\n",
        )
        for code in negatives:
            with self.subTest(code=code):
                self.assert_no_findings(code)

    def test_hugging_face_trust_remote_code_true_only(self):
        for call in (
            "AutoModel.from_pretrained(name, trust_remote_code=True)",
            "pipeline('text-generation', trust_remote_code=True)",
        ):
            with self.subTest(call=call):
                self.assert_one(
                    call,
                    "LLM03_TRUST_REMOTE_CODE_TRUE",
                    "remote_model",
                    "remote_code_trust",
                    0.9,
                )
        self.assert_no_findings(
            "AutoModel.from_pretrained(name, trust_remote_code=False)\n"
            "pipeline('text-generation')\n"
        )

    def test_async_exec_checks_every_argument(self):
        self.assert_one(
            "commands = {'python': ['python']}\n"
            "argument = llm.invoke(prompt)\n"
            "asyncio.create_subprocess_exec(commands['python'], argument)\n",
            "LLM05_LLM_OUTPUT_TO_SHELL",
            "llm_output",
            "shell_execution",
            0.9,
        )

    def test_agent_sql_side_effect_unwraps_text_and_excludes_select(self):
        self.assert_one(
            "@tool\n"
            "def write_row():\n"
            "    session.execute(text('DELETE FROM records'))\n"
            "agent = create_agent(model, tools=[write_row])\n",
            "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
            "tool_capability",
            "external_side_effect",
            0.75,
        )
        self.assert_no_findings(
            "@tool\n"
            "def read_rows():\n"
            "    session.execute(text('SELECT * FROM records'))\n"
            "agent = create_agent(model, tools=[read_rows])\n"
        )

    def test_limited_import_alias_resolution(self):
        self.assert_one(
            "import subprocess as sp\n"
            "model = ChatOpenAI()\n"
            "result = model.invoke(prompt)\n"
            "sp.run(result)\n",
            "LLM05_LLM_OUTPUT_TO_SHELL",
            "llm_output",
            "shell_execution",
            0.9,
        )
        self.assert_one(
            "from os import system as run_system\n"
            "model = ChatOpenAI()\n"
            "result = model.invoke(prompt)\n"
            "run_system(result)\n",
            "LLM05_LLM_OUTPUT_TO_SHELL",
            "llm_output",
            "shell_execution",
            0.9,
        )
        self.assert_one(
            "from openai import OpenAI as OA\n"
            "client = OA()\n"
            "external = requests.get(url).text\n"
            "client.responses.create(input=external)\n",
            "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
            "external_content",
            "llm_input",
            0.75,
        )


if __name__ == "__main__":
    unittest.main()
