"""Rule metadata and pattern constants for the Layer A analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass


# ---------------------------------------------------------------------------
# OWASP categories (OWASP Top 10 for LLM Applications 2025)
# ---------------------------------------------------------------------------
OWASP = {
    "LLM01": "LLM01:2025 Prompt Injection",
    "LLM02": "LLM02:2025 Sensitive Information Disclosure",
    "LLM03": "LLM03:2025 Supply Chain",
    "LLM05": "LLM05:2025 Improper Output Handling",
    "LLM06": "LLM06:2025 Excessive Agency",
    "LLM07": "LLM07:2025 System Prompt Leakage",
}


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    category: str
    detection_type: str
    source_kind: str
    sink_kind: str
    status: str
    severity: str


REQUIRED_RULES: tuple[RuleMetadata, ...] = (
    RuleMetadata(
        rule_id="LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
        category=OWASP["LLM01"],
        detection_type="ast_taint",
        source_kind="external_content",
        sink_kind="llm_input",
        status="risky",
        severity="medium",
    ),
    RuleMetadata(
        rule_id="LLM02_SECRET_TO_LLM_INPUT",
        category=OWASP["LLM02"],
        detection_type="ast_taint",
        source_kind="secret",
        sink_kind="llm_input",
        status="vulnerable",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM03_UNSAFE_DESERIALIZATION",
        category=OWASP["LLM03"],
        detection_type="ast_search",
        source_kind="serialized_artifact",
        sink_kind="unsafe_deserialization",
        status="risky",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM03_TRUST_REMOTE_CODE_TRUE",
        category=OWASP["LLM03"],
        detection_type="ast_search",
        source_kind="remote_model",
        sink_kind="remote_code_trust",
        status="risky",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
        category=OWASP["LLM05"],
        detection_type="ast_taint",
        source_kind="llm_output",
        sink_kind="code_execution",
        status="vulnerable",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM05_LLM_OUTPUT_TO_SHELL",
        category=OWASP["LLM05"],
        detection_type="ast_taint",
        source_kind="llm_output",
        sink_kind="shell_execution",
        status="vulnerable",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM05_LLM_OUTPUT_TO_SQL",
        category=OWASP["LLM05"],
        detection_type="ast_taint",
        source_kind="llm_output",
        sink_kind="sql_execution",
        status="vulnerable",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
        category=OWASP["LLM06"],
        detection_type="ast_capability",
        source_kind="tool_capability",
        sink_kind="destructive_or_execution",
        status="risky",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
        category=OWASP["LLM06"],
        detection_type="ast_capability",
        source_kind="tool_capability",
        sink_kind="external_side_effect",
        status="risky",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM07_SECRET_IN_SYSTEM_PROMPT",
        category=OWASP["LLM07"],
        detection_type="ast_taint",
        source_kind="secret",
        sink_kind="system_prompt",
        status="vulnerable",
        severity="high",
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in REQUIRED_RULES}
RULES = RULES_BY_ID

DEFAULT_CONFIDENCE = {
    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT": 0.75,
    "LLM02_SECRET_TO_LLM_INPUT": 0.75,
    "LLM03_UNSAFE_DESERIALIZATION": 0.90,
    "LLM03_TRUST_REMOTE_CODE_TRUE": 0.90,
    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION": 0.90,
    "LLM05_LLM_OUTPUT_TO_SHELL": 0.90,
    "LLM05_LLM_OUTPUT_TO_SQL": 0.90,
    "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION": 0.90,
    "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT": 0.75,
    "LLM07_SECRET_IN_SYSTEM_PROMPT": 0.75,
}


def get_rule(rule_id: str) -> RuleMetadata:
    return RULES_BY_ID[rule_id]


SECRET_ATTRS = {"email", "ssn", "phone", "password", "token", "secret", "apikey", "api_key"}

LLM_OUTPUT_ATTRS = {"content"}
LLM_OUTPUT_CALL_SUFFIXES = {"invoke", "predict", "ask_llm", "call_llm", "generate_response"}
LLM_OUTPUT_CALL_NAMES = {"ask_llm", "call_llm", "generate_response"}

EXTERNAL_CONTENT_ATTRS = {"text", "page_content", "body"}
EXTERNAL_CONTENT_CALL_SUFFIXES = {"read", "read_text", "get_relevant_documents", "similarity_search"}

EXTERNAL_NAME_HINTS = ["page_text", "file_content", "document_text", "email_body"]

# ---------------------------------------------------------------------------
# Sink dictionaries
# ---------------------------------------------------------------------------
CODE_EXEC_NAMES = {"eval", "exec", "compile"}

COMMAND_EXEC_SUFFIXES = {"system", "run", "check_output", "Popen", "call", "check_call"}
COMMAND_EXEC_MODULES = {"subprocess", "os"}

SQL_EXEC_SUFFIXES = {"execute", "executemany"}
SQL_EXEC_ROOTS = {"cursor", "conn", "connection", "db", "session", "engine"}

LLM_INPUT_ENDSWITH = (
    "chat.completions.create",
    "responses.create",
    "messages.create",
)

LLM_INPUT_SUFFIXES = {"invoke", "run", "predict"}
LLM_INPUT_NAMES = {"PromptTemplate", "ChatPromptTemplate"}

EXTERNAL_LOADERS = {"PyPDFLoader", "WebBaseLoader"}
EXTERNAL_RETRIEVAL_SUFFIXES = {"get_relevant_documents", "similarity_search"}

LLM_CALL_ROOTS = {"llm", "chain", "agent"}
LLM_OUTPUT_ATTR_SUFFIXES = ("output_text", "choices.message.content")
LLM_OUTPUT_CALL_ENDINGS = (
    "client.responses.create",
    "client.chat.completions.create",
)

UNSAFE_DESERIALIZATION_CALLS = {
    "pickle.load",
    "pickle.loads",
    "joblib.load",
    "torch.load",
}

SHELL_EXEC_CALLS = {
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}

DESTRUCTIVE_OR_EXECUTION_CALLS = SHELL_EXEC_CALLS | {
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
    "Path.unlink",
    "eval",
    "exec",
}

EXTERNAL_SIDE_EFFECT_CALLS = {
    "smtp.sendmail",
    "send_email",
    "requests.post",
    "requests.put",
    "requests.delete",
}

TOOL_FACTORY_SUFFIXES = {"Tool.from_function", "StructuredTool.from_function"}
TOOL_CONSTRUCTOR_NAMES = {"Tool", "StructuredTool"}
AGENT_BINDING_CALLS = {
    "initialize_agent",
    "AgentExecutor",
    "create_react_agent",
    "create_openai_functions_agent",
}

SQL_WRITE_VERBS = ("insert", "update", "delete", "drop", "alter", "create", "truncate")

RULE_ID_BY_KIND = {
    "llm01_external_to_prompt": "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
    "llm02_secret_to_prompt": "LLM02_SECRET_TO_LLM_INPUT",
    "llm02_exposure": "LLM02_SECRET_TO_LLM_INPUT",
    "llm03_deserialization": "LLM03_UNSAFE_DESERIALIZATION",
    "llm03_remote_code": "LLM03_TRUST_REMOTE_CODE_TRUE",
    "llm05_code_exec": "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
    "llm05_command_exec": "LLM05_LLM_OUTPUT_TO_SHELL",
    "llm05_sql_exec": "LLM05_LLM_OUTPUT_TO_SQL",
    "llm06_agent_tool": "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
    "llm07_secret_in_system": "LLM07_SECRET_IN_SYSTEM_PROMPT",
}

RULE_KIND_BY_ID = {value: key for key, value in RULE_ID_BY_KIND.items()}

SOURCE_SINK_KIND_BY_RULE_ID = {
    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT": ("external_content", "llm_input"),
    "LLM02_SECRET_TO_LLM_INPUT": ("secret", "llm_input"),
    "LLM03_UNSAFE_DESERIALIZATION": ("serialized_artifact", "unsafe_deserialization"),
    "LLM03_TRUST_REMOTE_CODE_TRUE": ("remote_model", "remote_code_trust"),
    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION": ("llm_output", "code_execution"),
    "LLM05_LLM_OUTPUT_TO_SHELL": ("llm_output", "shell_execution"),
    "LLM05_LLM_OUTPUT_TO_SQL": ("llm_output", "sql_execution"),
    "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION": ("tool_capability", "destructive_or_execution"),
    "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT": ("tool_capability", "external_side_effect"),
    "LLM07_SECRET_IN_SYSTEM_PROMPT": ("secret", "system_prompt"),
}

# ---------------------------------------------------------------------------
# Finding templates (keyed by analyzer "kind")
# ---------------------------------------------------------------------------
TEMPLATES = {
    "llm05_code_exec": {
        "owasp_category": OWASP["LLM05"],
        "severity": "critical",
        "status": "vulnerable",
        "confidence": 0.90,
        "title": "LLM output flows into code execution",
        "reason": "LLM/untrusted output is passed to eval()/exec()/compile(), allowing arbitrary Python execution.",
        "fix": "Never execute model output. Use allow-list actions, structured outputs, or schema validation instead.",
    },
    "llm05_command_exec": {
        "owasp_category": OWASP["LLM05"],
        "severity": "critical",
        "status": "vulnerable",
        "confidence": 0.90,
        "title": "LLM output flows into shell/command execution",
        "reason": "Untrusted data reaches a system command (os.system/subprocess), enabling command injection. shell=True increases the risk.",
        "fix": "Avoid shell execution of model output. Use fixed commands with argument lists and validate inputs.",
    },
    "llm05_sql_exec": {
        "owasp_category": OWASP["LLM05"],
        "severity": "high",
        "status": "vulnerable",
        "confidence": 0.75,
        "title": "Untrusted data flows into SQL execution",
        "reason": "Model/external data is passed to a SQL execute() call, risking SQL injection.",
        "fix": "Use parameterized queries / prepared statements; never interpolate untrusted data into SQL.",
    },
    "llm01_external_to_prompt": {
        "owasp_category": OWASP["LLM01"],
        "severity": "medium",
        "status": "risky",
        "confidence": 0.75,
        "title": "External content flows into LLM prompt",
        "reason": "External/untrusted content (web page, file, RAG document) is placed into the prompt, enabling indirect prompt injection.",
        "fix": "Treat external content as data: isolate it, add guardrails, and do not let it override system instructions.",
    },
    "llm02_secret_to_prompt": {
        "owasp_category": OWASP["LLM02"],
        "severity": "high",
        "status": "vulnerable",
        "confidence": 0.85,
        "title": "Secret flows into LLM input",
        "reason": "A secret/credential is included in the prompt or messages sent to the LLM.",
        "fix": "Keep secrets server-side. Never place credentials in prompts or messages.",
    },
    "llm07_secret_in_system": {
        "owasp_category": OWASP["LLM07"],
        "severity": "high",
        "status": "vulnerable",
        "confidence": 0.85,
        "title": "Secret included in system prompt",
        "reason": "A secret/internal value is embedded in the system prompt, which can be leaked via system-prompt extraction.",
        "fix": "Remove secrets from system prompts; fetch sensitive data through secured backend calls at request time.",
    },
    "llm02_exposure": {
        "owasp_category": OWASP["LLM02"],
        "severity": "medium",
        "status": "risky",
        "confidence": 0.75,
        "title": "Sensitive data flows into a logging/output sink",
        "reason": "Secret or system-prompt content is written to logs/output/network, risking disclosure.",
        "fix": "Redact secrets before logging or returning data.",
    },
    "llm06_agent_tool": {
        "owasp_category": OWASP["LLM06"],
        "severity": "critical",
        "status": "vulnerable",
        "confidence": 0.90,
        "title": "Agent has access to a high-impact tool",
        "reason": "An LLM agent is wired to a tool with dangerous capabilities (shell/file/DB/network).",
        "fix": "Apply least privilege: restrict tools, require human approval, and sandbox high-impact actions.",
    },
    "llm03_deserialization": {
        "owasp_category": OWASP["LLM03"],
        "severity": "high",
        "status": "risky",
        "confidence": 0.75,
        "title": "Unsafe deserialization of external artifact",
        "reason": "Loading pickled/serialized model artifacts can execute arbitrary code if the file is untrusted.",
        "fix": "Use safe formats (e.g. safetensors), verify integrity, and only load trusted artifacts.",
    },
    "llm03_remote_code": {
        "owasp_category": OWASP["LLM03"],
        "severity": "high",
        "status": "risky",
        "confidence": 0.75,
        "title": "Remote model code execution is trusted",
        "reason": "trust_remote_code=True executes code from the model repository, a supply-chain risk.",
        "fix": "Avoid trust_remote_code unless the source is fully trusted and pinned.",
    },
}

RULE_TABLE = [
    {"no": index, **asdict(rule)}
    for index, rule in enumerate(REQUIRED_RULES, start=1)
]

DICTIONARY = [
    ("Source", "requests.get(...).text / open(...).read()", "External content", "LLM01"),
    ("Source", "os.getenv(...) / os.environ[...] / api_key", "Secret", "LLM02/LLM07"),
    ("Source", "llm.invoke(...) / response.output_text", "LLM output", "LLM05"),
    ("Source", "pickle/joblib/torch artifacts", "Serialized artifact", "LLM03"),
    ("Source", "Tool functions bound to agents", "Tool capability", "LLM06"),
    ("Sink", "llm.invoke(...) / messages= / input=", "LLM input", "LLM01/LLM02"),
    ("Sink", '{"role": "system", "content": ...}', "System prompt", "LLM07"),
    ("Sink", "eval(...) / exec(...)", "Code execution", "LLM05"),
    ("Sink", "os.system(...) / subprocess.run(...)", "Shell execution", "LLM05"),
    ("Sink", "cursor.execute(...) / db.execute(...)", "SQL execution", "LLM05"),
    ("Sink", "pickle.load / torch.load / joblib.load", "Unsafe deserialization", "LLM03"),
    ("Sink", "from_pretrained(..., trust_remote_code=True)", "Remote code trust", "LLM03"),
    ("Sink", "initialize_agent(... tools ...)", "Agent tool binding", "LLM06"),
]
