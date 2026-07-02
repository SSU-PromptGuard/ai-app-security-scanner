"""Rule metadata and pattern constants for the Layer A analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass


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
        category="LLM01:2025 Prompt Injection",
        detection_type="ast_taint",
        source_kind="external_content",
        sink_kind="llm_input",
        status="risky",
        severity="medium",
    ),
    RuleMetadata(
        rule_id="LLM02_SECRET_TO_LLM_INPUT",
        category="LLM02:2025 Sensitive Information Disclosure",
        detection_type="ast_taint",
        source_kind="secret",
        sink_kind="llm_input",
        status="vulnerable",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM03_UNSAFE_DESERIALIZATION",
        category="LLM03:2025 Supply Chain",
        detection_type="ast_search",
        source_kind="serialized_artifact",
        sink_kind="unsafe_deserialization",
        status="risky",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM03_TRUST_REMOTE_CODE_TRUE",
        category="LLM03:2025 Supply Chain",
        detection_type="ast_search",
        source_kind="remote_model",
        sink_kind="remote_code_trust",
        status="risky",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
        category="LLM05:2025 Improper Output Handling",
        detection_type="ast_taint",
        source_kind="llm_output",
        sink_kind="code_execution",
        status="vulnerable",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM05_LLM_OUTPUT_TO_SHELL",
        category="LLM05:2025 Improper Output Handling",
        detection_type="ast_taint",
        source_kind="llm_output",
        sink_kind="shell_execution",
        status="vulnerable",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM05_LLM_OUTPUT_TO_SQL",
        category="LLM05:2025 Improper Output Handling",
        detection_type="ast_taint",
        source_kind="llm_output",
        sink_kind="sql_execution",
        status="vulnerable",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
        category="LLM06:2025 Excessive Agency",
        detection_type="ast_capability",
        source_kind="tool_capability",
        sink_kind="destructive_or_execution",
        status="risky",
        severity="critical",
    ),
    RuleMetadata(
        rule_id="LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
        category="LLM06:2025 Excessive Agency",
        detection_type="ast_capability",
        source_kind="tool_capability",
        sink_kind="external_side_effect",
        status="risky",
        severity="high",
    ),
    RuleMetadata(
        rule_id="LLM07_SECRET_IN_SYSTEM_PROMPT",
        category="LLM07:2025 System Prompt Leakage",
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


# Source families.
SECRET_NAME_PARTS = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "credentials",
    "database_url",
    "db_url",
    "private_key",
)

SECRET_ENV_KEY_PARTS = (
    "KEY",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "DATABASE_URL",
    "DB_URL",
    "CREDENTIAL",
    "PRIVATE_KEY",
)

SECRET_LITERAL_HINTS = (
    "sk-",
    "ghp_",
    "xoxb-",
    "postgres://",
    "postgresql://",
    "mysql://",
    "-----BEGIN PRIVATE KEY-----",
)

MASKING_HINTS = ("[REDACTED]", "<REDACTED>", "REDACTED", "***", "****", "xxxxx")

EXTERNAL_NAME_HINTS = (
    "page_text",
    "file_content",
    "document_text",
    "doc_text",
    "email_body",
    "retrieved",
    "retrieval",
)

REQUESTS_CONTENT_METHODS = {"requests.get", "requests.post"}
EXTERNAL_LOADERS = {"PyPDFLoader", "WebBaseLoader"}
EXTERNAL_RETRIEVAL_SUFFIXES = {"get_relevant_documents", "similarity_search"}

LLM_CALL_ROOTS = {"llm", "chain", "agent"}
LLM_OUTPUT_ATTR_SUFFIXES = ("output_text", "choices.message.content")
LLM_OUTPUT_CALL_ENDINGS = (
    "client.responses.create",
    "client.chat.completions.create",
)

# Sink families.
UNSAFE_DESERIALIZATION_CALLS = {
    "pickle.load",
    "pickle.loads",
    "joblib.load",
    "torch.load",
}

CODE_EXEC_CALLS = {"eval", "exec"}
SHELL_EXEC_CALLS = {
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
SQL_EXEC_SUFFIXES = {"execute"}
SQL_EXEC_ROOTS = {"cursor", "conn", "connection", "db", "session", "engine"}

LLM_INPUT_KEYWORDS = {"messages", "input", "prompt", "content", "text"}
SYSTEM_PROMPT_NAMES = {"system_prompt", "system_message", "system_instructions"}

# Agent/tool capability patterns.
TOOL_FACTORY_SUFFIXES = {"Tool.from_function", "StructuredTool.from_function"}
TOOL_CONSTRUCTOR_NAMES = {"Tool", "StructuredTool"}
AGENT_BINDING_CALLS = {
    "initialize_agent",
    "AgentExecutor",
    "create_react_agent",
    "create_openai_functions_agent",
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
SQL_WRITE_VERBS = ("insert", "update", "delete", "drop", "alter", "create", "truncate")


# UI/backward-compatible tables.
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
