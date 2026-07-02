"""Source/sink dictionaries, dangerous-pattern catalogs, and finding templates.

This module is pure data. The analysis logic lives in ``analyzer.py``.
All patterns here are heuristics for a *prototype* and are intentionally simple.
"""

from __future__ import annotations

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

# ---------------------------------------------------------------------------
# Source dictionaries
# ---------------------------------------------------------------------------

SECRET_NAME_PATTERNS = [
    "api_key", "apikey", "token", "access_token", "refresh_token",
    "secret", "password", "passwd", "credential", "private_key",
    "db_url", "database_url", "openai_api_key", "anthropic_api_key",
    "authorization", "bearer",
]

SECRET_LITERAL_PATTERNS = [
    "sk-", "ghp_", "xoxb-", "Bearer ",
    "-----BEGIN PRIVATE KEY-----",
    "postgresql://", "mysql://", "mongodb://",
]

LLM_OUTPUT_ATTRS = {"content"}
LLM_OUTPUT_CALL_SUFFIXES = {"invoke", "predict", "ask_llm", "call_llm", "generate_response"}
LLM_OUTPUT_CALL_NAMES = {"ask_llm", "call_llm", "generate_response"}

EXTERNAL_CONTENT_ATTRS = {"text", "page_content", "body"}
EXTERNAL_CONTENT_CALL_SUFFIXES = {"read", "get_relevant_documents", "similarity_search"}

EXTERNAL_NAME_HINTS = ["page_text", "file_content", "document_text", "email_body"]

# ---------------------------------------------------------------------------
# Sink dictionaries
# ---------------------------------------------------------------------------
CODE_EXEC_NAMES = {"eval", "exec", "compile"}

COMMAND_EXEC_SUFFIXES = {"system", "run", "check_output", "Popen", "call", "check_call"}
COMMAND_EXEC_MODULES = {"subprocess", "os"}

SQL_EXEC_SUFFIXES = {"execute", "executemany"}

LLM_INPUT_ENDSWITH = (
    "chat.completions.create",
    "responses.create",
    "messages.create",
)
LLM_INPUT_SUFFIXES = {"invoke", "run", "predict"}
LLM_INPUT_NAMES = {"PromptTemplate", "ChatPromptTemplate"}

EXPOSURE_SUFFIXES = {"print", "info", "debug", "warning", "error", "send_email", "post"}

DESERIALIZE_CALLS = {"pickle.load", "pickle.loads", "torch.load", "joblib.load"}

# ---------------------------------------------------------------------------
# Agent / tool (LLM06)
# ---------------------------------------------------------------------------
DANGEROUS_TOOL_NAMES = {
    "shell", "command", "terminal", "delete_file", "write_file",
    "send_email", "db_write", "execute_sql", "run_command", "exec",
}

CAPABILITY_DESCRIPTIONS = {
    "shell": "shell command execution",
    "file_delete": "file deletion",
    "file_write": "file write",
    "code_exec": "dynamic code execution",
    "network_post": "external network POST",
    "email": "email sending",
    "sql": "database write/query",
}

# ---------------------------------------------------------------------------
# Finding templates (keyed by analyzer "kind")
# ---------------------------------------------------------------------------
TEMPLATES = {
    "llm05_code_exec": {
        "owasp_category": OWASP["LLM05"],
        "severity": "critical",
        "status": "vulnerable",
        "confidence": "high",
        "title": "LLM output flows into code execution",
        "reason": "LLM/untrusted output is passed to eval()/exec()/compile(), "
                  "allowing arbitrary Python execution.",
        "fix": "Never execute model output. Use allow-list actions, structured "
               "outputs, or schema validation instead.",
    },
    "llm05_command_exec": {
        "owasp_category": OWASP["LLM05"],
        "severity": "critical",
        "status": "vulnerable",
        "confidence": "high",
        "title": "LLM output flows into shell/command execution",
        "reason": "Untrusted data reaches a system command (os.system/subprocess), "
                  "enabling command injection. shell=True increases the risk.",
        "fix": "Avoid shell execution of model output. Use fixed commands with "
               "argument lists and validate inputs.",
    },
    "llm05_sql_exec": {
        "owasp_category": OWASP["LLM05"],
        "severity": "high",
        "status": "vulnerable",
        "confidence": "medium",
        "title": "Untrusted data flows into SQL execution",
        "reason": "Model/external data is passed to a SQL execute() call, "
                  "risking SQL injection.",
        "fix": "Use parameterized queries / prepared statements; never interpolate "
               "untrusted data into SQL.",
    },
    "llm01_external_to_prompt": {
        "owasp_category": OWASP["LLM01"],
        "severity": "medium",
        "status": "risky",
        "confidence": "medium",
        "title": "External content flows into LLM prompt",
        "reason": "External/untrusted content (web page, file, RAG document) is placed "
                  "into the prompt, enabling indirect prompt injection.",
        "fix": "Treat external content as data: isolate it, add guardrails, and do not "
               "let it override system instructions.",
    },
    "llm02_secret_to_prompt": {
        "owasp_category": OWASP["LLM02"],
        "severity": "high",
        "status": "vulnerable",
        "confidence": "high",
        "title": "Secret flows into LLM input",
        "reason": "A secret/credential is included in the prompt or messages sent to the LLM.",
        "fix": "Keep secrets server-side. Never place credentials in prompts or messages.",
    },
    "llm07_secret_in_system": {
        "owasp_category": OWASP["LLM07"],
        "severity": "high",
        "status": "vulnerable",
        "confidence": "high",
        "title": "Secret included in system prompt",
        "reason": "A secret/internal value is embedded in the system prompt, which can "
                  "be leaked via system-prompt extraction.",
        "fix": "Remove secrets from system prompts; fetch sensitive data through secured "
               "backend calls at request time.",
    },
    "llm02_exposure": {
        "owasp_category": OWASP["LLM02"],
        "severity": "medium",
        "status": "risky",
        "confidence": "medium",
        "title": "Sensitive data flows into a logging/output sink",
        "reason": "Secret or system-prompt content is written to logs/output/network, "
                  "risking disclosure.",
        "fix": "Redact secrets before logging or returning data.",
    },
    "llm06_agent_tool": {
        "owasp_category": OWASP["LLM06"],
        "severity": "critical",
        "status": "vulnerable",
        "confidence": "high",
        "title": "Agent has access to a high-impact tool",
        "reason": "An LLM agent is wired to a tool with dangerous capabilities "
                  "(shell/file/DB/network).",
        "fix": "Apply least privilege: restrict tools, require human approval, and "
               "sandbox high-impact actions.",
    },
    "llm03_deserialization": {
        "owasp_category": OWASP["LLM03"],
        "severity": "high",
        "status": "risky",
        "confidence": "medium",
        "title": "Unsafe deserialization of external artifact",
        "reason": "Loading pickled/serialized model artifacts can execute arbitrary code "
                  "if the file is untrusted.",
        "fix": "Use safe formats (e.g. safetensors), verify integrity, and only load "
               "trusted artifacts.",
    },
    "llm03_remote_code": {
        "owasp_category": OWASP["LLM03"],
        "severity": "high",
        "status": "risky",
        "confidence": "medium",
        "title": "Remote model code execution is trusted",
        "reason": "trust_remote_code=True executes code from the model repository, "
                  "a supply-chain risk.",
        "fix": "Avoid trust_remote_code unless the source is fully trusted and pinned.",
    },
}

# ---------------------------------------------------------------------------
# Source/Sink dictionary — UI Source/Sink Dictionary 탭 표시용
# ---------------------------------------------------------------------------
DICTIONARY = [
    ("Source", "response.choices[0].message.content", "LLM output (untrusted)", "LLM05"),
    ("Source", "response.content", "LLM output (untrusted)", "LLM05"),
    ("Source", "llm.invoke(...) / chain.run(...) / agent.run(...)", "LLM output (untrusted)", "LLM05"),
    ("Source", "ask_llm() / call_llm() / generate_response()", "LLM output (untrusted)", "LLM05"),
    ("Source", "requests.get(...).text / .content", "External web content", "LLM01"),
    ("Source", "open(...).read() / uploaded_file.read()", "External file content", "LLM01"),
    ("Source", "doc.page_content / similarity_search(...)", "RAG / retrieved content", "LLM01"),
    ("Source", "api_key, token, password, secret, ...", "Secret-like variable name", "LLM02/LLM07"),
    ("Source", "sk-..., ghp_..., postgresql://...", "Secret-like literal", "LLM02/LLM07"),
    ("Sink", "eval(...) / exec(...) / compile(...)", "Code execution", "LLM05"),
    ("Sink", "os.system(...) / subprocess.run(..., shell=True)", "Command execution", "LLM05"),
    ("Sink", "cursor.execute(...) / db.execute(...)", "SQL execution", "LLM05"),
    ("Sink", "chat.completions.create / llm.invoke / messages[].content", "LLM input", "LLM01/LLM02/LLM07"),
    ("Sink", "{\"role\": \"system\", \"content\": ...}", "System prompt", "LLM07"),
    ("Sink", "print(...) / logger.debug(...) / requests.post(...)", "Logging / exposure", "LLM02"),
    ("Sink", "Tool(...) / @tool / initialize_agent(...)", "Agent tool capability", "LLM06"),
    ("Sink", "pickle.load / torch.load / joblib.load", "Unsafe deserialization", "LLM03"),
    ("Sink", "from_pretrained(..., trust_remote_code=True)", "Remote code execution", "LLM03"),
]

# ---------------------------------------------------------------------------
# Required Rule Table (10개) — About 탭 표시용
# ---------------------------------------------------------------------------

RULE_TABLE: list[dict] = [
    {
        "No": 1,
        "Rule ID":        "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
        "Category":       "LLM01:2025 Prompt Injection",
        "Detection Type": "ast_taint",
        "Source Kind":    "external_content",
        "Sink Kind":      "llm_input",
        "Status":         "risky",
        "Severity":       "medium",
        "Confidence":     0.75,
    },
    {
        "No": 2,
        "Rule ID":        "LLM02_SECRET_TO_LLM_INPUT",
        "Category":       "LLM02:2025 Sensitive Information Disclosure",
        "Detection Type": "ast_taint",
        "Source Kind":    "secret",
        "Sink Kind":      "llm_input",
        "Status":         "vulnerable",
        "Severity":       "high",
        "Confidence":     0.75,
    },
    {
        "No": 3,
        "Rule ID":        "LLM03_UNSAFE_DESERIALIZATION",
        "Category":       "LLM03:2025 Supply Chain",
        "Detection Type": "ast_search",
        "Source Kind":    "serialized_artifact",
        "Sink Kind":      "unsafe_deserialization",
        "Status":         "risky",
        "Severity":       "high",
        "Confidence":     0.9,
    },
    {
        "No": 4,
        "Rule ID":        "LLM03_TRUST_REMOTE_CODE_TRUE",
        "Category":       "LLM03:2025 Supply Chain",
        "Detection Type": "ast_search",
        "Source Kind":    "remote_model",
        "Sink Kind":      "remote_code_trust",
        "Status":         "risky",
        "Severity":       "high",
        "Confidence":     0.9,
    },
    {
        "No": 5,
        "Rule ID":        "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
        "Category":       "LLM05:2025 Improper Output Handling",
        "Detection Type": "ast_taint",
        "Source Kind":    "llm_output",
        "Sink Kind":      "code_execution",
        "Status":         "vulnerable",
        "Severity":       "critical",
        "Confidence":     0.9,
    },
    {
        "No": 6,
        "Rule ID":        "LLM05_LLM_OUTPUT_TO_SHELL",
        "Category":       "LLM05:2025 Improper Output Handling",
        "Detection Type": "ast_taint",
        "Source Kind":    "llm_output",
        "Sink Kind":      "shell_execution",
        "Status":         "vulnerable",
        "Severity":       "critical",
        "Confidence":     0.9,
    },
    {
        "No": 7,
        "Rule ID":        "LLM05_LLM_OUTPUT_TO_SQL",
        "Category":       "LLM05:2025 Improper Output Handling",
        "Detection Type": "ast_taint",
        "Source Kind":    "llm_output",
        "Sink Kind":      "sql_execution",
        "Status":         "vulnerable",
        "Severity":       "critical",
        "Confidence":     0.9,
    },
    {
        "No": 8,
        "Rule ID":        "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
        "Category":       "LLM06:2025 Excessive Agency",
        "Detection Type": "ast_capability",
        "Source Kind":    "tool_capability",
        "Sink Kind":      "destructive_or_execution",
        "Status":         "risky",
        "Severity":       "critical",
        "Confidence":     0.9,
    },
    {
        "No": 9,
        "Rule ID":        "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
        "Category":       "LLM06:2025 Excessive Agency",
        "Detection Type": "ast_capability",
        "Source Kind":    "tool_capability",
        "Sink Kind":      "external_side_effect",
        "Status":         "risky",
        "Severity":       "high",
        "Confidence":     0.75,
    },
    {
        "No": 10,
        "Rule ID":        "LLM07_SECRET_IN_SYSTEM_PROMPT",
        "Category":       "LLM07:2025 System Prompt Leakage",
        "Detection Type": "ast_taint",
        "Source Kind":    "secret",
        "Sink Kind":      "system_prompt",
        "Status":         "vulnerable",
        "Severity":       "high",
        "Confidence":     0.75,
    },
]