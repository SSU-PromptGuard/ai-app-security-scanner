from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from scanner import Finding, ScanResult, analyze_code, scan_code, scan_file
from scanner.models import build_finding_id
from scanner.rules import DEFAULT_CONFIDENCE, REQUIRED_RULES, RULES


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "dev"
SCHEMA_PATH = ROOT / "schemas" / "result_schema.json"

EXPECTED_RULES = {
    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT": (
        "LLM01:2025 Prompt Injection",
        "ast_taint",
        "external_content",
        "llm_input",
        "risky",
        "medium",
        0.75,
    ),
    "LLM02_SECRET_TO_LLM_INPUT": (
        "LLM02:2025 Sensitive Information Disclosure",
        "ast_taint",
        "secret",
        "llm_input",
        "vulnerable",
        "high",
        0.75,
    ),
    "LLM03_UNSAFE_DESERIALIZATION": (
        "LLM03:2025 Supply Chain",
        "ast_search",
        "serialized_artifact",
        "unsafe_deserialization",
        "risky",
        "high",
        0.9,
    ),
    "LLM03_TRUST_REMOTE_CODE_TRUE": (
        "LLM03:2025 Supply Chain",
        "ast_search",
        "remote_model",
        "remote_code_trust",
        "risky",
        "high",
        0.9,
    ),
    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION": (
        "LLM05:2025 Improper Output Handling",
        "ast_taint",
        "llm_output",
        "code_execution",
        "vulnerable",
        "critical",
        0.9,
    ),
    "LLM05_LLM_OUTPUT_TO_SHELL": (
        "LLM05:2025 Improper Output Handling",
        "ast_taint",
        "llm_output",
        "shell_execution",
        "vulnerable",
        "critical",
        0.9,
    ),
    "LLM05_LLM_OUTPUT_TO_SQL": (
        "LLM05:2025 Improper Output Handling",
        "ast_taint",
        "llm_output",
        "sql_execution",
        "vulnerable",
        "critical",
        0.9,
    ),
    "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION": (
        "LLM06:2025 Excessive Agency",
        "ast_capability",
        "tool_capability",
        "destructive_or_execution",
        "risky",
        "critical",
        0.9,
    ),
    "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT": (
        "LLM06:2025 Excessive Agency",
        "ast_capability",
        "tool_capability",
        "external_side_effect",
        "risky",
        "high",
        0.75,
    ),
    "LLM07_SECRET_IN_SYSTEM_PROMPT": (
        "LLM07:2025 System Prompt Leakage",
        "ast_taint",
        "secret",
        "system_prompt",
        "vulnerable",
        "high",
        0.75,
    ),
}

SAMPLE_EXPECTATIONS = {
    "llm01_external_to_prompt.py": {"LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT"},
    "llm02_secret_to_prompt.py": {"LLM02_SECRET_TO_LLM_INPUT"},
    "llm03_unsafe_load.py": {"LLM03_UNSAFE_DESERIALIZATION"},
    "llm03_trust_remote_code.py": {"LLM03_TRUST_REMOTE_CODE_TRUE"},
    "llm05_eval.py": {"LLM05_LLM_OUTPUT_TO_CODE_EXECUTION"},
    "llm05_shell.py": {"LLM05_LLM_OUTPUT_TO_SHELL"},
    "llm05_sql.py": {"LLM05_LLM_OUTPUT_TO_SQL"},
    "llm06_agent_destructive_tool.py": {
        "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION"
    },
    "llm06_agent_external_side_effect.py": {
        "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT"
    },
    "llm07_secret_system_prompt.py": {"LLM07_SECRET_IN_SYSTEM_PROMPT"},
}

SAFE_SAMPLES = {
    "safe_basic_llm_call.py",
    "safe_env_client_only.py",
    "safe_readonly_tool.py",
}

FINDING_FIELDS = {
    "finding_id",
    "rule_id",
    "category",
    "status",
    "severity",
    "file",
    "line",
    "source_kind",
    "source",
    "sink_kind",
    "sink",
    "flow",
    "evidence",
    "confidence",
}

EXPECTED_CATEGORIES = {
    "LLM01:2025 Prompt Injection",
    "LLM02:2025 Sensitive Information Disclosure",
    "LLM03:2025 Supply Chain",
    "LLM05:2025 Improper Output Handling",
    "LLM06:2025 Excessive Agency",
    "LLM07:2025 System Prompt Leakage",
}


def rule_ids(result: ScanResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


class LayerAContractTests(unittest.TestCase):
    def test_required_rules_are_exactly_ten_with_expected_metadata(self) -> None:
        self.assertEqual(10, len(REQUIRED_RULES))
        self.assertEqual(set(EXPECTED_RULES), set(RULES))
        for rule_id, expected in EXPECTED_RULES.items():
            with self.subTest(rule_id=rule_id):
                rule = RULES[rule_id]
                actual = (
                    rule.category,
                    rule.detection_type,
                    rule.source_kind,
                    rule.sink_kind,
                    rule.status,
                    rule.severity,
                    DEFAULT_CONFIDENCE[rule_id],
                )
                self.assertEqual(expected, actual)

    def test_required_smoke_samples(self) -> None:
        covered: set[str] = set()
        for filename, expected in SAMPLE_EXPECTATIONS.items():
            with self.subTest(filename=filename):
                result = scan_file(SAMPLES / filename)
                self.assertTrue(result.ok)
                self.assertEqual(expected, rule_ids(result))
                for finding in result.findings:
                    self.assertEqual(
                        DEFAULT_CONFIDENCE[finding.rule_id], finding.confidence
                    )
                covered.update(rule_ids(result))
        self.assertEqual(set(EXPECTED_RULES), covered)

    def test_safe_samples_and_zero_count_summary(self) -> None:
        empty_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        empty_status = {"vulnerable": 0, "risky": 0}
        for filename in SAFE_SAMPLES:
            with self.subTest(filename=filename):
                result = scan_file(SAMPLES / filename)
                self.assertTrue(result.ok)
                self.assertEqual([], result.findings)
                self.assertEqual(0, result.summary.total_findings)
                self.assertEqual(empty_severity, result.summary.by_severity)
                self.assertEqual(empty_status, result.summary.by_status)

    def test_parse_error_is_a_scan_result(self) -> None:
        result = scan_code("def broken(:\n", "broken.py")
        self.assertIsInstance(result, ScanResult)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.parse_error)
        self.assertEqual([], result.findings)
        self.assertEqual(0, result.summary.total_findings)

    def test_scan_code_and_scan_file_return_scan_results(self) -> None:
        self.assertIsInstance(scan_code("value = 1"), ScanResult)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.py"
            path.write_text("value = 1\n", encoding="utf-8")
            result = scan_file(path)
        self.assertIsInstance(result, ScanResult)
        self.assertTrue(result.ok)

    def test_analyze_code_remains_findings_only_helper(self) -> None:
        code = "import pickle\nvalue = pickle.loads(payload)\n"
        findings = analyze_code(code, "compat.py")
        self.assertIsInstance(findings, list)
        self.assertTrue(all(isinstance(finding, Finding) for finding in findings))
        self.assertEqual(
            {"LLM03_UNSAFE_DESERIALIZATION"},
            {finding.rule_id for finding in findings},
        )

    def test_repeated_scan_is_deterministic(self) -> None:
        code = """
import os
import requests
token = os.getenv("ADMIN_TOKEN")
external = requests.get("https://example.com").text
llm.invoke(external)
llm.invoke(token)
"""
        first = scan_code(code, "deterministic.py").to_dict()
        second = scan_code(code, "deterministic.py").to_dict()
        self.assertEqual(first, second)

    def test_finding_id_is_stable_and_changes_with_source_or_sink(self) -> None:
        stable = build_finding_id("a.py", "RULE", 7, "llm.invoke(...)", "source-a")
        self.assertEqual(
            stable,
            build_finding_id("a.py", "RULE", 7, "llm.invoke(...)", "source-a"),
        )
        self.assertNotEqual(
            stable,
            build_finding_id("a.py", "RULE", 7, "llm.invoke(...)", "source-b"),
        )
        self.assertNotEqual(
            stable,
            build_finding_id("a.py", "RULE", 7, "chain.invoke(...)", "source-a"),
        )

    def test_llm07_duplicate_prefers_specific_system_prompt(self) -> None:
        code = """
import os
api_key = os.getenv("OPENAI_API_KEY")
system_prompt = f"Admin key: {api_key}"
messages = [{"role": "system", "content": system_prompt}]
"""
        findings = [
            finding
            for finding in scan_code(code, "duplicate.py").findings
            if finding.rule_id == "LLM07_SECRET_IN_SYSTEM_PROMPT"
        ]
        self.assertEqual(1, len(findings))
        self.assertEqual('{"role": "system", "content": ...}', findings[0].sink)

    def test_distinct_llm07_system_prompts_remain_separate(self) -> None:
        code = """
import os
api_key = os.getenv("OPENAI_API_KEY")
messages = [
    {"role": "system", "content": f"Admin key: {api_key}"},
    {"role": "system", "content": f"Audit key: {api_key}"},
]
"""
        findings = [
            finding
            for finding in scan_code(code, "distinct.py").findings
            if finding.rule_id == "LLM07_SECRET_IN_SYSTEM_PROMPT"
        ]
        self.assertEqual(2, len(findings))

    def test_unrelated_invoke_is_not_an_llm_sink(self) -> None:
        calls = {
            "workflow": "workflow.invoke(external)",
            "pipeline": "pipeline.invoke(external)",
            "callback": "callback.invoke(external)",
            "not_llm": "not_llm.invoke(external)",
            "supply_chain": "supply_chain.run(external)",
        }
        for name, expression in calls.items():
            with self.subTest(call=name):
                code = f"""
import requests
external = requests.get("https://example.com").text
{expression}
"""
                self.assertEqual([], scan_code(code, f"{name}.py").findings)

    def test_registered_llm_calls_remain_sinks(self) -> None:
        calls = {
            "llm.invoke": "llm.invoke(external)",
            "self.llm.invoke": "self.llm.invoke(external)",
            "service.chain.invoke": "service.chain.invoke(external)",
            "context.chain.run": "context.chain.run(external)",
            "self.agent.run": "self.agent.run(external)",
            "nested.responses": "self.client.responses.create(input=external)",
            "nested.chat": (
                "service.client.chat.completions.create(messages=external)"
            ),
        }
        for name, expression in calls.items():
            with self.subTest(call=name):
                code = f"""
import requests
external = requests.get("https://example.com").text
{expression}
"""
                self.assertIn(
                    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                    rule_ids(scan_code(code, f"{name}.py")),
                )

    def test_nested_known_llm_call_remains_an_output_source(self) -> None:
        code = """
result = service.chain.invoke("write an expression")
eval(result)
"""
        self.assertEqual(
            {"LLM05_LLM_OUTPUT_TO_CODE_EXECUTION"},
            rule_ids(scan_code(code, "nested_output.py")),
        )

    def test_fake_mask_and_unknown_transformations_preserve_taint(self) -> None:
        transformations = {
            "mask_badly(token)": "function-name mask",
            "redact_badly(token)": "function-name redact",
            "validate(token)": "generic validate",
            "token.strip()": "method receiver",
            "token.replace('A', 'B')": "ordinary replace",
        }
        for expression, label in transformations.items():
            with self.subTest(transformation=label):
                code = f"""
import os
def mask_badly(value):
    return value
def redact_badly(value):
    return value
def validate(value):
    return value
token = os.getenv("ADMIN_TOKEN")
transformed = {expression}
llm.invoke(transformed)
"""
                self.assertEqual(
                    {"LLM02_SECRET_TO_LLM_INPUT"},
                    rule_ids(scan_code(code, f"{label}.py")),
                )

    def test_explicit_masking_literal_is_non_triggering(self) -> None:
        for literal in ('"[REDACTED]"', '"<REDACTED>"', '"********"'):
            with self.subTest(literal=literal):
                code = f"""
import os
token = os.getenv("ADMIN_TOKEN")
masked = {literal}
llm.invoke(masked)
"""
                self.assertEqual([], scan_code(code, "literal_mask.py").findings)

    def test_re_sub_does_not_remove_secret_taint(self) -> None:
        expressions = {
            "full_dot": 're.sub(r".", "*", token)',
            "count_one": 're.sub(r".", "*", token, count=1)',
            "first_char": 're.sub(r"^.", "*", token)',
            "dynamic": "re.sub(pattern, replacement, token)",
        }
        for name, expression in expressions.items():
            with self.subTest(case=name):
                code = f"""
import os
import re
pattern = r"."
replacement = "*"
token = os.getenv("ADMIN_TOKEN")
masked = {expression}
llm.invoke(masked)
"""
                self.assertEqual(
                    {"LLM02_SECRET_TO_LLM_INPUT"},
                    rule_ids(scan_code(code, f"regex_mask_{name}.py")),
                )

    def test_fixed_shell_allowlist_mapping_is_non_triggering(self) -> None:
        code = """
import subprocess
choice = llm.invoke("choose status or list")
commands = {"status": ["git", "status"], "list": ["dir"]}
command = commands[choice]
subprocess.run(command)
"""
        self.assertNotIn(
            "LLM05_LLM_OUTPUT_TO_SHELL",
            rule_ids(scan_code(code, "shell_allowlist.py")),
        )

    def test_direct_llm_output_to_shell_triggers(self) -> None:
        code = """
import subprocess
command = llm.invoke("write a command")
subprocess.run(command, shell=True)
"""
        self.assertEqual(
            {"LLM05_LLM_OUTPUT_TO_SHELL"},
            rule_ids(scan_code(code, "shell_direct.py")),
        )

    def test_parameterized_sql_value_is_non_triggering(self) -> None:
        code = """
value = llm.invoke("choose a customer id")
cursor.execute("SELECT * FROM users WHERE id = %s", (value,))
"""
        self.assertNotIn(
            "LLM05_LLM_OUTPUT_TO_SQL",
            rule_ids(scan_code(code, "sql_parameter.py")),
        )

    def test_tainted_sql_query_structure_triggers(self) -> None:
        code = """
fragment = llm.invoke("write a WHERE clause")
query = f"SELECT * FROM users {fragment}"
cursor.execute(query)
"""
        self.assertEqual(
            {"LLM05_LLM_OUTPUT_TO_SQL"},
            rule_ids(scan_code(code, "sql_structure.py")),
        )

    def test_finding_metadata_matches_rule_metadata(self) -> None:
        for filename in SAMPLE_EXPECTATIONS:
            for finding in scan_file(SAMPLES / filename).findings:
                with self.subTest(filename=filename, rule_id=finding.rule_id):
                    rule = RULES[finding.rule_id]
                    self.assertEqual(rule.category, finding.category)
                    self.assertEqual(rule.status, finding.status)
                    self.assertEqual(rule.severity, finding.severity)
                    self.assertEqual(rule.source_kind, finding.source_kind)
                    self.assertEqual(rule.sink_kind, finding.sink_kind)

    def test_finding_model_field_contract(self) -> None:
        self.assertEqual(FINDING_FIELDS, {field.name for field in fields(Finding)})

    def test_confidence_uses_rule_default_and_weak_provenance_cap(self) -> None:
        cases = {
            "exact_external.py": (
                """
import requests
external = requests.get("https://example.com").text
llm.invoke(external)
""",
                "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                0.75,
            ),
            "heuristic_external.py": (
                "normalized = normalize(page_text)\nllm.invoke(normalized)\n",
                "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
                0.6,
            ),
            "exact_secret.py": (
                """
import os
token = os.getenv("ADMIN_TOKEN")
llm.invoke(token)
""",
                "LLM02_SECRET_TO_LLM_INPUT",
                0.75,
            ),
            "heuristic_secret.py": (
                "api_token = user_value\nllm.invoke(api_token)\n",
                "LLM02_SECRET_TO_LLM_INPUT",
                0.6,
            ),
            "exact_execution.py": (
                "result = llm.invoke('expression')\neval(result)\n",
                "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
                0.9,
            ),
        }
        for filename, (code, expected_rule, confidence) in cases.items():
            with self.subTest(filename=filename):
                findings = scan_code(code, filename).findings
                match = next(
                    finding
                    for finding in findings
                    if finding.rule_id == expected_rule
                )
                self.assertEqual(confidence, match.confidence)
                self.assertIn(match.confidence, {0.9, 0.75, 0.6})

    def test_scan_result_serialization_matches_schema(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        safe = scan_code("value = 1\n", "safe.py").to_dict()
        finding = scan_code(
            "import pickle\nvalue = pickle.loads(payload)\n", "finding.py"
        ).to_dict()
        parse_error = scan_code("def broken(:\n", "broken.py").to_dict()
        for label, result in {
            "safe": safe,
            "finding": finding,
            "parse_error": parse_error,
        }.items():
            with self.subTest(result=label):
                jsonschema.validate(result, schema)

        self.assertEqual([], safe["findings"])
        self.assertEqual(
            {"critical", "high", "medium", "low"},
            set(safe["summary"]["by_severity"]),
        )
        self.assertEqual(
            {"vulnerable", "risky"}, set(safe["summary"]["by_status"])
        )

    def test_schema_enums_and_required_fields_match_contract(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        finding = schema["$defs"]["finding"]
        self.assertEqual(FINDING_FIELDS, set(finding["required"]))
        schema_categories = set(finding["properties"]["category"]["enum"])
        rule_categories = {rule.category for rule in REQUIRED_RULES}
        self.assertEqual(EXPECTED_CATEGORIES, schema_categories)
        self.assertEqual(rule_categories, schema_categories)
        self.assertEqual(
            {"vulnerable", "risky"},
            set(finding["properties"]["status"]["enum"]),
        )
        self.assertEqual(
            {"critical", "high", "medium", "low"},
            set(finding["properties"]["severity"]["enum"]),
        )
        self.assertEqual(
            6, len(finding["properties"]["source_kind"]["enum"])
        )
        self.assertEqual(9, len(finding["properties"]["sink_kind"]["enum"]))
        confidence = finding["properties"]["confidence"]
        self.assertEqual(0, confidence["minimum"])
        self.assertEqual(1, confidence["maximum"])

    def test_schema_rejects_invalid_category(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        result = scan_code(
            "import pickle\npickle.loads(payload)\n", "invalid_category.py"
        ).to_dict()
        result["findings"][0]["category"] = "INVALID CATEGORY"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(result, schema)


if __name__ == "__main__":
    unittest.main()
