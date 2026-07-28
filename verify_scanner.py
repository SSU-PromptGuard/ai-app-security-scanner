from __future__ import annotations

from pathlib import Path

try:
    from scanner.analyzer import scan_code, scan_file
except Exception as exc:
    raise SystemExit(f"[IMPORT FAIL] cannot import scanner: {exc}")

try:
    from scanner.rules import RULES
except Exception as exc:
    raise SystemExit(f"[IMPORT FAIL] cannot import RULES: {exc}")


REQUIRED_RULE_IDS = {
    "LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT",
    "LLM02_SECRET_TO_LLM_INPUT",
    "LLM03_UNSAFE_DESERIALIZATION",
    "LLM03_TRUST_REMOTE_CODE_TRUE",
    "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION",
    "LLM05_LLM_OUTPUT_TO_SHELL",
    "LLM05_LLM_OUTPUT_TO_SQL",
    "LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION",
    "LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT",
    "LLM07_SECRET_IN_SYSTEM_PROMPT",
}

EXPECTED_SAMPLE_RULES = {
    "llm01_external_to_prompt.py": {"LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT"},
    "llm02_secret_to_prompt.py": {"LLM02_SECRET_TO_LLM_INPUT"},
    "llm03_unsafe_load.py": {"LLM03_UNSAFE_DESERIALIZATION"},
    "llm03_trust_remote_code.py": {"LLM03_TRUST_REMOTE_CODE_TRUE"},
    "llm05_eval.py": {"LLM05_LLM_OUTPUT_TO_CODE_EXECUTION"},
    "llm05_shell.py": {"LLM05_LLM_OUTPUT_TO_SHELL"},
    "llm05_sql.py": {"LLM05_LLM_OUTPUT_TO_SQL"},
    "llm06_agent_destructive_tool.py": {"LLM06_AGENT_TOOL_DESTRUCTIVE_OR_EXECUTION"},
    "llm06_agent_external_side_effect.py": {"LLM06_AGENT_TOOL_EXTERNAL_SIDE_EFFECT"},
    "llm07_secret_system_prompt.py": {"LLM07_SECRET_IN_SYSTEM_PROMPT"},
}

SAFE_SAMPLES = {
    "safe_basic_llm_call.py",
    "safe_env_client_only.py",
    "safe_readonly_tool.py",
}

EMPTY_SEVERITY = {"critical": 0, "high": 0, "medium": 0, "low": 0}
EMPTY_STATUS = {"vulnerable": 0, "risky": 0}


def rule_ids(result):
    return {finding.rule_id for finding in result.findings}


def main() -> None:
    ok = True
    sample_dir = Path("samples/dev")

    print("== Import and rule metadata ==")
    missing_rules = REQUIRED_RULE_IDS - set(RULES)
    extra_rules = set(RULES) - REQUIRED_RULE_IDS
    if missing_rules:
        print("[FAIL] missing required rules:", sorted(missing_rules))
        ok = False
    else:
        print("[PASS] all required rules exist")
    if extra_rules:
        print("[FAIL] optional/extra rules present:", sorted(extra_rules))
        ok = False

    print()
    print("== Parse samples ==")
    for path in sorted(sample_dir.glob("*.py")):
        result = scan_file(path)
        if result.ok:
            print(f"[PASS] {path.name}: parses")
        else:
            print(f"[FAIL] {path.name}: {result.parse_error}")
            ok = False

    print()
    print("== Smoke samples ==")
    seen_required: set[str] = set()
    for filename, expected in EXPECTED_SAMPLE_RULES.items():
        path = sample_dir / filename
        if not path.exists():
            print(f"[FAIL] {filename}: missing sample")
            ok = False
            continue

        result = scan_file(path)
        found = rule_ids(result)
        seen_required.update(found & REQUIRED_RULE_IDS)
        if found == expected:
            print(f"[PASS] {filename}: {sorted(found)}")
        else:
            print(f"[FAIL] {filename}: expected {sorted(expected)}, found {sorted(found)}")
            ok = False

    print()
    print("== Safe samples ==")
    for filename in sorted(SAFE_SAMPLES):
        result = scan_file(sample_dir / filename)
        found = rule_ids(result)
        if found:
            print(f"[FAIL] {filename}: expected no findings, found {sorted(found)}")
            ok = False
        elif result.summary.by_severity != EMPTY_SEVERITY:
            print(f"[FAIL] {filename}: bad empty severity summary {result.summary.by_severity}")
            ok = False
        elif result.summary.by_status != EMPTY_STATUS:
            print(f"[FAIL] {filename}: bad empty status summary {result.summary.by_status}")
            ok = False
        else:
            print(f"[PASS] {filename}: no findings")

    print()
    print("== Inline regression checks ==")
    duplicate_case = """
import os
api_key = os.getenv("OPENAI_API_KEY")
system_prompt = f"Admin key: {api_key}"
messages = [{"role": "system", "content": system_prompt}]
"""
    result = scan_code(duplicate_case, filename="duplicate_llm07.py")
    llm07_count = sum(
        1 for finding in result.findings
        if finding.rule_id == "LLM07_SECRET_IN_SYSTEM_PROMPT"
    )
    if llm07_count == 1:
        print("[PASS] LLM07 duplicate system_prompt flow collapses to one finding")
    else:
        print(f"[FAIL] expected one LLM07 finding, found {llm07_count}")
        ok = False

    distinct_system_prompts = """
import os
api_key = os.getenv("OPENAI_API_KEY")
messages = [
    {"role": "system", "content": f"Admin key: {api_key}"},
    {"role": "system", "content": f"Audit key: {api_key}"},
]
"""
    result = scan_code(distinct_system_prompts, filename="distinct_llm07.py")
    llm07_count = sum(
        1 for finding in result.findings
        if finding.rule_id == "LLM07_SECRET_IN_SYSTEM_PROMPT"
    )
    if llm07_count == 2:
        print("[PASS] distinct LLM07 system prompts remain separate")
    else:
        print(f"[FAIL] expected two distinct LLM07 findings, found {llm07_count}")
        ok = False

    fake_mask = """
import os
def mask_badly(value):
    return value
token = os.getenv("ADMIN_TOKEN")
masked = mask_badly(token)
llm.invoke(masked)
"""
    result = scan_code(fake_mask, filename="fake_mask.py")
    if rule_ids(result) == {"LLM02_SECRET_TO_LLM_INPUT"}:
        print("[PASS] unknown fake mask call preserves secret taint")
    else:
        print(f"[FAIL] fake mask expected LLM02, found {sorted(rule_ids(result))}")
        ok = False

    unrelated_invoke = """
import requests
external = requests.get("https://example.com").text
workflow.invoke(external)
"""
    result = scan_code(unrelated_invoke, filename="workflow.py")
    if not result.findings:
        print("[PASS] unrelated workflow.invoke is not an LLM sink")
    else:
        print(f"[FAIL] workflow.invoke produced {sorted(rule_ids(result))}")
        ok = False

    known_invoke = """
import requests
external = requests.get("https://example.com").text
llm.invoke(external)
"""
    result = scan_code(known_invoke, filename="known_llm.py")
    if rule_ids(result) == {"LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT"}:
        print("[PASS] known llm.invoke remains an LLM sink")
    else:
        print(f"[FAIL] llm.invoke expected LLM01, found {sorted(rule_ids(result))}")
        ok = False

    nested_known_invoke = """
import requests
external = requests.get("https://example.com").text
self.llm.invoke(external)
"""
    result = scan_code(nested_known_invoke, filename="nested_known_llm.py")
    if rule_ids(result) == {"LLM01_EXTERNAL_CONTENT_TO_LLM_PROMPT"}:
        print("[PASS] nested self.llm.invoke is an LLM sink")
    else:
        print(f"[FAIL] self.llm.invoke expected LLM01, found {sorted(rule_ids(result))}")
        ok = False

    partial_regex_mask = """
import os
import re
token = os.getenv("ADMIN_TOKEN")
masked = re.sub(r".", "*", token, count=1)
llm.invoke(masked)
"""
    result = scan_code(partial_regex_mask, filename="partial_regex_mask.py")
    if rule_ids(result) == {"LLM02_SECRET_TO_LLM_INPUT"}:
        print("[PASS] re.sub does not remove secret taint")
    else:
        print(f"[FAIL] re.sub expected LLM02, found {sorted(rule_ids(result))}")
        ok = False

    missing_smoke = REQUIRED_RULE_IDS - seen_required
    if missing_smoke:
        print("[FAIL] required rules without smoke coverage:", sorted(missing_smoke))
        ok = False
    else:
        print("[PASS] all required rules have smoke coverage")

    print()
    if ok:
        print("ALL CHECKS PASSED")
    else:
        print("SOME CHECKS FAILED")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
