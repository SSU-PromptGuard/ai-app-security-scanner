import unittest

from scanner.analyzer import analyze_code, scan_code, scan_file


class AnalyzerSanitizerTests(unittest.TestCase):
    def test_vulnerable_eval_in_function_is_detected(self) -> None:
        source = '''
from openai import OpenAI

client = OpenAI(api_key="sk-test")


def calculate(user_expr: str) -> any:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_expr}],
    )
    answer = response.choices[0].message.content
    return eval(answer)
'''
        findings = analyze_code(source, "test.py")
        self.assertTrue(any(f.rule_id == "LLM05_LLM_OUTPUT_TO_CODE_EXECUTION" for f in findings))

    def test_parameterized_query_is_not_flagged_as_sql_injection(self) -> None:
        source = '''
import sqlite3

class FakeResponse:
    class Choices:
        class Message:
            content = "alice"

    choices = [Choices()]


def search_user() -> list:
    response = FakeResponse()
    llm_output = response.choices[0].message.content

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE name = ?"
    cursor.execute(sql, (llm_output,))
    return cursor.fetchall()
'''
        findings = analyze_code(source, "test.py")
        self.assertEqual([], findings)

    def test_scan_code_returns_result_with_agreed_rule_id(self) -> None:
        source = '''
import subprocess


def run(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
'''
        result = scan_code(source, "demo.py")
        self.assertEqual("LLM05_LLM_OUTPUT_TO_SHELL", result.findings[0].rule_id)

    def test_scan_file_reads_from_disk(self) -> None:
        result = scan_file("samples/dev/llm05_v1.py")
        self.assertTrue(result.findings)


if __name__ == "__main__":
    unittest.main()
