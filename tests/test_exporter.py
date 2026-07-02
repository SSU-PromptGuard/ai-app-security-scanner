import os
import tempfile
import unittest

from scanner.exporter import export_findings
from scanner.models import Finding


class ExporterTests(unittest.TestCase):
    def test_export_csv_writes_expected_rows(self) -> None:
        findings = [
            Finding(
                rule_id="llm05_code_exec",
                owasp_category="LLM05",
                severity="critical",
                status="vulnerable",
                title="demo",
                source="response.content",
                sink="eval()",
                flow="response.content -> eval()",
                reason="demo",
                fix="avoid",
                line=5,
                confidence="high",
            )
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "results.csv")
            export_findings(findings, output, fmt="csv")
            with open(output, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("rule_id", text)
            self.assertIn("llm05_code_exec", text)

    def test_export_markdown_writes_table(self) -> None:
        findings = [
            Finding(
                rule_id="llm01_external_to_prompt",
                owasp_category="LLM01",
                severity="medium",
                status="risky",
                title="demo",
                source="requests.get(url).text",
                sink="messages.content",
                flow="requests.get(url).text -> messages.content",
                reason="demo",
                fix="sanitize",
                line=8,
                confidence="medium",
            )
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "results.md")
            export_findings(findings, output, fmt="md")
            with open(output, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("# Scan Results", text)
            self.assertIn("llm01_external_to_prompt", text)


if __name__ == "__main__":
    unittest.main()
