"""Tests for codeql_report.py. Run: python3 -m unittest discover -s .github/scripts"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "codeql_report.py")

RULE_HIGH = {
    "id": "rust/hard-coded-cryptographic-value",
    "helpUri": "https://codeql.github.com/codeql-query-help/rust/rust-hard-coded-cryptographic-value/",
    "fullDescription": {"text": "Using a hard-coded cryptographic value makes it easy to recover protected data."},
    "help": {"text": "## Recommendation\nGenerate the key randomly.\n## References\n"},
    "properties": {"security-severity": "9.8", "tags": ["security", "external/cwe/cwe-798"]},
}
RULE_QUALITY = {"id": "js/unused-local-variable", "properties": {"tags": ["maintainability"]}}


def result(rule_id, uri, line=1, level="error"):
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"{rule_id} here"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
    }


def run_report(rules, results, rules_in="extensions"):
    tool = {"driver": {"name": "CodeQL"}}
    if rules_in == "extensions":
        # How CodeQL really writes them: under the query pack, not the driver.
        tool["extensions"] = [{"name": "codeql/rust-queries", "rules": rules}]
    else:
        tool["driver"]["rules"] = rules
    sarif = {"runs": [{"tool": tool, "results": results}]}
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.sarif")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f)
        return subprocess.run(
            [sys.executable, SCRIPT, "--repo-root", d, path], capture_output=True, text=True
        )


class Report(unittest.TestCase):
    def test_high_security_finding_in_shipped_code_fails_with_all_five_parts(self):
        for where in ("extensions", "driver"):
            r = run_report([RULE_HIGH], [result(RULE_HIGH["id"], "src/crypto.rs")], where)
            self.assertEqual(r.returncode, 1, (where, r.stdout))
            out = r.stdout
            self.assertIn("Source: CodeQL `rust/hard-coded-cryptographic-value`", out)
            self.assertIn("https://cwe.mitre.org/data/definitions/798.html", out)
            self.assertIn("Source quote: > Using a hard-coded cryptographic value", out)
            self.assertIn("SOC 2: C1.1 Confidential information", out)
            self.assertIn("Fix: Generate the key randomly.", out)
            self.assertIn("Failing the check:\n- rust/hard-coded-cryptographic-value at src/crypto.rs:1", out)
            self.assertLess(out.index("GATE **"), out.index("SOC 2:"))

    def test_the_same_finding_in_test_code_is_listed_but_does_not_fail(self):
        r = run_report([RULE_HIGH], [result(RULE_HIGH["id"], "src/crypto/tests.rs")])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("Findings in test code (1), listed but not failing the check", r.stdout)
        self.assertIn("- critical: rust/hard-coded-cryptographic-value at src/crypto/tests.rs:1 (test code)", r.stdout)
        self.assertNotIn("Source quote", r.stdout, "test findings are one line, not a full block")

    def test_quality_finding_is_not_a_soc2_finding_and_does_not_fail(self):
        r = run_report([RULE_QUALITY], [result(RULE_QUALITY["id"], "lab/src/App.tsx", level="note")])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("SOC 2: none (correctness)", r.stdout)

    def test_workflow_rules_map_to_change_management(self):
        rule = {
            "id": "actions/code-injection/critical",
            "fullDescription": {"text": "User input may inject code."},
            "properties": {"security-severity": "9.0", "tags": ["security", "external/cwe/cwe-094"]},
        }
        r = run_report([rule], [result(rule["id"], ".github/workflows/x.yml")])
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("SOC 2: CC8.1 Change management", r.stdout)

    def test_no_results_passes(self):
        self.assertEqual(run_report([RULE_HIGH], []).returncode, 0)


if __name__ == "__main__":
    unittest.main()
