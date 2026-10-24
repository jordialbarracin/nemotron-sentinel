import unittest
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

from sentinel.scanner import CodeSecurityScanner
from sentinel.agent import NemotronRemediator
from sentinel.samples import SAMPLE_TARGETS

class TestSentinel(unittest.TestCase):
    def test_sql_injection_detection(self):
        code = SAMPLE_TARGETS["ecommerce_auth"]["code"]
        scanner = CodeSecurityScanner(code, "auth.py")
        issues = scanner.scan()
        cwes = [i["cwe"] for i in issues]
        self.assertIn("CWE-89", cwes)
        self.assertIn("CWE-798", cwes)

    def test_command_injection_detection(self):
        code = SAMPLE_TARGETS["network_diagnostics"]["code"]
        scanner = CodeSecurityScanner(code, "diag.py")
        issues = scanner.scan()
        cwes = [i["cwe"] for i in issues]
        self.assertIn("CWE-78", cwes)

    def test_deserialization_and_eval(self):
        code = SAMPLE_TARGETS["session_loader"]["code"]
        scanner = CodeSecurityScanner(code, "session.py")
        issues = scanner.scan()
        cwes = [i["cwe"] for i in issues]
        self.assertIn("CWE-502", cwes)
        self.assertIn("CWE-94", cwes)

    def test_path_traversal_and_tempfile(self):
        code = SAMPLE_TARGETS["file_upload_gateway"]["code"]
        scanner = CodeSecurityScanner(code, "upload.py")
        issues = scanner.scan()
        cwes = [i["cwe"] for i in issues]
        self.assertIn("CWE-22", cwes)
        self.assertIn("CWE-377", cwes)

    def test_remediation_and_diff(self):
        code = SAMPLE_TARGETS["ecommerce_auth"]["code"]
        scanner = CodeSecurityScanner(code, "auth.py")
        issues = scanner.scan()
        remediator = NemotronRemediator()
        res = remediator.generate_patch(code, issues, "auth.py")
        self.assertGreaterEqual(res["vulnerabilities_fixed"], 2)
        self.assertIn("diff --git", res["unified_diff"])
        self.assertIn("cursor.execute", res["patched_code"])

if __name__ == "__main__":
    unittest.main()
