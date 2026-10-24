"""
Unit tests for Nemotron Sentinel Scanner and Remediation Engine.
"""

import pytest
from sentinel.scanner import CodeSecurityScanner
from sentinel.agent import NemotronRemediator
from sentinel.samples import SAMPLE_TARGETS

def test_sql_injection_detection():
    code = SAMPLE_TARGETS["ecommerce_auth"]["code"]
    scanner = CodeSecurityScanner(code, "auth.py")
    issues = scanner.scan()
    
    cwes = [i["cwe"] for i in issues]
    assert "CWE-89" in cwes, "SQL Injection CWE-89 must be detected"
    assert "CWE-798" in cwes, "Hardcoded Secret CWE-798 must be detected"
    assert len(issues) >= 2

def test_command_injection_detection():
    code = SAMPLE_TARGETS["network_diagnostics"]["code"]
    scanner = CodeSecurityScanner(code, "diag.py")
    issues = scanner.scan()
    
    cwes = [i["cwe"] for i in issues]
    assert "CWE-78" in cwes, "OS Command Injection CWE-78 must be detected"
    assert any(i["severity"] == "CRITICAL" for i in issues)

def test_deserialization_and_eval_detection():
    code = SAMPLE_TARGETS["session_loader"]["code"]
    scanner = CodeSecurityScanner(code, "session.py")
    issues = scanner.scan()
    
    cwes = [i["cwe"] for i in issues]
    assert "CWE-502" in cwes, "Insecure Deserialization CWE-502 must be detected"
    assert "CWE-94" in cwes, "Code Execution eval CWE-94 must be detected"

def test_remediation_and_diff_generation():
    code = SAMPLE_TARGETS["ecommerce_auth"]["code"]
    scanner = CodeSecurityScanner(code, "auth.py")
    issues = scanner.scan()
    
    remediator = NemotronRemediator()
    res = remediator.generate_patch(code, issues, "auth.py")
    
    assert res["vulnerabilities_fixed"] >= 2
    assert "diff --git" in res["unified_diff"]
    assert "cursor.execute" in res["patched_code"]
    assert res["regression_test"] != ""
