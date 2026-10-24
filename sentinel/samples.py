"""
Sample Vulnerable Targets for Nemotron Sentinel Demos & Audits.
"""

SAMPLE_TARGETS = {
    "ecommerce_auth": {
        "name": "E-Commerce Authentication & Billing",
        "file_name": "auth_service.py",
        "description": "SQL Injection in user login query and hardcoded secret keys.",
        "code": """import sqlite3

# CRITICAL: Hardcoded API Secret
api_key = "MOCK_KEY_FOR_TESTING_ONLY"
secret_key = "prod_secret_token_super_classified"

def authenticate_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection via f-string
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user
"""
    },
    "network_diagnostics": {
        "name": "Cloud Network Diagnostics Service",
        "file_name": "diagnostic.py",
        "description": "Remote OS Command Injection via unvalidated shell arguments.",
        "code": """import os
import subprocess

def run_ping_test(host_ip):
    # VULNERABILITY: OS Command Injection via os.system
    cmd = "ping -c 1 " + host_ip
    exit_code = os.system(cmd)
    return exit_code

def run_traceroute(domain):
    # VULNERABILITY: Command Injection via shell=True
    proc = subprocess.Popen(f"traceroute {domain}", shell=True, stdout=subprocess.PIPE)
    stdout, _ = proc.communicate()
    return stdout.decode()
"""
    },
    "session_loader": {
        "name": "Distributed Session & Config Loader",
        "file_name": "session_mgr.py",
        "description": "Insecure Deserialization (pickle RCE) and Arbitrary Code Execution (eval).",
        "code": """import pickle

def restore_user_session(cookie_payload):
    # VULNERABILITY: Insecure Deserialization leading to Remote Code Execution
    session_data = pickle.loads(cookie_payload)
    return session_data

def evaluate_discount_formula(formula, user_points):
    # VULNERABILITY: Arbitrary Code Execution via eval()
    result = eval(formula)
    return result
"""
    },
    "file_upload_gateway": {
        "name": "Cloud Storage & Media Upload Gateway",
        "file_name": "upload_service.py",
        "description": "Path Traversal (CWE-22) and Insecure Temporary File Creation (CWE-377).",
        "code": """import os
import tempfile

UPLOAD_DIR = "/var/data/uploads"

def serve_user_document(user_filename):
    # VULNERABILITY: Path Traversal allows accessing ../../../etc/passwd
    target_path = f"{UPLOAD_DIR}/{user_filename}"
    with open(target_path, "rb") as f:
        return f.read()

def create_temporary_cache_buffer():
    # VULNERABILITY: Race condition via deprecated mktemp
    temp_path = tempfile.mktemp()
    with open(temp_path, "w") as f:
        f.write("CACHE_INIT")
    return temp_path
"""
    },
    "enterprise_orm_finance": {
        "name": "Enterprise Banking & Ledger ORM",
        "file_name": "ledger_service.py",
        "description": "SQLAlchemy dynamic raw query interpolation vs safe ORM query builder.",
        "code": """from sqlalchemy import create_engine
from sqlalchemy.orm import Session

def transfer_funds_unsafe(session: Session, account_id: str, amount: float):
    # VULNERABILITY: SQL Injection inside ORM session.execute with raw string formatting
    query = f"UPDATE accounts SET balance = balance - {amount} WHERE id = '{account_id}'"
    session.execute(query)
    session.commit()

def get_account_safe(session: Session, account_id: str):
    # SAFE: Parameterized ORM filter
    return session.query(Account).filter(Account.id == account_id).first()
"""
    }
}
