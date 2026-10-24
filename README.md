# Nemotron Sentinel: Autonomous Code Vulnerability Auto-Patcher & CI/CD Security Agent

**Nebius x NVIDIA Global AI Hackathon**  
*Track:* **Coding and Agentic Engineering Track** | **Best Apps and Agents Track**

Nemotron Sentinel is an autonomous cybersecurity remediation agent powered by **NVIDIA Nemotron-3.5-Lightning** on **Nebius Token Factory**. It performs static AST dataflow taint tracking (Source $\rightarrow$ Propagation $\rightarrow$ Sink), models complex enterprise ORM sinks (SQLAlchemy, Django), synthesizes production-ready unified diff patches, and validates security closure through an isolated multi-scenario Pytest sandbox.

---

## Core Capabilities

1. **AST Dataflow Taint Tracking:** Tracks untrusted external inputs across function arguments, f-string interpolations, and container dictionaries to identify exploitable code paths.
2. **Enterprise ORM Sinks:** Identifies dynamic SQL injections in `session.execute()`, `connection.execute()`, SQLAlchemy `text()`, and Django `raw()`/`extra()`.
3. **Zero False-Positives on Safe ORMs:** Differentiates parametric queries (`session.query(User).filter(...)`, `Model.objects.filter(...)`), recognizing them as safe by design.
4. **Autonomous Nemotron Patching:** Synthesizes drop-in unified diffs replacing dynamic string interpolations with parameterized bindings while preserving 100% of business logic.
5. **Multi-Scenario Sandbox Pytest Verification:** Executes 3-stage validation testing AST syntax parsing, hostile exploit payload neutralization, and parameter typing preservation.
6. **Git Branch & PR Preparation:** Automatically provisions remediation branches (`sentinel/fix-...`), stages diffs, and creates commit history.

---

## Multi-Scenario OWASP / CWE Verification Benchmark Results

| Scenario & Target File | Vulnerability Detected | AST Taint Path | Auto-Patch Applied | Sandbox Status |
| :--- | :--- | :--- | :--- | :--- |
| **Enterprise Ledger (SQLAlchemy)** | **CWE-89 (SQL Injection)** | `user_id` $\rightarrow$ f-string $\rightarrow$ `session.execute` | Parameterized `text(:id)` bind | **3/3 passed (0.016s)** |
| **Auth Service (DB-API)** | **CWE-89 (SQL Injection)** | `username` $\rightarrow$ f-string $\rightarrow$ `cursor.execute` | Parameterized `%s` tuple | **3/3 passed (0.018s)** |
| **Network Diagnostics** | **CWE-78 (Command Injection)** | `host_ip` $\rightarrow$ concat $\rightarrow$ `os.system` | `subprocess.run(shell=False)` | **3/3 passed (0.012s)** |
| **Session Loader** | **CWE-502 (Deserialization)** | `cookie` $\rightarrow$ `pickle.loads` | Safe `json.loads` / HMAC | **3/3 passed (0.015s)** |
| **Storage Gateway** | **CWE-22 (Path Traversal)** | `filename` $\rightarrow$ `open()` | `os.path.basename` sanitizer | **3/3 passed (0.014s)** |

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment (`.env`)
```bash
NEBIUS_API_KEY=your_token_factory_key
```

### 3. Launch Security Console
```bash
python -m uvicorn sentinel.server:app --host 127.0.0.1 --port 8002
```
Open **[http://127.0.0.1:8002](http://127.0.0.1:8002)** in your browser.
