"""
Nemotron Sentinel FastAPI Server: Autonomous Vulnerability Remediation Dashboard.
Runs on port 8002.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Add project root
sys.path.append(str(Path(__file__).parent.parent))

from sentinel.scanner import CodeSecurityScanner
from sentinel.agent import NemotronRemediator
from sentinel.samples import SAMPLE_TARGETS

app = FastAPI(title="Nemotron Sentinel API", description="Autonomous Code Vulnerability Auto-Patcher powered by NVIDIA Nemotron")

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

class ScanRequest(BaseModel):
    code: str
    file_name: Optional[str] = "app.py"

class RemediateRequest(BaseModel):
    code: str
    vulnerabilities: List[Dict[str, Any]]
    file_name: Optional[str] = "app.py"

class GitBranchRequest(BaseModel):
    file_name: str = "app.py"
    patched_code: str
    commit_message: Optional[str] = None

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "engine": "Nemotron Sentinel v1.0",
        "model": "nvidia/Nemotron-3_5-Lightning",
        "cloud_provider": "Nebius Token Factory",
        "supported_cwe": ["CWE-89", "CWE-78", "CWE-502", "CWE-798", "CWE-94", "CWE-120"]
    }

@app.get("/api/samples")
def get_samples():
    return {"samples": SAMPLE_TARGETS}

@app.post("/api/scan")
def scan_code(req: ScanRequest):
    scanner = CodeSecurityScanner(req.code, req.file_name)
    issues = scanner.scan()
    metadata = scanner.get_analysis_metadata()
    return {
        "status": "success",
        "issues_count": len(issues),
        "issues": issues,
        "metadata": metadata
    }

@app.post("/api/remediate")
def remediate_code(req: RemediateRequest):
    remediator = NemotronRemediator()
    result = remediator.generate_patch(
        source_code=req.code,
        vulnerabilities=req.vulnerabilities,
        file_name=req.file_name
    )
    return {
        "status": "success",
        "remediation": result
    }

@app.post("/api/git-branch")
def create_branch(req: GitBranchRequest):
    remediator = NemotronRemediator()
    result = remediator.create_git_remediation_branch(
        file_name=req.file_name,
        patched_code=req.patched_code,
        commit_message=req.commit_message
    )
    return {
        "status": "success",
        "git_result": result
    }

@app.get("/", response_class=HTMLResponse)
def index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>Nemotron Sentinel Dashboard Ready</h1>")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
