from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from app.detectors import detect_log_type
from app.parsers import parse_log
from app.analyzers import analyze_events
from app.database import init_db, verify_user
from pathlib import Path
import tempfile
import shutil

app = FastAPI(title="Log Analysis Engine", version="1.0")

@app.on_event("startup")
def startup_event():
    init_db()

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/serv/login")
def serv_login(request: LoginRequest):
    """SERV authentication endpoint"""
    if verify_user(request.username, request.password):
        return {"ok": True}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/analyze/path")
def analyze_log_path(path: str):
    log_path = Path(path)

    if not log_path.exists() or not log_path.is_file():
        raise HTTPException(status_code=400, detail="Invalid file path")

    with log_path.open("r", errors="ignore") as f:
        lines = f.readlines()

    log_type = detect_log_type(lines)
    events = parse_log(lines, log_type)
    report = analyze_events(events, log_type)

    return report

@app.post("/analyze/upload")
def analyze_uploaded_log(file: UploadFile = File(...)):
    suffix = Path(file.filename).suffix or ".log"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        with open(tmp_path, "r", errors="ignore") as f:
            lines = f.readlines()
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    log_type = detect_log_type(lines)
    events = parse_log(lines, log_type)
    report = analyze_events(events, log_type)

    return report
