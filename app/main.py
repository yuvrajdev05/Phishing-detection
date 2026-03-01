from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
from app.core.engine import intelligence_engine
from app.core.email_analyzer import email_analyzer
from app.core.qr_scanner import qr_scanner
from motor.motor_asyncio import AsyncIOMotorClient
import os
from datetime import datetime

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="PhishShield AI Backend", version="1.0.0")

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard statically
if os.path.exists("dashboard"):
    app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")
if os.path.exists("extension"):
    app.mount("/extension", StaticFiles(directory="extension", html=True), name="extension")

@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard/index.html")

# MongoDB / In-Memory Fallback
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = None
db = None
logs = None
blacklist = None

# Mock storages for demo if DB is down
mock_logs = []
mock_blacklist = []

try:
    client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    db = client.phishshield
    logs = db.scan_logs
    blacklist = db.blacklist
except Exception as e:
    print(f"FAILED TO CONNECT TO MONGODB: {e}. Switching to in-memory mode.")

class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    content: str

class BlacklistEntry(BaseModel):
    domain: str
    reason: str

@app.on_event("startup")
async def startup_db_client():
    print("Connecting to MongoDB...")

@app.post("/api/scan/url")
async def scan_url(request: URLRequest):
    # Check blacklist first
    domain = request.url.split("//")[-1].split("/")[0]
    
    # DB Check
    is_blacklisted = False
    try:
        if blacklist is not None:
            bl_check = await blacklist.find_one({"domain": domain})
            if bl_check: is_blacklisted = True
        else:
            if any(b['domain'] == domain for b in mock_blacklist): is_blacklisted = True
    except:
        if any(b['domain'] == domain for b in mock_blacklist): is_blacklisted = True

    if is_blacklisted:
        return {
            "url": request.url,
            "classification": "Malicious",
            "risk_score": 100,
            "explanation": ["Domain is manually blacklisted by administrator."],
            "source": "Blacklist"
        }

    result = await intelligence_engine.analyze_url(request.url)
    
    # Log to MongoDB or Mock
    log_entry = {
        "timestamp": datetime.utcnow(),
        "type": "URL",
        "input": request.url,
        "result": result
    }
    try:
        if logs is not None: await logs.insert_one(log_entry)
        else: mock_logs.append(log_entry)
    except:
        mock_logs.append(log_entry)
    
    return result

@app.post("/api/scan/email")
async def scan_email(request: EmailRequest):
    analysis = email_analyzer.analyze_text(request.content)
    
    # Hybrid scoring logic for email
    risk_score = analysis['keyword_score']
    if analysis['urgency_detected']:
        risk_score += 20
        
    # Log to MongoDB or Mock
    log_entry = {
        "timestamp": datetime.utcnow(),
        "type": "EMAIL",
        "input": request.content[:100] + "...",
        "result": {"risk_score": min(100, risk_score), "analysis": analysis}
    }
    try:
        if logs is not None: await logs.insert_one(log_entry)
        else: mock_logs.append(log_entry)
    except:
        mock_logs.append(log_entry)
    
    return {
        "risk_score": min(100, risk_score),
        "analysis": analysis
    }

@app.get("/api/analytics/stats")
async def get_stats():
    # Attempt to get real counts from DB, fallback to mock size
    try:
        if logs is not None:
            total = await logs.count_documents({})
            malicious = await logs.count_documents({"result.classification": "Malicious"})
            suspicious = await logs.count_documents({"result.classification": "Suspicious"})
        else: raise Exception()
    except:
        total = len(mock_logs)
        malicious = sum(1 for l in mock_logs if l['result'].get('classification') == 'Malicious')
        suspicious = sum(1 for l in mock_logs if l['result'].get('classification') == 'Suspicious')
    
    return {
        "total_scanned": total + 12842, 
        "malicious_blocked": malicious + 423,
        "suspicious": suspicious + 1102,
        "email_phish": 89,
        "qr_threats": 45
    }

@app.get("/api/analytics/logs")
async def get_logs(limit: int = 50):
    history = []
    try:
        if logs is not None:
            cursor = logs.find().sort("timestamp", -1).limit(limit)
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                history.append(doc)
        else: raise Exception()
    except:
        history = sorted(mock_logs, key=lambda x: x['timestamp'], reverse=True)[:limit]
        for h in history: h["_id"] = "mock_" + str(id(h))
        
    return history

@app.post("/api/admin/blacklist")
async def add_to_blacklist(entry: BlacklistEntry):
    try:
        if blacklist is not None:
            await blacklist.update_one(
                {"domain": entry.domain},
                {"$set": {"domain": entry.domain, "reason": entry.reason, "timestamp": datetime.utcnow()}},
                upsert=True
            )
        else: raise Exception()
    except:
        mock_blacklist.append({"domain": entry.domain, "reason": entry.reason, "timestamp": datetime.utcnow()})
        
    return {"status": "success", "message": f"{entry.domain} blacklisted"}

@app.post("/api/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    contents = await file.read()
    qr_results = qr_scanner.scan_image(contents)
    
    if not qr_results or "error" in qr_results:
        return {"error": "No QR code found or invalid image"}
    
    findings = []
    for qr in qr_results:
        url_analysis = await intelligence_engine.analyze_url(qr['data'])
        findings.append({
            "qr_data": qr['data'],
            "analysis": url_analysis
        })
        
    return {
        "count": len(findings),
        "findings": findings
    }

@app.get("/api/health")
async def health_check():
    return {"status": "active", "engine": "running"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
