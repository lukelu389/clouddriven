from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request, Header
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func
import secrets
from datetime import datetime
from typing import Optional, List
import os, shutil, json
from .database import SessionLocal, engine, Base
import backend.models as models
from backend.auth import create_access_token, decode_token, get_password_hash, verify_password, get_current_user, get_db
from pydantic import BaseModel
from backend.auth import router as auth_router





device_security = HTTPBearer(auto_error=False)

def get_device_by_token(
    creds: HTTPAuthorizationCredentials = Depends(device_security),
    db: Session = Depends(get_db),
):
    if not creds or not creds.credentials:
        raise HTTPException(401, "Missing device token")
    tok = creds.credentials
    d = db.query(models.Device).filter(models.Device.device_token == tok).first()
    if not d:
        raise HTTPException(401, "Invalid device token")
    return d


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Clouddriven", version="0.1.0")
app.include_router(auth_router)
# Serve static frontend
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.post("/api/devices/{device_id}/issue-token")
def issue_device_token(device_id: int,
                       current: models.User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    d = db.query(models.Device).filter(models.Device.id == device_id,
                                       models.Device.user_id == current.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    d.device_token = secrets.token_hex(32)
    d.last_sync = datetime.utcnow()
    db.commit()
    return {"device_token": d.device_token}


@app.get("/", response_class=HTMLResponse)
def index():
    index_path = os.path.join(static_dir, "index.html")
    return FileResponse(index_path)

# CORS (allow same-origin or dev ports)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> models.User:
    token = credentials.credentials
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Invalid token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------------- Auth ----------------------
@app.post("/api/auth/register")
def register(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(email=email, password_hash=get_password_hash(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": user.id, "email": user.email})
    return {"token": token, "user": {"id": user.id, "email": user.email}}

@app.post("/api/auth/login")
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.id, "email": user.email})
    return {"token": token, "user": {"id": user.id, "email": user.email}}

@app.get("/api/auth/whoami")
def whoami(current: models.User = Depends(get_current_user)):
    return {"id": current.id, "email": current.email}
# ---------------------- Devices ----------------------
from sqlalchemy import func

@app.get("/api/devices")
def list_devices(current: models.User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    devices = (
        db.query(models.Device)
        .filter(models.Device.user_id == current.id)
        .all()
    )

    result = []
    for d in devices:
        used_bytes = (
            db.query(func.coalesce(func.sum(models.File.size_bytes), 0))
              .select_from(models.FileAssignment)
              .join(models.File, models.File.id == models.FileAssignment.file_id)
              .filter(models.FileAssignment.device_id == d.id)
              .scalar()
        ) or 0

        capacity_bytes = (d.capacity_gb or 0) * (1024 ** 3)
        used_percent = float(used_bytes) / capacity_bytes * 100 if capacity_bytes else 0.0

        result.append({
            "id": d.id,
            "name": d.name,
            "capacity_gb": d.capacity_gb,
            "is_online": d.is_online,
            "last_sync": d.last_sync.isoformat() if d.last_sync else None,
            "created_at": d.created_at.isoformat() if getattr(d, "created_at", None) else None,
            "free_bytes": int(getattr(d, "free_bytes", 0)),  # safe default
            "used_bytes": int(used_bytes),
            "used_percent": used_percent,
        })
    return result

@app.post("/api/devices")
def create_device(
    name: str = Form(...),
    capacity_gb: float = Form(...),
    current: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    d = models.Device(user_id=current.id, name=name, capacity_gb=capacity_gb, is_online=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"id": d.id, "name": d.name, "capacity_gb": d.capacity_gb}

@app.patch("/api/devices/{device_id}")
def update_device(
    device_id: int,
    name: Optional[str] = Form(None),
    capacity_gb: Optional[float] = Form(None),
    is_online: Optional[bool] = Form(None),
    current: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    d = db.query(models.Device).filter(models.Device.id == device_id, models.Device.user_id == current.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    if name is not None:
        d.name = name
    if capacity_gb is not None:
        d.capacity_gb = capacity_gb
    if is_online is not None:
        d.is_online = is_online
    db.commit()
    return {"ok": True}

@app.delete("/api/devices/{device_id}")
def delete_device(device_id: int, current: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    d = db.query(models.Device).filter(models.Device.id == device_id, models.Device.user_id == current.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(d)
    db.commit()
    return {"ok": True}

# ---------------------- Files ----------------------
UPLOAD_ROOT = os.path.join(os.path.dirname(__file__), "storage")

@app.post("/api/files")
async def upload_file(
    thefile: UploadFile = File(...),
    device_ids: Optional[str] = Form(None),
    current: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    user_dir = os.path.join(UPLOAD_ROOT, f"user_{current.id}")
    os.makedirs(user_dir, exist_ok=True)
    # Save file
    import uuid, shutil
    file_id_str = str(uuid.uuid4())
    dest_path = os.path.join(user_dir, file_id_str)
    size = 0
    with open(dest_path, "wb") as out:
        while True:
            chunk = await thefile.read(1024*1024)
            if not chunk:
                break
            size += len(chunk)
            out.write(chunk)
    f = models.File(user_id=current.id, name=thefile.filename, mime_type=thefile.content_type or "application/octet-stream", size_bytes=size, path=dest_path)
    db.add(f)
    db.commit()
    db.refresh(f)

    if device_ids:
        try:
            ids = json.loads(device_ids)
            if isinstance(ids, list):
                for did in ids:
                    d = db.query(models.Device).filter(models.Device.id == int(did), models.Device.user_id == current.id).first()
                    if d:
                        db.add(models.FileAssignment(file_id=f.id, device_id=d.id, status="pending"))
                db.commit()
        except Exception:
            pass

    return {"id": f.id, "name": f.name, "size_bytes": f.size_bytes}

@app.get("/api/files")
def list_files(current: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    files = db.query(models.File).filter(models.File.user_id == current.id).order_by(models.File.created_at.desc()).all()
    results = []
    for f in files:
        assignments = [
            {"device_id": a.device_id, "device_name": a.device.name, "status": a.status}
            for a in f.assignments
        ]
        results.append({
            "id": f.id,
            "name": f.name,
            "mime_type": f.mime_type,
            "size_bytes": f.size_bytes,
            "created_at": f.created_at.isoformat(),
            "assignments": assignments
        })
    return results

@app.delete("/api/files/{file_id}")
def delete_file(file_id: int, current: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    f = db.query(models.File).filter(models.File.id == file_id, models.File.user_id == current.id).first()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    # Delete from disk
    try:
        if f.path and os.path.exists(f.path):
            os.remove(f.path)
    except Exception:
        pass
    db.delete(f)
    db.commit()
    return {"ok": True}

BYTES_PER_GB = 1024 ** 3

@app.post("/api/files/{file_id}/assign")
def assign_file(
    file_id: int,
    device_id: int = Form(...),
    current: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # load entities (owned by user)
    f = db.query(models.File).filter(models.File.id == file_id,
                                     models.File.user_id == current.id).first()
    d = db.query(models.Device).filter(models.Device.id == device_id,
                                       models.Device.user_id == current.id).first()
    if not f or not d:
        raise HTTPException(status_code=404, detail="File or device not found")

    exists = db.query(models.DeviceFile)\
        .filter(models.DeviceFile.device_id == d.id,
                models.DeviceFile.file_id == f.id).first()
    if exists:
        return {"ok": True}  # idempotent


    assigned_bytes = db.query(func.coalesce(func.sum(models.File.size_bytes), 0))\
        .select_from(models.DeviceFile)\
        .join(models.File, models.File.id == models.DeviceFile.file_id)\
        .filter(models.DeviceFile.device_id == d.id).scalar()

    capacity_bytes = int((d.capacity_gb or 0) * BYTES_PER_GB)
    projected = assigned_bytes + int(f.size_bytes or 0)

    if capacity_bytes <= 0:
        raise HTTPException(400, "This device has zero capacity configured.")

    if capacity_bytes and projected > capacity_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"Assignment exceeds device capacity ({projected} > {capacity_bytes} bytes)."
        )

    link = models.DeviceFile(device_id=d.id, file_id=f.id)
    db.add(link)
    db.commit()
    return {"ok": True}

@app.delete("/api/files/{file_id}/assign/{device_id}")
def unassign_file(file_id: int, device_id: int, current: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.query(models.FileAssignment).join(models.File).join(models.Device).filter(
        models.FileAssignment.file_id == file_id,
        models.FileAssignment.device_id == device_id,
        models.File.user_id == current.id,
        models.Device.user_id == current.id,
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="Assignment not found")
    db.delete(a)
    db.commit()
    return {"ok": True}

# Device “pairing” (create token for the agent)
@app.post("/api/devices/{device_id}/issue-token")
def issue_device_token(device_id: int, current=Depends(get_current_user), db: Session=Depends(get_db)):
    d = db.query(models.Device).filter_by(id=device_id, user_id=current.id).first()
    if not d: raise HTTPException(404, "Device not found")
    import secrets
    d.device_token = secrets.token_hex(32)
    db.commit()
    return {"device_token": d.device_token}

# Device agent auth dependency
def get_device(db: Session = Depends(get_db), x_device_token: str | None = Header(None)):
    if not x_device_token: raise HTTPException(401, "Missing X-Device-Token")
    d = db.query(models.Device).filter_by(device_token=x_device_token).first()
    if not d: raise HTTPException(401, "Invalid device token")
    return d


class HeartbeatIn(BaseModel):
    total_bytes: int | None = None
    free_bytes:  int | None = None
    used_bytes:  int | None = None

@app.post("/api/agent/heartbeat")
def agent_heartbeat(
    hb: HeartbeatIn,
    device: models.Device = Depends(get_device_by_token),
    db: Session = Depends(get_db),
):
    device.last_seen = datetime.utcnow()
    if hb.total_bytes is not None: device.total_bytes = hb.total_bytes
    if hb.free_bytes  is not None: device.free_bytes  = hb.free_bytes
    if hb.used_bytes  is not None: device.used_bytes  = hb.used_bytes
    db.add(models.DeviceHeartbeat(device_id=device.id,
                                  total_bytes=hb.total_bytes,
                                  free_bytes=hb.free_bytes,
                                  used_bytes=hb.used_bytes))
    db.commit()
    return {"ok": True, "device_id": device.id, "last_seen": device.last_seen.isoformat()}

@app.post("/api/devices/{device_id}/heartbeat")
def device_heartbeat(
    device_id: int,
    hb: HeartbeatIn,
    current: models.User = Depends(get_current_user), 
    db: Session = Depends(get_db),
):
    d = db.query(models.Device).filter(models.Device.id == device_id,
                                       models.Device.user_id == current.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    # upsert device live info
    d.last_seen = datetime.utcnow()
    if hb.total_bytes is not None: d.total_bytes = hb.total_bytes
    if hb.free_bytes  is not None: d.free_bytes  = hb.free_bytes
    if hb.used_bytes  is not None: d.used_bytes  = hb.used_bytes

    db.add(models.DeviceHeartbeat(
        device_id=d.id,
        total_bytes=hb.total_bytes,
        free_bytes=hb.free_bytes,
        used_bytes=hb.used_bytes,
    ))
    db.commit()
    return {"ok": True, "last_seen": d.last_seen.isoformat()}


# List assignments to sync for this device
@app.get("/api/agent/assignments")
def agent_assignments(device=Depends(get_device), db: Session=Depends(get_db)):
    q = (db.query(models.File, models.FileAssignment)
          .join(models.FileAssignment, models.File.id == models.FileAssignment.file_id)
          .filter(models.FileAssignment.device_id == device.id))
    items = []
    for f, a in q:
        items.append({
            "assignment_id": a.id,
            "file_id": f.id,
            "name": f.name,
            "size_bytes": f.size_bytes,
            "download_url": f"/api/agent/files/{f.id}/download"  # see below
        })
    return items

# Serve file content to the agent (direct download)
@app.get("/api/agent/files/{file_id}/download")
def agent_download(file_id: int, device=Depends(get_device), db: Session=Depends(get_db)):
    f = db.query(models.File).filter_by(id=file_id, user_id=device.user_id).first()
    if not f or not f.path or not os.path.exists(f.path): raise HTTPException(404, "Not found")
    return FileResponse(f.path, filename=f.name)


# The agent marks an assignment as synced/failed
@app.post("/api/agent/assignments/{assignment_id}/status")
def agent_update_status(assignment_id: int, status: str = Form(...), note: str = Form(""),
                        device=Depends(get_device), db: Session=Depends(get_db)):
    a = (db.query(models.FileAssignment)
          .join(models.File, models.File.id == models.FileAssignment.file_id)
          .filter(models.FileAssignment.id == assignment_id, models.File.user_id == device.user_id,
                  models.FileAssignment.device_id == device.id).first())
    if not a: raise HTTPException(404, "Assignment not found")
    a.status = status
    db.commit()
    return {"ok": True}


# ---------------------- Dashboard ----------------------
@app.get("/api/dashboard")
def dashboard(current: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(models.Device).filter(models.Device.user_id == current.id).all()
    files = db.query(models.File).filter(models.File.user_id == current.id).all()

    total_storage_gb = sum(d.capacity_gb for d in devices) if devices else 0.0

    used_bytes = 0
    per_device = []
    for d in devices:
        d_used = (
            db.query(func.coalesce(func.sum(models.File.size_bytes), 0))
            .join(models.FileAssignment, models.File.id == models.FileAssignment.file_id)
            .filter(models.FileAssignment.device_id == d.id)
            .scalar()
            or 0
        )
        used_bytes += d_used
        per_device.append({
            "device_id": d.id,
            "device_name": d.name,
            "used_bytes": d_used,
            "capacity_gb": d.capacity_gb,
            "free_bytes": int(getattr(d, "free_bytes", 0)),
           "last_seen": d.last_seen.isoformat() if getattr(d, "last_seen", None) else None,
        })

    return {
        "total_devices": len(devices),
        "total_storage_gb": total_storage_gb,
        "used_storage_gb": round(used_bytes / (1024**3), 2),
        "total_files": len(files),
        "per_device": per_device,
    }


@app.get("/api/dashboard")
def dashboard(current: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(models.Device).filter(models.Device.user_id == current.id).all()
    files = db.query(models.File).filter(models.File.user_id == current.id).all()

    total_storage_gb = sum(float(d.capacity_gb or 0.0) for d in devices)

    assigned_map = dict(
        db.query(
            models.Device.id,
            func.coalesce(func.sum(models.File.size_bytes), 0)
        )
        .outerjoin(models.FileAssignment, models.Device.id == models.FileAssignment.device_id)
        .outerjoin(models.File, models.File.id == models.FileAssignment.file_id)
        .filter(models.Device.user_id == current.id)
        .group_by(models.Device.id)
        .all()
    )

    used_bytes_total = 0
    per_device = []
    for d in devices:
        d_used = int(assigned_map.get(d.id, 0))
        used_bytes_total += d_used
        per_device.append({
            "device_id": d.id,
            "device_name": d.name,
            "used_bytes": d_used,
            "capacity_gb": float(d.capacity_gb or 0.0),
            "free_bytes": int(getattr(d, "free_bytes", 0)),
            "last_seen": d.last_seen.isoformat() if getattr(d, "last_seen", None) else None,
        })

    return {
        "total_devices": len(devices),
        "total_storage_gb": total_storage_gb,
        "used_storage_gb": round(used_bytes_total / (1024**3), 2),
        "total_files": len(files),
        "per_device": per_device,
        "used_bytes": int(used_bytes_total),
    }
