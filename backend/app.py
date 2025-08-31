# app.py
# uvicorn app:app --reload --host 0.0.0.0 --port 8000
# pip install "Pillow>=10" passlib[bcrypt] python-multipart

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
import secrets, uuid, io, random

# ---------- Camera demo (optional) ----------
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
except Exception:
    PIL_OK = False

# ---------- App ----------
app = FastAPI(title="SmartHome API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # จำกัด origin ตอนขึ้นโปรดักชัน
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Auth (demo) ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_users_db: Dict[str, str] = {
    "smarthome-user": pwd_context.hash("password123"),
    "admin": pwd_context.hash("admin"),
    "kasidid" : pwd_context.hash("mark")
}

class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)

class LoginResponse(BaseModel):
    success: bool
    message: str
    user: Optional[Dict[str, str]] = None

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    u = req.username.strip()
    if u not in _users_db:
        return LoginResponse(success=False, message="ไม่พบผู้ใช้")
    if not pwd_context.verify(req.password, _users_db[u]):
        return LoginResponse(success=False, message="รหัสผ่านไม่ถูกต้อง")
    return LoginResponse(success=True, message="ล็อกอินสำเร็จ", user={"username": u})

def _color_from_name(name: str) -> str:
    random.seed(name.lower())
    palette = ["#22d3ee", "#38bdf8", "#60a5fa", "#818cf8", "#a78bfa", "#34d399"]
    return palette[random.randrange(len(palette))]

@app.get("/user/{username}")
def user_profile(username: str):
    name = username.strip()
    return {
        "username": name,
        "display_name": name,
        "initial": (name[:1] or "?").upper(),
        "avatar_color": _color_from_name(name),
    }

# ---------- In-memory state ----------
STATE = {"door_locked": True}
LOGS: List[Dict] = []

# OTP: แยก active (dict) และ history (list)
OTPS: Dict[str, Dict] = {}
OTP_HISTORY: List[Dict] = []

FINGERPRINTS: Dict[str, Dict] = {}
FACES: Dict[str, Dict] = {}

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def add_log(who: str, action: str, info: str = ""):
    LOGS.append({"ts": _now_iso(), "who": who, "action": action, "info": info})
    if len(LOGS) > 500:
        del LOGS[:len(LOGS)-500]

# ---------- Door Lock ----------
class LockRequest(BaseModel):
    action: str   # lock | unlock
    who: Optional[str] = None

@app.get("/lock/status")
def lock_status():
    return {"locked": STATE["door_locked"]}

@app.post("/lock")
def lock_control(req: LockRequest):
    action = req.action.lower().strip()
    if action not in ("lock", "unlock"):
        raise HTTPException(400, detail="action ต้องเป็น lock หรือ unlock")
    STATE["door_locked"] = (action == "lock")
    add_log(req.who or "system", action.upper(), "สั่งจาก API")
    return {"ok": True, "locked": STATE["door_locked"]}

# ---------- OTP ----------
class OTPCreateRequest(BaseModel):
    minutes: int = Field(ge=1, le=1440)
    uses: int = Field(ge=1, le=100)
    who: Optional[str] = None
    comment: Optional[str] = None

class OTPUseRequest(BaseModel):
    code: str

def _push_history(item: Dict):
    """append snapshot ลงประวัติ"""
    OTP_HISTORY.append(item.copy())
    if len(OTP_HISTORY) > 1000:
        del OTP_HISTORY[:len(OTP_HISTORY)-1000]

def _cleanup_otps():
    """ย้ายรายการที่หมดอายุ/ใช้ครบออกจาก active และบันทึกลงประวัติ"""
    now = datetime.now(timezone.utc)
    for code in list(OTPS.keys()):
        o = OTPS[code]
        expired = datetime.fromisoformat(o["expires_at"]) <= now
        no_remaining = o["remaining"] <= 0
        if expired or no_remaining:
            o["status"] = "expired"
            _push_history(o)
            del OTPS[code]

@app.get("/otp/active")
def otp_active():
    _cleanup_otps()
    items = sorted(OTPS.values(), key=lambda x: x["expires_at"])
    return {"items": items}

@app.get("/otp/history")
def otp_history(limit: int = 200):
    """ประวัติ OTP ที่หมดอายุแล้วเท่านั้น (ล่าสุดก่อน)"""
    _cleanup_otps()
    expired_items = [it for it in OTP_HISTORY if it.get("status") == "expired"]
    items = expired_items[::-1][:max(1, min(1000, limit))]
    return {"items": items}


@app.post("/otp")
def otp_create(req: OTPCreateRequest):
    _cleanup_otps()
    code = f"{secrets.randbelow(10**6):06d}"
    now = datetime.now(timezone.utc)
    item = {
        "code": code,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=req.minutes)).isoformat(),
        "uses": req.uses,
        "remaining": req.uses,
        "comment": (req.comment or None),
        "status": "active",
    }
    OTPS[code] = item
    add_log(req.who or "system", "OTP_CREATE", f"{code} ({req.uses} ครั้ง / {req.minutes} นาที)")
    # history snapshot แรกเป็น active
    _push_history(item)
    return item

@app.delete("/otp/{code}")
def otp_revoke(code: str, who: Optional[str] = None):
    """ยกเลิกก่อนหมดอายุ"""
    _cleanup_otps()
    o = OTPS.pop(code, None)
    if not o:
        raise HTTPException(404, detail="ไม่พบ OTP ที่ยังใช้งาน")
    o["status"] = "revoked"
    _push_history(o)
    add_log(who or "system", "OTP_REVOKE", f"ยกเลิก {code}")
    return {"ok": True, "revoked": code}

@app.post("/otp/use")
def otp_use(req: OTPUseRequest):
    _cleanup_otps()
    o = OTPS.get(req.code)
    if not o:
        return {"valid": False, "reason": "not_found_or_expired"}
    if o["remaining"] <= 0:
        return {"valid": False, "reason": "no_remaining"}
    # ใช้ 1 ครั้ง
    o["remaining"] -= 1
    _push_history(o)  # snapshot หลังใช้
    if o["remaining"] <= 0:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[req.code]
    return {"valid": True, "remaining": o.get("remaining", 0)}

@app.delete("/otp/history/clear")
def otp_history_clear():
    n = len(OTP_HISTORY)
    OTP_HISTORY.clear()
    return {"ok": True, "cleared": n}

# ---------- Logs ----------
@app.get("/logs")
def get_logs():
    return {"items": LOGS[::-1]}

# ---------- Fingerprints ----------
class FPEnrollRequest(BaseModel):
    user: str
    finger: str

@app.get("/fingerprints")
def fp_list():
    return {"items": list(FINGERPRINTS.values())}

@app.post("/fingerprints/enroll")
def fp_enroll(req: FPEnrollRequest):
    fid = str(uuid.uuid4())
    item = {"id": fid, "user": req.user.strip(), "finger": req.finger.strip()}
    FINGERPRINTS[fid] = item
    add_log(req.user, "FP_ENROLL", req.finger)
    return item

@app.delete("/fingerprints/{fid}")
def fp_delete(fid: str):
    item = FINGERPRINTS.pop(fid, None)
    if not item:
        raise HTTPException(404, detail="ไม่พบรายการลายนิ้วมือ")
    add_log(item["user"], "FP_DELETE", item["finger"])
    return {"ok": True, "deleted": fid}

# ---------- Faces ----------
@app.get("/faces")
def face_list():
    return {"items": list(FACES.values())}

@app.post("/faces/enroll")
async def face_enroll(user: str = Form(...), file: UploadFile = File(None)):
    fid = str(uuid.uuid4())
    file_name = None
    if file is not None:
        await file.read()
        file_name = file.filename
    item = {"id": fid, "user": user.strip(), "file_name": file_name}
    FACES[fid] = item
    add_log(user, "FACE_ENROLL", file_name or "-")
    return item

@app.delete("/faces/{fid}")
def face_delete(fid: str):
    item = FACES.pop(fid, None)
    if not item:
        raise HTTPException(404, detail="ไม่พบข้อมูลใบหน้า")
    add_log(item["user"], "FACE_DELETE", item.get("file_name") or "-")
    return {"ok": True, "deleted": fid}

# ---------- UI state ----------
@app.get("/ui/state")
def ui_state():
    _cleanup_otps()
    return {
        "door": {"locked": STATE["door_locked"]},
        "otp": {"items": list(OTPS.values())},
        "otp_history": OTP_HISTORY[::-1][:200],
        "logs": LOGS[::-1][:100],
        "fingerprints": list(FINGERPRINTS.values()),
        "faces": list(FACES.values()),
    }

# ---------- Camera demo ----------
def _make_frame_bytes(text: str = "SmartHome Camera") -> bytes:
    if not PIL_OK:
        # 1x1 black PNG (fallback)
        return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0bIDATx\x9cc``\x00\x00"
                b"\x00\x04\x00\x01\x0b\xe7\x02b\x00\x00\x00\x00IEND\xaeB`\x82")
    img = Image.new("RGB", (640, 360), (10, 14, 26))
    d = ImageDraw.Draw(img)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    caption = f"{text}\n{now}"
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    d.rectangle([(16,16),(624,120)], outline=(180,180,255))
    d.text((24,24), caption, fill=(235,240,255), font=font, spacing=4)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80)
    return buf.getvalue()

@app.get("/camera/snapshot")
def camera_snapshot():
    frame = _make_frame_bytes("Snapshot")
    return Response(content=frame, media_type="image/jpeg")

@app.get("/camera/mjpeg")
def camera_mjpeg():
    boundary = "frame"
    def gen():
        import time
        while True:
            frame = _make_frame_bytes("Live MJPEG")
            yield (b"--" + boundary.encode() + b"\r\n"
                   b"Content-Type: image/jpeg\r\n"
                   b"Content-Length: " + str(len(frame)).encode() + b"\r\n\r\n" +
                   frame + b"\r\n")
            time.sleep(0.1)
    return StreamingResponse(gen(), media_type=f"multipart/x-mixed-replace; boundary={boundary}")
