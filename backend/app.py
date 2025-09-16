# app.py
# uvicorn app:app --reload --host 0.0.0.0 --port 8000
#pip install -r requirements.txt

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
from os import getenv
import os, secrets, uuid, io, random
import threading, requests  # <-- เพิ่ม
from dotenv import load_dotenv  # <-- เพิ่ม
import subprocess

load_dotenv()
RPI_CAMERA_BASE = getenv("RPI_CAMERA_BASE", "http://127.0.0.1:8080")
# ---------- Camera demo (optional) ----------
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
except Exception:
    PIL_OK = False

# ---------- App ----------
app = FastAPI(title="SmartHome API", version="3.0.0")
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5500", 
    "http://192.168.56.1:8000",
    "http://192.168.56.1:8000/web/login.html"
    # ใส่โดเมนจริงของเว็บคุณเพิ่มได้ เช่น "https://yourdomain.com"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,   # ถ้าไม่ต้องใช้คุกกี้/credentials จะตั้ง False ก็ได้
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Auth (demo) ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_users_db: Dict[str, str] = {
    "smarthome-user": pwd_context.hash("password123"),
    "admin": pwd_context.hash("admin"),
    "kasidid": pwd_context.hash("mark"),
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

# OTP state
OTPS: Dict[str, Dict] = {}
OTP_HISTORY: List[Dict] = []

# Biometric demo
FINGERPRINTS: Dict[str, Dict] = {}
FACES: Dict[str, Dict] = {}

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def add_log(who: str, action: str, info: str = ""):
    LOGS.append({"ts": _now_iso(), "who": who, "action": action, "info": info})
    if len(LOGS) > 500:
        del LOGS[:len(LOGS)-500]
TELEGRAM_BOT_TOKEN = getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = getenv("TELEGRAM_CHAT_ID")

def _tg_enabled() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)

def _send_telegram_message(text: str):
    """
    ส่งข้อความไป Telegram แบบไม่บล็อก (background thread)
    ใช้ HTML ได้ เช่น <b>หนา</b>
    """
    if not _tg_enabled():
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    def _post():
        try:
            requests.post(url, json=payload, timeout=6)
        except Exception:
            pass
    threading.Thread(target=_post, daemon=True).start()

# ---------- Door Lock ----------
class LockRequest(BaseModel):
    action: str   # lock | unlock
    who: Optional[str] = None

@app.get("/lock/status")
def lock_status():
    return {"locked": STATE["door_locked"]}

def _now_hms():
    # คืนค่าเวลาแบบ HH:mm:ss (UTC)
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

@app.post("/lock")
def lock_control(req: LockRequest):
    action = req.action.lower().strip()
    if action not in ("lock", "unlock"):
        raise HTTPException(400, detail="action ต้องเป็น lock หรือ unlock")

    STATE["door_locked"] = (action == "lock")
    add_log(req.who or "system", action.upper(), "สั่งจาก API")

    if action == "unlock":
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: API\nBy: {req.who or 'system'}\nTime: {_now_hms()}"
        )

    if action == "lock":
        _send_telegram_message(
            f"🔐 <b>Door Locked</b>\nBy: {req.who or 'system'}\nTime: {_now_hms()}"
        )

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
    OTP_HISTORY.append(item.copy())
    if len(OTP_HISTORY) > 1000:
        del OTP_HISTORY[:len(OTP_HISTORY)-1000]

def _cleanup_otps():
    now = datetime.now(timezone.utc)
    for code in list(OTPS.keys()):
        o = OTPS[code]
        expired = datetime.fromisoformat(o["expires_at"]) <= now
        no_remaining = o["remaining"] <= 0
        if expired or no_remaining:
            o["status"] = "expired"
            _push_history(o)
            del OTPS[code]
def _consume_otp(code: str):
    """
    ใช้ OTP 1 ครั้ง:
    - สำเร็จ: คืน (True, remaining_after, item_snapshot)
    - ไม่สำเร็จ: คืน (False, reason, None)
      reason: "not_found_or_expired" | "no_remaining"
    """
    _cleanup_otps()
    o = OTPS.get(code)
    now = datetime.now(timezone.utc)

    if not o:
        return (False, "not_found_or_expired", None)

    # เช็คหมดอายุ
    if datetime.fromisoformat(o["expires_at"]) <= now:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[code]
        return (False, "not_found_or_expired", None)

    if o["remaining"] <= 0:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[code]
        return (False, "no_remaining", None)

    # ใช้ 1 ครั้ง
    o["remaining"] -= 1
    _push_history(o)  # snapshot หลังใช้

    # ถ้าใช้หมด → ปิดสถานะ & ย้ายไป history แล้วลบจาก active
    if o["remaining"] <= 0:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[code]

    return (True, o.get("remaining", 0), o)

@app.get("/otp/active")
def otp_active():
    _cleanup_otps()
    items = sorted(OTPS.values(), key=lambda x: x["expires_at"])
    return {"items": items}

@app.get("/otp/history")
def otp_history(limit: int = 200):
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
    _push_history(item)
    return item

@app.delete("/otp/{code}")
def otp_revoke(code: str, who: Optional[str] = None):
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
    o["remaining"] -= 1
    _push_history(o)
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

# ---------- PIN Unlock (with default + change) ----------
class PinVerifyRequest(BaseModel):
    pin: str = Field(min_length=6, max_length=6)

class PinSetRequest(BaseModel):
    current_pin: Optional[str] = None   # ถ้ายัง default อนุญาตให้ไม่ส่ง
    new_pin: str = Field(min_length=6, max_length=6)

DEFAULT_PIN = getenv("SMARTLOCK_DEFAULT_PIN", "123456")  # ตั้งผ่าน ENV ได้
PIN_IS_DEFAULT = True
PIN_HASH = pwd_context.hash(DEFAULT_PIN)

def _verify_pin(raw_pin: str) -> bool:
    p = (raw_pin or "").strip()
    if len(p) != 6 or not p.isdigit():
        return False
    return pwd_context.verify(p, PIN_HASH)

@app.get("/pin/info")
def pin_info():
    return {"success": True, "is_default": PIN_IS_DEFAULT, "length": 6}

@app.post("/pin/verify")
def pin_verify(req: PinVerifyRequest):
    if _verify_pin(req.pin):
        add_log("pin", "PIN_VERIFY_OK", "verify only")
        return {"success": True, "message": "PIN OK"}
    add_log("pin", "PIN_VERIFY_FAIL", "invalid pin")
    return {"success": False, "message": "PIN ไม่ถูกต้อง"}

@app.post("/pin/unlock")
def pin_unlock(req: PinVerifyRequest):
    # 1) ถ้าเป็น PIN ที่ถูกต้อง → ปลดล็อก
    if _verify_pin(req.pin):
        STATE["door_locked"] = False
        add_log("pin", "UNLOCK", "ปลดล็อกจาก PIN")
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: PIN\nTime: {_now_iso()}"
        )
        return {"success": True, "method": "pin", "message": "ประตูปลดล็อกแล้ว", "locked": STATE["door_locked"]}

    # 2) ถ้าไม่ใช่ PIN → ลอง OTP
    ok, info, item = _consume_otp(req.pin)
    if ok:
        STATE["door_locked"] = False
        remaining = info  # จำนวนครั้งที่เหลือหลังหัก 1
        add_log("otp", "UNLOCK", f"ปลดล็อกจาก OTP {req.pin} (เหลือ {remaining})")
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: OTP\nRemaining: {remaining}\nTime: {_now_iso()}"
        )
        return {
            "success": True,
            "method": "otp",
            "message": f"ปลดล็อกด้วย OTP (เหลือ {remaining} ครั้ง)",
            "remaining": remaining,
            "locked": STATE["door_locked"],
        }
    else:
        reason = info
        if reason == "no_remaining":
            msg = "OTP นี้ถูกใช้ครบแล้ว"
        else:
            msg = "OTP หมดอายุหรือไม่พบ"
        add_log("otp", "UNLOCK_FAIL", f"{req.pin}: {msg}")
        _send_telegram_message(
            f"❌ <b>Unlock Attempt Failed</b>\nReason: {msg}\nTime: {_now_iso()}"
        )
        return {"success": False, "message": msg}



@app.post("/pin/set")
def pin_set(req: PinSetRequest):
    global PIN_HASH, PIN_IS_DEFAULT
    newp = (req.new_pin or "").strip()
    if not newp.isdigit() or len(newp) != 6:
        raise HTTPException(400, detail="new_pin ต้องเป็นตัวเลข 6 หลัก")

    if PIN_IS_DEFAULT:
        # ตั้งครั้งแรก ไม่ต้องใช้ current_pin
        PIN_HASH = pwd_context.hash(newp)
        PIN_IS_DEFAULT = False
        add_log("pin", "PIN_SET", "set from default")
        return {"success": True, "message": "ตั้ง PIN ใหม่สำเร็จ (จากค่าเริ่มต้น)"}
    else:
        cur = (req.current_pin or "").strip()
        if not _verify_pin(cur):
            raise HTTPException(401, detail="current_pin ไม่ถูกต้อง")
        PIN_HASH = pwd_context.hash(newp)
        PIN_IS_DEFAULT = False
        add_log("pin", "PIN_SET", "changed")
        return {"success": True, "message": "เปลี่ยน PIN ใหม่สำเร็จ"}


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
    try:
        r = requests.get(f"{RPI_CAMERA_BASE}/?action=snapshot", timeout=5)
        r.raise_for_status()
        return Response(content=r.content, media_type="image/jpeg")
    except Exception as e:
        raise HTTPException(502, detail=f"Snapshot upstream error: {e}")

@app.get("/camera/mjpeg")
def camera_mjpeg():
    try:
        upstream = requests.get(f"{RPI_CAMERA_BASE}/?action=stream", stream=True, timeout=10)
        upstream.raise_for_status()
        ctype = upstream.headers.get("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        return StreamingResponse(upstream.iter_content(chunk_size=1024), media_type=ctype)
    except Exception as e:
        raise HTTPException(502, detail=f"MJPEG upstream error: {e}")

# ---------- Static Web ----------
# โฟลเดอร์ 'web' ต้องอยู่โฟลเดอร์เดียวกับ app.py
if not os.path.isdir("web"):
    os.makedirs("web", exist_ok=True)

app.mount("/web", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
def root():
    # ไปที่ /web/ เพื่อเปิดหน้า index.html
    return RedirectResponse(url="/web/")

@app.get("/favicon.ico")
def favicon():
    path = os.path.join("web", "favicon.ico")
    if os.path.exists(path):
        return FileResponse(path)
    return Response(status_code=204)
# app.py
# uvicorn app:app --reload --host 0.0.0.0 --port 8000
#pip install -r requirements.txt

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
from os import getenv
import os, secrets, uuid, io, random
import threading, requests  # <-- เพิ่ม
from dotenv import load_dotenv  # <-- เพิ่ม
import subprocess
import shlex
import shutil 
from zoneinfo import ZoneInfo  # Python 3.9+

TZ_NAME = os.getenv("TZ") or os.getenv("TIMEZONE") or "Asia/Bangkok"
try:
    LOCAL_TZ = ZoneInfo(TZ_NAME)
except Exception:
    # ถ้าหาโซนไม่เจอ ใช้โซนของระบบเป็น fallback
    LOCAL_TZ = datetime.now().astimezone().tzinfo

def _now_local():
    return datetime.now(LOCAL_TZ)

def _now_hms():
    # เดิมใช้ timezone.utc -> เปลี่ยนเป็นเวลาท้องถิ่น
    return _now_local().strftime("%H:%M:%S")

def _now_local_iso():
    return _now_local().isoformat()

# === AI Cam (LBPH) imports ===
import json, collections
try:
    import cv2, numpy as np
except Exception:
    cv2 = None
    np = None

# ---------- Servo Control ----------
import pigpio, time
BOUNDARY = "frame"
PIN = 12  # ถ้าใช้ Header Pin 12 (PWM) จริง ๆ ควรเป็น BCM18; ถ้าเสียบ BCM12 ให้แก้คอมเมนต์ให้ตรง
MIN_US = 500
MAX_US = 2500
AI_FACE_HOLD_SEC = float(os.getenv("AI_FACE_HOLD_SEC", "5"))  # เวลาค้างเปิดขั้นต่ำ/กรณีคนออกจากกล้อง

load_dotenv()
# ✅ ปรับมุมตามที่ต้องการ
SERVO_LOCK_ANGLE = 90     # มุมตอน "ล็อก"  (อยู่กลาง 90°)
SERVO_UNLOCK_ANGLE = 180  # มุมตอน "ปลดล็อก"


def angle_to_us(angle, min_us=MIN_US, max_us=MAX_US):
    angle = max(0, min(180, float(angle)))
    return int(min_us + (max_us - min_us) * (angle / 180.0))

def _servo_go(angle: float, hold: float = 0.6):
    """สั่งเซอร์โวไปมุมที่กำหนด; ต้องมี pigpiod รันอยู่"""
    pi = pigpio.pi()
    if not pi.connected:
        raise RuntimeError("pigpio daemon ไม่ได้รันอยู่ (ลอง sudo systemctl start pigpiod)")
    try:
        us = angle_to_us(angle)
        pi.set_servo_pulsewidth(PIN, us)
        time.sleep(hold)  # รอสั้นๆ ให้ถึงตำแหน่ง
        # หมายเหตุ: ถ้าต้องการค้างแรงบิด ให้คง pulse ไว้ (ไม่ set 0)
    finally:
        pi.stop()
def _which(cmd: str) -> str | None:
    return shutil.which(cmd)

def _spawn_camera_mjpeg(width=1280, height=720, fps=30, quality=85):
    """
    พยายามใช้ rpicam-vid ก่อน ถ้าไม่มี ค่อยลอง libcamera-vid
    """
    if _which("rpicam-vid"):
        cmd = (
            f"rpicam-vid -t 0 --width {width} --height {height} "
            f"--framerate {fps} --codec mjpeg --quality {quality} -o -"
        )
    elif _which("libcamera-vid"):
        cmd = (
            f"libcamera-vid -t 0 --width {width} --height {height} "
            f"--framerate {fps} --codec mjpeg --quality {quality} -o -"
        )
    else:
        raise RuntimeError("ไม่พบ rpicam-vid หรือ libcamera-vid ในระบบ")

    proc = subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    return proc

def _run_camera_still():
    """
    พยายามใช้ rpicam-still ก่อน ถ้าไม่มี ค่อยลอง libcamera-still
    คืนค่า bytes ของ JPEG
    """
    if _which("rpicam-still"):
        cmd = "rpicam-still -n -e jpg -q 90 -o -"
    elif _which("libcamera-still"):
        cmd = "libcamera-still -n -e jpg -q 90 -o -"
    else:
        raise RuntimeError("ไม่พบ rpicam-still หรือ libcamera-still ในระบบ")

    proc = subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=8
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError("camera-still command failed")
    return proc.stdout

def _spawn_libcamera_mjpeg(width=1280, height=720, fps=30, quality=85):
    cmd = (
        f"libcamera-vid -t 0 --width {width} --height {height} "
        f"--framerate {fps} --codec mjpeg --quality {quality} -o -"
    )
    proc = subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    return proc

def _jpeg_frames_from_stdout(stream, chunk_size=65536):
    SOI, EOI = b"\xff\xd8", b"\xff\xd9"
    buf = bytearray()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        buf.extend(chunk)
        while True:
            start = buf.find(SOI)
            if start < 0: break
            end = buf.find(EOI, start + 2)
            if end < 0: break
            frame = bytes(buf[start:end+2])
            yield frame
            del buf[:end+2]
            
            
def servo_for_state(locked: bool):
    """
    โหมดค้างยาว:
      - locked=True  -> ไปที่ SERVO_LOCK_ANGLE (90°) แล้วค้างไว้ยาว
      - locked=False -> ไปที่ SERVO_UNLOCK_ANGLE (180°) แล้วค้างไว้ยาว
    หมายเหตุ: เรา 'ไม่' set 0 หลังจากนี้ เพื่อค้างแรงบิดไว้จนกว่าจะมีคำสั่งใหม่
    """
    target = SERVO_LOCK_ANGLE if locked else SERVO_UNLOCK_ANGLE

    def _worker():
        try:
            _servo_go(target, hold=0.6)  # ไปที่มุมเป้าหมายแล้วค้าง pulse ต่อ
            add_log("servo", "MOVE", f"hold at {target}°")
        except Exception as e:
            add_log("servo", "ERROR", str(e))

    threading.Thread(target=_worker, daemon=True).start()

def servo_unlock_temp(hold_sec: float = 5.0):
    """
    ปลดล็อกชั่วคราว: ไป 180° ค้าง hold_sec วินาที แล้วกลับมาล็อก 90°
    ใช้เฉพาะตอนปลดล็อกด้วย PIN
    """
    def _worker():
        try:
            _servo_go(SERVO_UNLOCK_ANGLE, hold=0.6)
            add_log("servo", "MOVE", f"pin unlock -> {SERVO_UNLOCK_ANGLE}° (hold {hold_sec}s)")
            time.sleep(max(0.0, hold_sec))
            _servo_go(SERVO_LOCK_ANGLE, hold=0.6)
            add_log("servo", "MOVE", f"auto relock -> {SERVO_LOCK_ANGLE}°")
            STATE["door_locked"] = True
        except Exception as e:
            add_log("servo", "ERROR", f"pin unlock temp: {e}")

    threading.Thread(target=_worker, daemon=True).start()

RPI_CAMERA_BASE = getenv("RPI_CAMERA_BASE", "http://127.0.0.1:8080")
# ---------- Camera demo (optional) ----------
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
except Exception:
    PIL_OK = False

# ---------- App ----------
app = FastAPI(title="SmartHome API", version="3.0.0")
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
    "http://192.168.56.1:8000", 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,   # ถ้าไม่ต้องใช้คุกกี้/credentials จะตั้ง False ก็ได้
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Auth (demo) ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_users_db: Dict[str, str] = {
    "smarthome-user": pwd_context.hash("password123"),
    "admin": pwd_context.hash("admin"),
    "kasidid": pwd_context.hash("mark"),
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
    return {"status": "ok", "time": _now_local_iso()}


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

# OTP state
OTPS: Dict[str, Dict] = {}
OTP_HISTORY: List[Dict] = []

# Biometric demo
FINGERPRINTS: Dict[str, Dict] = {}
FACES: Dict[str, Dict] = {}

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def add_log(who: str, action: str, info: str = ""):
    LOGS.append({"ts": _now_local_iso(), "who": who, "action": action, "info": info})
    if len(LOGS) > 500:
        del LOGS[:len(LOGS)-500]
TELEGRAM_BOT_TOKEN = getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = getenv("TELEGRAM_CHAT_ID")

def _tg_enabled() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)

def _send_telegram_message(text: str):
    """
    ส่งข้อความไป Telegram แบบไม่บล็อก (background thread)
    ใช้ HTML ได้ เช่น <b>หนา</b>
    """
    if not _tg_enabled():
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    def _post():
        try:
            requests.post(url, json=payload, timeout=6)
        except Exception:
            pass
    threading.Thread(target=_post, daemon=True).start()

# ---------- Door Lock ----------
class LockRequest(BaseModel):
    action: str   # lock | unlock | (ยอมรับคำพ้องด้วย)
    who: Optional[str] = None

def _normalize_action(s: str) -> str:
    """ map คำพ้องให้เหลือ lock / unlock """
    s = (s or "").strip().lower()
    unlock_words = {"unlock","open","เปิด","open_door","1","true","on"}
    lock_words   = {"lock","close","ปิด","close_door","0","false","off"}

    if s in unlock_words:
        return "unlock"
    if s in lock_words:
        return "lock"
    return s  # เผื่อกรณีส่งตรง lock/unlock อยู่แล้ว
@app.get("/lock/status")
def lock_status():
    return {"locked": STATE["door_locked"]}

@app.post("/lock")
def lock_control(req: LockRequest):
    action = _normalize_action(req.action)
    if action not in ("lock", "unlock"):
        raise HTTPException(400, detail="action ต้องเป็น lock/unlock หรือคำพ้อง open/close/เปิด/ปิด/1/0")

    STATE["door_locked"] = (action == "lock")
    add_log(req.who or "system", action.upper(), "สั่งจาก API")

    # สั่งเซอร์โวตามสถานะใหม่ (non-blocking)
    servo_for_state(STATE["door_locked"])

    if action == "unlock":
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: API\nBy: {req.who or 'system'}\nTime: {_now_hms()}"# type: ignore
        )
    else:
        _send_telegram_message(
            f"🔐 <b>Door Locked</b>\nBy: {req.who or 'system'}\nTime: {_now_hms()}"# type: ignore
        )

    return {"ok": True, "locked": STATE["door_locked"]}

# ✅ สร้าง alias ให้ Dashboard เรียกง่าย ๆ
@app.post("/door/open")
def door_open(who: Optional[str] = None):
    STATE["door_locked"] = False
    add_log(who or "system", "UNLOCK", "alias /door/open")
    servo_for_state(False)
    _send_telegram_message(f"🔓 <b>Door Unlocked</b>\nMethod: /door/open\nTime: {_now_hms()}")# type: ignore
    return {"ok": True, "locked": STATE["door_locked"]}

@app.post("/door/close")
def door_close(who: Optional[str] = None):
    STATE["door_locked"] = True
    add_log(who or "system", "LOCK", "alias /door/close")
    servo_for_state(True)
    _send_telegram_message(f"🔐 <b>Door Locked</b>\nMethod: /door/close\nTime: {_now_hms()}")# type: ignore
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
    OTP_HISTORY.append(item.copy())
    if len(OTP_HISTORY) > 1000:
        del OTP_HISTORY[:len(OTP_HISTORY)-1000]

def _cleanup_otps():
    now = datetime.now(timezone.utc)
    for code in list(OTPS.keys()):
        o = OTPS[code]
        expired = datetime.fromisoformat(o["expires_at"]) <= now
        no_remaining = o["remaining"] <= 0
        if expired or no_remaining:
            o["status"] = "expired"
            _push_history(o)
            del OTPS[code]
def _consume_otp(code: str):
    """
    ใช้ OTP 1 ครั้ง:
    - สำเร็จ: คืน (True, remaining_after, item_snapshot)
    - ไม่สำเร็จ: คืน (False, reason, None)
      reason: "not_found_or_expired" | "no_remaining"
    """
    _cleanup_otps()
    o = OTPS.get(code)
    now = datetime.now(timezone.utc)

    if not o:
        return (False, "not_found_or_expired", None)

    # เช็คหมดอายุ
    if datetime.fromisoformat(o["expires_at"]) <= now:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[code]
        return (False, "not_found_or_expired", None)

    if o["remaining"] <= 0:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[code]
        return (False, "no_remaining", None)

    # ใช้ 1 ครั้ง
    o["remaining"] -= 1
    _push_history(o)  # snapshot หลังใช้

    # ถ้าใช้หมด → ปิดสถานะ & ย้ายไป history แล้วลบจาก active
    if o["remaining"] <= 0:
        o["status"] = "expired"
        _push_history(o)
        del OTPS[code]

    return (True, o.get("remaining", 0), o)

@app.get("/otp/active")
def otp_active():
    _cleanup_otps()
    items = sorted(OTPS.values(), key=lambda x: x["expires_at"])
    return {"items": items}

@app.get("/otp/history")
def otp_history(limit: int = 200):
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
    _push_history(item)
    return item

@app.delete("/otp/{code}")
def otp_revoke(code: str, who: Optional[str] = None):
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
    o["remaining"] -= 1
    _push_history(o)
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
# สำหรับ /face/unlock และการส่งชื่อจาก AI Cam
class FaceUnlockRequest(BaseModel):
    name: str
    conf: Optional[float] = None

# ✅ เพิ่ม endpoint สำหรับปลดล็อกด้วยใบหน้า
@app.post("/face/unlock")
def face_unlock(req: FaceUnlockRequest):
    # ตรวจสอบว่าชื่อที่ส่งมาตรงกับใบหน้าที่ลงทะเบียนไว้หรือไม่
    # ในตัวอย่างนี้ เราจะถือว่าถ้ามีการเรียก endpoint นี้ แสดงว่าจดจำใบหน้าได้แล้ว
    # และจะทำการปลดล็อกประตู
    
    # ตรวจสอบว่ามีใบหน้าของคนนี้ลงทะเบียนอยู่หรือไม่ (ไม่จำเป็นต้องเป๊ะ แต่เพื่อความสมจริง)
    found_face = False
    for face_id, face_data in FACES.items():
        if face_data["user"].lower() == req.name.lower():
            found_face = True
            break
    
    if not found_face:
        add_log(req.name, "FACE_UNLOCK_FAIL", f"ไม่พบใบหน้าของ {req.name} ในระบบ")
        _send_telegram_message(
            f"❌ <b>Face Unlock Failed</b>\nReason: Face '{req.name}' not registered\nTime: {_now_hms()}"
        )
        raise HTTPException(404, detail=f"ไม่พบใบหน้าของ {req.name} ในระบบ")
    STATE["door_locked"] = False
    add_log(req.name, "FACE_UNLOCK", f"ปลดล็อกจากใบหน้า (conf: {req.conf or 'N/A'})")
    _send_telegram_message(
        f"🔓 <b>Door Unlocked</b>\nMethod: Face Recognition\nBy: {req.name}\nConfidence: {req.conf or 'N/A'}\nTime: {_now_hms()}"
    )
    
    # 👉 สั่งเซอร์โวปลดล็อกชั่วคราว 5 วินาที แล้วล็อกกลับ
    servo_unlock_temp(hold_sec=5.0)
    return {
        "success": True,
        "message": f"ปลดล็อกด้วยใบหน้าของ {req.name}",
        "locked": STATE["door_locked"],
    }
    

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

# ---------- PIN Unlock (with default + change) ----------
class PinVerifyRequest(BaseModel):
    pin: str = Field(min_length=6, max_length=6)

class PinSetRequest(BaseModel):
    current_pin: Optional[str] = None   # ถ้ายัง default อนุญาตให้ไม่ส่ง
    new_pin: str = Field(min_length=6, max_length=6)

DEFAULT_PIN = getenv("SMARTLOCK_DEFAULT_PIN", "123456")  # ตั้งผ่าน ENV ได้
PIN_IS_DEFAULT = True
PIN_HASH = pwd_context.hash(DEFAULT_PIN)

def _verify_pin(raw_pin: str) -> bool:
    p = (raw_pin or "").strip()
    if len(p) != 6 or not p.isdigit():
        return False
    return pwd_context.verify(p, PIN_HASH)

@app.get("/pin/info")
def pin_info():
    return {"success": True, "is_default": PIN_IS_DEFAULT, "length": 6}

@app.post("/pin/verify")
def pin_verify(req: PinVerifyRequest):
    if _verify_pin(req.pin):
        add_log("pin", "PIN_VERIFY_OK", "verify only")
        return {"success": True, "message": "PIN OK"}
    add_log("pin", "PIN_VERIFY_FAIL", "invalid pin")
    return {"success": False, "message": "PIN ไม่ถูกต้อง"}

@app.post("/pin/unlock")
def pin_unlock(req: PinVerifyRequest):
    # 1) ปลดล็อกด้วย PIN
    if _verify_pin(req.pin):
        STATE["door_locked"] = False
        add_log("pin", "UNLOCK", "ปลดล็อกจาก PIN")
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: PIN\nTime: {_now_iso()}"
        )
        # 👉 ปลดล็อกชั่วคราว 5 วิ แล้วล็อกกลับ
        servo_unlock_temp(hold_sec=5.0)
        return {
            "success": True,
            "method": "pin",
            "message": "ปลดล็อกด้วย PIN (5 วิแล้วล็อกกลับ)",
            "locked": STATE["door_locked"],
        }


    # 2) ลองปลดล็อกด้วย OTP
    ok, info, item = _consume_otp(req.pin)
    if ok:
        STATE["door_locked"] = False
        remaining = info
        add_log("otp", "UNLOCK", f"ปลดล็อกจาก OTP {req.pin} (เหลือ {remaining})")
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: OTP\nRemaining: {remaining}\nTime: {_now_iso()}"
        )
        # 👉 สั่งเซอร์โว
        servo_unlock_temp(hold_sec=5.0)
        return {
            "success": True,
            "method": "otp",
            "message": f"ปลดล็อกด้วย OTP (เหลือ {remaining} ครั้ง)",
            "remaining": remaining,
            "locked": STATE["door_locked"],
        }
    else:
        reason = info
        if reason == "no_remaining":
            msg = "OTP นี้ถูกใช้ครบแล้ว"
        else:
            msg = "OTP หมดอายุหรือไม่พบ"
        add_log("otp", "UNLOCK_FAIL", f"{req.pin}: {msg}")
        _send_telegram_message(
            f"❌ <b>Unlock Attempt Failed</b>\nReason: {msg}\nTime: {_now_iso()}"
        )
        return {"success": False, "message": msg}


@app.post("/pin/set")
def pin_set(req: PinSetRequest):
    global PIN_HASH, PIN_IS_DEFAULT
    newp = (req.new_pin or "").strip()
    if not newp.isdigit() or len(newp) != 6:
        raise HTTPException(400, detail="new_pin ต้องเป็นตัวเลข 6 หลัก")

    if PIN_IS_DEFAULT:
        # ตั้งครั้งแรก ไม่ต้องใช้ current_pin
        PIN_HASH = pwd_context.hash(newp)
        PIN_IS_DEFAULT = False
        add_log("pin", "PIN_SET", "set from default")
        return {"success": True, "message": "ตั้ง PIN ใหม่สำเร็จ (จากค่าเริ่มต้น)"}
    else:
        cur = (req.current_pin or "").strip()
        if not _verify_pin(cur):
            raise HTTPException(401, detail="current_pin ไม่ถูกต้อง")
        PIN_HASH = pwd_context.hash(newp)
        PIN_IS_DEFAULT = False
        add_log("pin", "PIN_SET", "changed")
        return {"success": True, "message": "เปลี่ยน PIN ใหม่สำเร็จ"}


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
def camera_snapshot_live():
    try:
        jpeg = _run_camera_still()
        return Response(content=jpeg, media_type="image/jpeg")
    except Exception as e:
        raise HTTPException(502, detail=f"Snapshot error: {e}")


@app.get("/camera/mjpeg")
def camera_mjpeg_live():
    try:
        proc = _spawn_camera_mjpeg()  # เปลี่ยนมาใช้ helper ใหม่
        if proc.stdout is None:
            raise RuntimeError("camera-vid stdout not available")

        def _gen():
            try:
                for jpeg in _jpeg_frames_from_stdout(proc.stdout):
                    yield (
                        f"--{BOUNDARY}\r\n"
                        "Content-Type: image/jpeg\r\n"
                        f"Content-Length: {len(jpeg)}\r\n\r\n"
                    ).encode() + jpeg + b"\r\n"
            finally:
                try: proc.kill()
                except: pass

        return StreamingResponse(
            _gen(),
            media_type=f"multipart/x-mixed-replace; boundary={BOUNDARY}",
        )
    except Exception as e:
        raise HTTPException(502, detail=f"MJPEG live error: {e}")


# ---------- Static Web ----------
# โฟลเดอร์ 'web' ต้องอยู่โฟลเดอร์เดียวกับ app.py
if not os.path.isdir("web"):
    os.makedirs("web", exist_ok=True)

app.mount("/web", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
def root():
    # ไปที่ /web/ เพื่อเปิดหน้า index.html
    return RedirectResponse(url="/web/")

@app.get("/favicon.ico")
def favicon():
    path = os.path.join("web", "favicon.ico")
    if os.path.exists(path):
        return FileResponse(path)
    return Response(status_code=204)

#8888888888#

def angle_to_us(angle, min_us=MIN_US, max_us=MAX_US):
    angle = max(0, min(180, float(angle)))
    return int(min_us + (max_us - min_us) * (angle / 180.0))

def servo_demo():
    """
    ทดสอบ Servo:
    เริ่ม 90° -> หมุนไป 180° -> ค้าง 5 วิ -> กลับมา 90°
    """
    pi = pigpio.pi()
    if not pi.connected:
        raise RuntimeError("pigpio daemon ไม่ได้รันอยู่ (ลอง sudo systemctl start pigpiod)")

    try:
        # เริ่มต้นที่ 90°
        mid_angle = 180
        us = angle_to_us(mid_angle)
        pi.set_servo_pulsewidth(PIN, us)
        print(f"เริ่มที่ {mid_angle}° -> {us} µs")
        time.sleep(1.0)

        # หมุนไป 180°
        end_angle = 90
        us = angle_to_us(end_angle)
        pi.set_servo_pulsewidth(PIN, us)
        print(f"หมุนไป {end_angle}° -> {us} µs")
        time.sleep(5.0)

        # กลับมาที่ 90°
        us = angle_to_us(mid_angle)
        pi.set_servo_pulsewidth(PIN, us)
        print(f"กลับมาที่ {mid_angle}° -> {us} µs")
        time.sleep(1.0)

    finally:
        pi.set_servo_pulsewidth(PIN, 0)
        pi.stop()

@app.post("/servo/test")
def servo_test():
    """
    เรียก endpoint นี้เพื่อให้ Servo หมุนทดสอบ
    """
    try:
        servo_demo()
        return {"ok": True, "message": "servo moved"}
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    
# ========== AI Camera (LBPH) Worker ==========
AI = None  # global worker
FRAME_LOCK = threading.Lock()
LAST_JPEG = None

# --- ค่า config ผ่าน ENV ---
AI_CAM_SRC = os.getenv("CAM_SRC", "picam")   # "picam" | camera index "0" | RTSP URL
AI_FACE_SIZE = tuple(map(int, os.getenv("FACE_SIZE", "160,160").split(",")))
AI_CONF_THR  = float(os.getenv("CONF_THR", "120"))   # LBPH distance: ยิ่งต่ำยิ่งดี
AI_VOTE_LEN  = int(os.getenv("VOTE_LEN", "5"))
AI_SHOW_GUI  = bool(int(os.getenv("SHOW_GUI", "0")))
AI_MODEL     = os.getenv("LBPH_MODEL", "models/lbph.yml")
AI_LABELS    = os.getenv("LBPH_LABELS", "models/labels.json")
AI_CASCADE   = os.getenv("CASCADE_PATH", "/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml")
# เข้ารหัส JPEG เก็บไว้ให้เว็บดึง
try:
    ok_j, enc = cv2.imencode(".jpg", bgr, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
    if ok_j:
        data = enc.tobytes()
        with FRAME_LOCK:
            LAST_JPEG = data
except Exception:
    pass

def _build_cascade():
    cands = [AI_CASCADE,
             "/usr/share/opencv/haarcascades/haarcascade_frontalface_default.xml",
             "/usr/local/share/opencv4/haarcascades/haarcascade_frontalface_default.xml"]
    for p in cands:
        if p and os.path.exists(p):
            cas = cv2.CascadeClassifier(p)
            if not cas.empty():
                print(f"[AI] Haar: {p}")
                return cas
    raise RuntimeError("ไม่พบ haarcascade_frontalface_default.xml (ตั้ง CASCADE_PATH หรือ apt install opencv-data)")

def _load_lbph():
    if cv2 is None or not hasattr(cv2, "face") or not hasattr(cv2.face, "LBPHFaceRecognizer_create"):
        raise RuntimeError("ต้องใช้ opencv-contrib-python (มี cv2.face)")
    if not os.path.exists(AI_MODEL):
        raise RuntimeError(f"ไม่พบโมเดล LBPH: {AI_MODEL}")
    rec = cv2.face.LBPHFaceRecognizer_create()
    rec.read(AI_MODEL)
    id2name = {}
    if os.path.exists(AI_LABELS):
        raw = json.load(open(AI_LABELS, "r", encoding="utf-8"))
        # รองรับทั้ง id->name และ name->id
        def is_int_like(x):
            try: int(x); return True
            except: return False
        if isinstance(raw, dict):
            if all(is_int_like(k) for k in raw.keys()):
                id2name = {int(k): str(v) for k, v in raw.items()}
            elif all(is_int_like(v) for v in raw.values()):
                id2name = {int(v): str(k) for k, v in raw.items()}
            else:
                for k, v in raw.items():
                    if is_int_like(k): id2name[int(k)] = str(v)
                    elif is_int_like(v): id2name[int(v)] = str(k)
    return rec, id2name

def _handle_face_match(name: str, conf: float | None):
    # ปลดล็อกและเปิดค้าง (จนกว่าจะไม่เห็นคนครบ AI_FACE_HOLD_SEC)
    if STATE["door_locked"]:
        STATE["door_locked"] = False
        add_log(name, "FACE_UNLOCK", f"conf={conf if conf is not None else 'N/A'}")
        _send_telegram_message(
            f"🔓 <b>Door Unlocked</b>\nMethod: Face Recognition\nBy: {name}\n"
            f"Confidence: {conf if conf is not None else 'N/A'}\nTime: {_now_hms()}"
        )
        servo_for_state(False)  # 👉 เปิดค้าง

class _PiCam2Reader:
    def __init__(self, w=640, h=480):
        # เติมพาธ system dist-packages เฉพาะตอน import picamera2
        import os, sys, site
        for p in (
            "/usr/lib/python3/dist-packages",
            f"/usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/dist-packages",
            "/usr/local/lib/python3/dist-packages",
        ):
            if os.path.isdir(p) and p not in sys.path:
                site.addsitedir(p)

        from picamera2 import Picamera2
        self.picam2 = Picamera2()
        cfg = self.picam2.create_video_configuration(
            main={"size": (w, h), "format": "RGB888"}
        )
        self.picam2.configure(cfg)
        self.picam2.start()
        time.sleep(0.3)

    def read(self):
        rgb = self.picam2.capture_array()
        return True, cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)

    def release(self):
        try:
            self.picam2.stop()
        except:
            pass


class _CV2Reader:
    def __init__(self, src, w=640, h=480):
        self.cap = cv2.VideoCapture(src, cv2.CAP_V4L2)
        if not self.cap.isOpened():
            raise RuntimeError(f"เปิดกล้องไม่ได้: {src}")
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, w)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, h)
    def read(self):
        return self.cap.read()
    def release(self):
        try: self.cap.release()
        except: pass

def _build_reader(src):
    s = str(src).lower()
    # ถ้าขอ picam ให้พยายามใช้ Picamera2 แต่ถ้าล้มให้ fallback ไป USB 0
    if s in ("picam", "picamera", "picamera2"):
        try:
            return _PiCam2Reader()
        except Exception as e:
            print(f"[AI][WARN] Picamera2 failed: {e}; fallback to /dev/video0")
            return _CV2Reader(0)

    # กรณีอื่น ๆ: ถ้ามี picamera2 ติดตั้งและ src เป็นค่า default ก็ใช้ picamera2
    try:
        import importlib; importlib.import_module("picamera2")
        if s in ("0", "", "default"):
            try:
                return _PiCam2Reader()
            except Exception as e:
                print(f"[AI][WARN] Picamera2 failed: {e}; fallback to {s or 0}")
    except Exception:
        pass

    try:
        src2 = int(src)
    except Exception:
        src2 = src
    return _CV2Reader(src2)


class AICamWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.stop_evt = threading.Event()
        self.det = _build_cascade()
        self.rec, self.id2name = _load_lbph()
        self.votes = collections.deque(maxlen=AI_VOTE_LEN)
        try:
            self.rec.setThreshold(AI_CONF_THR)
        except Exception:
            pass
        self.cam = _build_reader(AI_CAM_SRC)

        # 👉 ตัวใหม่
        self.hold_sec = AI_FACE_HOLD_SEC
        self.opened_by_face = False
        self.last_seen_auth = 0.0
        self.last_name = None
        self.last_conf = None


    def stop(self):
        self.stop_evt.set()

    def run(self):
        print("[AI] Camera worker started")
        last_name = None
        last_seen = 0.0
        try:
            while not self.stop_evt.is_set():
                ok, bgr = self.cam.read()
                if not ok or bgr is None:
                    time.sleep(0.02); continue

                gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
                faces = self.det.detectMultiScale(gray, 1.1, 5, minSize=(80,80))
                box = None
                if len(faces):
                    x,y,w,h = max(faces, key=lambda f: f[2]*f[3])
                    H,W = gray.shape[:2]
                    mx,my = int(0.1*w), int(0.15*h)
                    x1,y1 = max(0,x-mx), max(0,y-my)
                    x2,y2 = min(W,x+w+mx), min(H,y+h+my)
                    box = (x1,y1,x2,y2)

                pred = "NULL"; conf_val = None
                if box:
                    x1,y1,x2,y2 = box
                    roi = gray[y1:y2, x1:x2]
                    roi = cv2.equalizeHist(roi)
                    roi = cv2.resize(roi, AI_FACE_SIZE)
                    label_id, conf = self.rec.predict(roi)
                    name = self.id2name.get(int(label_id), "UNKNOWN")
                    conf_val = float(conf)
                    if conf < AI_CONF_THR:
                        pred = name

                self.votes.append(pred if box else "NULL")
                final = max(set(self.votes), key=self.votes.count) if len(self.votes)==self.votes.maxlen else None

                now = time.time()
                name_to_unlock = final if final and final != "NULL" else (pred if pred != "NULL" else None)

                if name_to_unlock:
                    # เห็นหน้าถูกต้อง → ต่ออายุเวลา & เปิดค้างถ้ายังไม่เปิด
                    self.last_seen_auth = now
                    self.last_name = name_to_unlock
                    self.last_conf = conf_val
                    if not self.opened_by_face:
                        _handle_face_match(self.last_name, self.last_conf)
                        self.opened_by_face = True
                else:
                    # ไม่เห็นหน้าถูกต้อง → ถ้าเปิดค้างอยู่ และหายเกิน hold_sec ให้ล็อกกลับ
                    if self.opened_by_face and (now - self.last_seen_auth) >= self.hold_sec:
                        STATE["door_locked"] = True
                        idle_s = now - self.last_seen_auth
                        who = self.last_name or "system"
                        add_log(who, "FACE_RELOCK", f"idle {idle_s:.1f}s")
                        _send_telegram_message(
                            f"🔐 <b>Door Locked</b>\nMethod: Face hold timeout ({int(self.hold_sec)}s)\nTime: {_now_hms()}"
                        )
                        servo_for_state(True)
                        self.opened_by_face = False
                        self.last_name = None
                        self.last_conf = None

                if AI_SHOW_GUI:
                    draw = bgr.copy()
                    if box:
                        x1,y1,x2,y2 = box
                        cv2.rectangle(draw,(x1,y1),(x2,y2),(0,255,0),2)
                        cv2.putText(draw, f"{pred if pred!='NULL' else 'FACE'} ({conf_val:.1f if conf_val is not None else 'NA'})",
                                    (x1,max(0,y1-8)), cv2.FONT_HERSHEY_SIMPLEX,0.7,(0,255,0),2)
                    if final:
                        cv2.putText(draw, f"VOTE: {final}", (10,25), cv2.FONT_HERSHEY_SIMPLEX,0.9,(255,255,255),2)
                    cv2.imshow("AI Cam (LBPH)", draw)
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        break
        finally:
            try: self.cam.release()
            except: pass
            try: cv2.destroyAllWindows()
            except: pass
            print("[AI] Camera worker stopped")

def _start_ai_worker():
    global AI
    if AI and AI.is_alive():
        return False
    AI = AICamWorker()
    AI.start()
    return True

def _stop_ai_worker():
    global AI
    if AI and AI.is_alive():
        AI.stop()
        AI.join(timeout=3)
        AI = None
        return True
    return False

@app.post("/ai/start")
def ai_start():
    if cv2 is None:
        raise HTTPException(500, detail="OpenCV ไม่พร้อม (ไม่มี cv2)")
    try:
        ok = _start_ai_worker()
    except Exception as e:
        add_log("system", "AI_START_FAIL", str(e))
        raise HTTPException(500, detail=f"AI start failed: {e}")
    return {
        "running": ok or (AI is not None and AI.is_alive()),
        "conf_thr": AI_CONF_THR, "vote_len": AI_VOTE_LEN, "src": AI_CAM_SRC
    }

@app.post("/ai/stop")
def ai_stop():
    ok = _stop_ai_worker()
    return {"stopped": ok}

@app.get("/ai/status")
def ai_status():
    return {"running": (AI is not None and AI.is_alive()),
            "src": AI_CAM_SRC, "conf_thr": AI_CONF_THR, "vote_len": AI_VOTE_LEN}

# autostart เมื่อเซิร์ฟเวอร์บูต (ตั้ง AI_CAM_AUTOSTART=1 เพื่อเปิด)
@app.on_event("startup")
def _ai_autostart():
    if os.getenv("AI_CAM_AUTOSTART","0") == "1":
        try:
            _start_ai_worker()
            add_log("system","AI_START","autostart")
        except Exception as e:
            add_log("system","AI_START_FAIL",str(e))