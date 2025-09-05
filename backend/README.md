## SmartHome API (FastAPI)

เอกสารนี้อธิบายการใช้งาน API ทั้งหมดที่มีอยู่ใน `app.py` สำหรับระบบ SmartHome

### การรันเซิร์ฟเวอร์ (Development)

จำเป็นต้องมี Python 3.9+ และติดตั้ง dependencies ตามต้องการ (เช่น `fastapi`, `uvicorn`, `passlib[bcrypt]`, `pydantic`, `Pillow`)

```bash
pip install fastapi uvicorn passlib[bcrypt] pydantic pillow

# รันเซิร์ฟเวอร์
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

- ค่าเริ่มต้น PIN ตั้งได้ผ่านตัวแปรแวดล้อม `SMARTLOCK_DEFAULT_PIN` (ค่า default คือ `123456`)
  - ตัวอย่าง (PowerShell):
  ```powershell
  $env:SMARTLOCK_DEFAULT_PIN = "654321"; uvicorn app:app --reload --host 0.0.0.0 --port 8000
  ```

### Base URL

- เมื่อรันตามด้านบน: `http://localhost:8000`

### หมายเหตุทั่วไป

- API เปิดใช้งาน CORS แบบกว้างเพื่อความสะดวกในการทดสอบ (โปรดจำกัด origin ใน production)
- ทุกเวลาถูกเก็บเป็น ISO8601 (UTC)
- มีเส้นทางเว็บสแตติกที่ `GET /web/`

---

## Health

- `GET /health`
  - ตรวจสอบสถานะเซิร์ฟเวอร์
  - ตัวอย่าง:
  ```bash
  curl http://localhost:8000/health
  ```

## Authentication (Demo)

- `POST /login`
  - Body (JSON): `{ "username": "smarthome-user", "password": "password123" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/login \
       -H "Content-Type: application/json" \
       -d '{"username":"smarthome-user","password":"password123"}'
  ```

- `GET /user/{username}`
  - ดึงโปรไฟล์แบบง่ายตามชื่อผู้ใช้
  - ตัวอย่าง: `curl http://localhost:8000/user/admin`

## Door Lock

- `GET /lock/status`
  - ดูสถานะประตูล็อกอยู่หรือไม่
  - ตัวอย่าง: `curl http://localhost:8000/lock/status`

- `POST /lock`
  - Body (JSON): `{ "action": "lock" | "unlock", "who": "optional" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/lock \
       -H "Content-Type: application/json" \
       -d '{"action":"unlock","who":"tester"}'
  ```

## OTP

- `GET /otp/active`
  - ดูรายการ OTP ที่ยังใช้งานอยู่
  - ตัวอย่าง: `curl http://localhost:8000/otp/active`

- `GET /otp/history?limit=200`
  - ดูประวัติ OTP ที่หมดอายุ/สิ้นสุดแล้ว ล่าสุดก่อน
  - ตัวอย่าง: `curl "http://localhost:8000/otp/history?limit=50"`

- `POST /otp`
  - สร้าง OTP ใหม่
  - Body (JSON): `{ "minutes": 5, "uses": 3, "who": "optional", "comment": "optional" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/otp \
       -H "Content-Type: application/json" \
       -d '{"minutes":5,"uses":3,"who":"tester","comment":"delivery"}'
  ```

- `DELETE /otp/{code}`
  - เพิกถอน OTP ที่ยัง active
  - ตัวอย่าง: `curl -X DELETE http://localhost:8000/otp/123456`

- `POST /otp/use`
  - ใช้ OTP 1 ครั้ง
  - Body (JSON): `{ "code": "123456" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/otp/use \
       -H "Content-Type: application/json" \
       -d '{"code":"123456"}'
  ```

- `DELETE /otp/history/clear`
  - ล้างประวัติ OTP ทั้งหมด
  - ตัวอย่าง: `curl -X DELETE http://localhost:8000/otp/history/clear`

## Logs

- `GET /logs`
  - ดูรายการเหตุการณ์ (ล่าสุดก่อน)
  - ตัวอย่าง: `curl http://localhost:8000/logs`

## Fingerprints (Demo)

- `GET /fingerprints`
  - รายการลายนิ้วมือทั้งหมด
  - ตัวอย่าง: `curl http://localhost:8000/fingerprints`

- `POST /fingerprints/enroll`
  - ลงทะเบียนลายนิ้วมือแบบจำลอง
  - Body (JSON): `{ "user": "alice", "finger": "left-index" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/fingerprints/enroll \
       -H "Content-Type: application/json" \
       -d '{"user":"alice","finger":"left-index"}'
  ```

- `DELETE /fingerprints/{fid}`
  - ลบรายการตาม id
  - ตัวอย่าง: `curl -X DELETE http://localhost:8000/fingerprints/<fid>`

## Faces (Demo)

- `GET /faces`
  - รายการใบหน้าทั้งหมด
  - ตัวอย่าง: `curl http://localhost:8000/faces`

- `POST /faces/enroll`
  - ลงทะเบียนใบหน้าแบบจำลอง (รองรับอัปโหลดไฟล์รูปแบบ multipart)
  - ฟอร์มฟิลด์: `user` (จำเป็น), `file` (อาจส่งหรือไม่ส่งก็ได้)
  - ตัวอย่าง (มีไฟล์):
  ```bash
  curl -X POST http://localhost:8000/faces/enroll \
       -F "user=alice" \
       -F "file=@/path/to/photo.jpg"
  ```
  - ตัวอย่าง (ไม่มีไฟล์):
  ```bash
  curl -X POST http://localhost:8000/faces/enroll \
       -F "user=alice"
  ```

- `DELETE /faces/{fid}`
  - ลบรายการตาม id
  - ตัวอย่าง: `curl -X DELETE http://localhost:8000/faces/<fid>`

## UI State

- `GET /ui/state`
  - ดึงสถานะรวมของระบบสำหรับหน้า UI (door/otp/history/logs/fingerprints/faces)
  - ตัวอย่าง: `curl http://localhost:8000/ui/state`

## PIN Unlock

- `GET /pin/info`
  - ดูสถานะ PIN (เช่น ยังเป็นค่า default หรือไม่)
  - ตัวอย่าง: `curl http://localhost:8000/pin/info`

- `POST /pin/verify`
  - ตรวจสอบความถูกต้องของ PIN โดยไม่ปลดล็อกประตู
  - Body (JSON): `{ "pin": "123456" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/pin/verify \
       -H "Content-Type: application/json" \
       -d '{"pin":"123456"}'
  ```

- `POST /pin/unlock`
  - ปลดล็อกประตูด้วย PIN; ถ้า PIN ไม่ถูกต้อง จะลองใช้เป็น OTP อัตโนมัติ
  - Body (JSON): `{ "pin": "123456" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/pin/unlock \
       -H "Content-Type: application/json" \
       -d '{"pin":"123456"}'
  ```

- `POST /pin/set`
  - ตั้ง/เปลี่ยน PIN ความยาว 6 หลัก (ตัวเลขเท่านั้น)
  - สถานะครั้งแรก (PIN default): ไม่ต้องส่ง `current_pin`
  - Body (JSON):
    - ตั้งครั้งแรก: `{ "new_pin": "654321" }`
    - เปลี่ยนครั้งถัดไป: `{ "current_pin": "123456", "new_pin": "654321" }`
  - ตัวอย่าง:
  ```bash
  curl -X POST http://localhost:8000/pin/set \
       -H "Content-Type: application/json" \
       -d '{"new_pin":"654321"}'
  ```

## Camera (Demo)

- `GET /camera/snapshot`
  - รับภาพ JPEG หนึ่งเฟรม (จำลองด้วย Pillow ถ้ามี)
  - ตัวอย่าง: `curl -o snapshot.jpg http://localhost:8000/camera/snapshot`

- `GET /camera/mjpeg`
  - สตรีม MJPEG (multipart/x-mixed-replace)
  - เปิดในเบราว์เซอร์: `http://localhost:8000/camera/mjpeg`

## Static Web

- `GET /web/`
  - ให้บริการไฟล์สแตติกจากโฟลเดอร์ `web` (ถูก mount ที่ `/web`)
  - `GET /` จะ redirect ไปยัง `/web/`
  - `GET /favicon.ico` จะเสิร์ฟไฟล์ `web/favicon.ico` ถ้ามี

---

### ข้อแนะนำสำหรับ Production

- จำกัด CORS origins ให้ปลอดภัย
- จัดการรหัสผ่านผู้ใช้/secret ผ่านตัวแปรแวดล้อมหรือ Secret Manager
- ใช้ HTTPS, Reverse Proxy (เช่น Nginx) และตั้งค่า Timeout/Rate limit ให้เหมาะสม
- เก็บสถานะถาวร (OTP/Logs/Faces/Fingerprints/PIN) ในฐานข้อมูลจริงแทน in-memory


