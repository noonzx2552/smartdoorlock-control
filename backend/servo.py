import time, pigpio

SERVO = 12  # เปลี่ยนได้ตาม GPIO ที่ใช้
MIN_US = 500    # ~0°
MID_US = 1500   # ~90°
MAX_US = 2500   # ~180°  (ปรับตามจริงได้)

pi = pigpio.pi()
if not pi.connected:
    raise SystemExit("pigpio daemon ไม่ได้รัน")

def write_angle(angle):
    angle = max(0, min(180, angle))
    us = int(MIN_US + (MAX_US - MIN_US) * (angle / 180.0))
    pi.set_servo_pulsewidth(SERVO, us)

try:
    # ทดสอบขยับ
    for a in [0, 90, 180, 90]:
        write_angle(a)
        time.sleep(0.6)

    # สแกนไป-กลับ
    for a in range(0, 181, 5):
        write_angle(a); time.sleep(0.02)
    for a in range(180, -1, -5):
        write_angle(a); time.sleep(0.02)

finally:
    pi.set_servo_pulsewidth(SERVO, 0)  # ปล่อยสัญญาณ
    pi.stop()
