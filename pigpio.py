#sudo apt update
#sudo apt install -y pigpio python3-pigpio
#sudo systemctl enable --now pigpiod

#python3 servo_pigpio.py            # โหมดกวาด
#python3 servo_pigpio.py 0 90 180   # สั่งไปมุมที่ต้องการ

# servo_pigpio.py
import time, sys
import pigpio

PIN = 12  # ใช้ GPIO18 (BCM)
MIN_US = 500   # ปรับคาลิเบรตได้ 500–600
MAX_US = 2500  # ปรับคาลิเบรตได้ 2300–2500

def angle_to_us(angle, min_us=MIN_US, max_us=MAX_US):
    angle = max(0, min(180, float(angle)))
    return int(min_us + (max_us - min_us) * (angle / 180.0))

def main():
    pi = pigpio.pi()
    if not pi.connected:
        raise RuntimeError("pigpio daemon ไม่ได้รันอยู่ (ลอง sudo systemctl start pigpiod)")

    try:
        if len(sys.argv) > 1:
            # ใช้มุมจากพารามิเตอร์: python3 servo_pigpio.py 0 90 180
            for a in sys.argv[1:]:
                us = angle_to_us(float(a))
                pi.set_servo_pulsewidth(PIN, us)
                print(f"ไปที่ {a}° -> {us} µs")
                time.sleep(0.6)
        else:

            # เดโม: กวาด 0 -> 180 -> 0
            for a in list(range(0, 181, 10)) + list(range(180, -1, -10)):
                us = angle_to_us(a)
                pi.set_servo_pulsewidth(PIN, us)
                print(f"{a}° -> {us} µs")
                time.sleep(0.05)
    finally:
        # ปล่อยสัญญาณ (หยุดถือแรง) แล้วตัดการเชื่อมต่อ
        pi.set_servo_pulsewidth(PIN, 0)
        pi.stop()

if __name__ == "__main__":
    main()