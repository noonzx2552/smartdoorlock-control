#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pyfingerprint.pyfingerprint import PyFingerprint
import time

PORT = '/dev/serial0'   # ใช้พอร์ต UART หลักของ Pi
BAUD = 57600            # ค่าเริ่มต้นของ AS608

def wait_finger(f):
    """รอจนกว่าจะได้ภาพนิ้ว (อ่านสำเร็จ)"""
    print("วางนิ้วบนเซ็นเซอร์...")
    while not f.readImage():
        time.sleep(0.05)
    print("อ่านภาพสำเร็จ")

def main():
    try:
        f = PyFingerprint(PORT, BAUD, 0xFFFFFFFF, 0x00000000)

        if not f.verifyPassword():
            raise Exception('รหัสผ่านไม่ถูกต้อง (verifyPassword false)')

    except Exception as e:
        print('ไม่สามารถเชื่อมต่อเซ็นเซอร์ได้:')
        print('> ', e)
        print('ตรวจ: สาย TX/RX, พอร์ต /dev/serial0, raspi-config, ไฟ 5V, GND ร่วม')
        return

    print('เชื่อมต่อสำเร็จ ✅')
    print('Library size  :', f.getStorageCapacity())
    print('Template count:', f.getTemplateCount())

    try:
        # 1) รอวางนิ้ว
        wait_finger(f)

        # 2) แปลงภาพเป็นลายนิ้วมือ
        f.convertImage(0x01)

        # 3) ลองค้นหาในฐานข้อมูลของเซ็นเซอร์
        result = f.searchTemplate()
        position_number = result[0]
        accuracy_score = result[1]

        if position_number >= 0:
            print(f'พบลายนิ้วมือที่ตำแหน่ง #{position_number} (score={accuracy_score}) 🎉')
        else:
            print('ไม่พบในฐานข้อมูล (position = -1) ❌')

        # 4) รอปลายนิ้วออก (ป้องกันอ่านซ้ำ)
        print('ยกนิ้วออก...')
        while f.readImage():
            time.sleep(0.05)

    except Exception as e:
        print('เกิดข้อผิดพลาด:')
        print('> ', e)

if __name__ == '__main__':
    main()
