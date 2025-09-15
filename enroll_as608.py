#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pyfingerprint.pyfingerprint import PyFingerprint
import time

PORT = '/dev/serial0'
BAUD = 57600

def wait_finger(f, msg="วางนิ้ว"):
    print(msg)
    while not f.readImage():
        time.sleep(0.05)
    print("อ่านภาพสำเร็จ")

def main():
    try:
        f = PyFingerprint(PORT, BAUD, 0xFFFFFFFF, 0x00000000)
        if not f.verifyPassword():
            raise Exception('verifyPassword failed')
    except Exception as e:
        print('เชื่อมต่อเซ็นเซอร์ไม่ได้:', e)
        return

    try:
        print('จำนวน template ก่อนบันทึก:', f.getTemplateCount())
        # ขั้นที่ 1: วางนิ้วครั้งที่ 1
        wait_finger(f, "วางนิ้วครั้งที่ 1")
        f.convertImage(0x01)

        # ตรวจว่ามีอยู่แล้วไหม
        result = f.searchTemplate()
        if result[0] >= 0:
            print(f'ลายนิ้วมือนี้มีอยู่แล้วที่ตำแหน่ง #{result[0]}')
            return

        # ยกนิ้วออก
        print('ยกนิ้วออก...')
        while f.readImage():
            time.sleep(0.05)

        # ขั้นที่ 2: วางนิ้วครั้งที่ 2
        wait_finger(f, "วางนิ้วครั้งที่ 2 (ให้วางเหมือนเดิม)")
        f.convertImage(0x02)

        # สร้าง model จาก buffer1 + buffer2
        if f.compareCharacteristics() == 0:
            raise Exception('สองภาพไม่ตรงกัน ลองใหม่')

        f.createTemplate()
        position = f.storeTemplate()
        print(f'บันทึกสำเร็จที่ตำแหน่ง #{position} ✅')

    except Exception as e:
        print('ผิดพลาด:', e)

if __name__ == '__main__':
    main()
