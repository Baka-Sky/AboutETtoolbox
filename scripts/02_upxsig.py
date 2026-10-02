# -*- coding: utf-8 -*-
raw = open(r"c:\Users\jh_JL\Desktop\CKTOOLBOX\万物工具箱.exe", "rb").read()
sigs = [b"UPX!", b"UPX ", b"Info", b"NRV2B", b"NRV2D", b"NRV2E", b"NRV2B", b"LZMA", b"upx"]
for s in sigs:
    i = raw.find(s)
    print("%-8s count=%-4d first=%s" % (s, raw.count(s), hex(i) if i >= 0 else None))
i = raw.find(b"UPX!")
if i >= 0:
    print("stub head:", raw[i - 16:i + 80])
# UPX version string in stub tail
print("tail:", raw[-256:])
