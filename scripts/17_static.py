# -*- coding: utf-8 -*-
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()
print("=== 0x3086a0-0x308720 (含 静态编译) ===")
print(repr(raw[0x3086a0:0x308720]))
print(raw[0x3086a0:0x308720].decode("gbk", "replace"))
print("\n=== 0x307a00-0x308900 GBK ===")
seg = raw[0x307a00:0x308900]
# 提取可读串
import re
for m in re.finditer(rb"(?:[\x81-\xfe][\x40-\xfe]|[\x20-\x7e]){3,}", seg):
    s = m.group()
    try:
        t = s.decode("gbk")
    except Exception:
        continue
    if re.search(r"[\u4e00-\u9fff]", t):
        print("  %08x %s" % (0x307a00 + m.start(), t[:100]))
