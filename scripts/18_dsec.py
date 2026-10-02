# -*- coding: utf-8 -*-
import re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()
print("=== ASCII strings in .data 0x30d000-0x311200 ===")
seg = raw[0x30d000:0x311200]
for m in re.finditer(rb"[\x20-\x7e]{4,}", seg):
    print("  %08x %s" % (0x30d000 + m.start(), m.group().decode("latin1")[:90]))
