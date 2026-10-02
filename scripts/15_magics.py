# -*- coding: utf-8 -*-
import struct
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

for name, v in [("kMagicEncryptedSource", 1162630231),
                ("kMagicFileHeader1(CNWT)", 1415007811),
                ("kMagicFileHeader2(EPRG)", 1196576837),
                ("kMagicSection", 353465113),
                ("kSectionFolder", 0x0E007319)]:
    b = struct.pack("<I", v)
    idx = []
    st = 0
    while True:
        i = raw.find(b, st)
        if i < 0: break
        idx.append(i); st = i + 1
        if len(idx) > 10: break
    print("%-26s 0x%08x %-10s -> %s" % (name, v, b, [hex(i) for i in idx]))
print()
print("kMagicSection bytes:", struct.pack("<I", 353465113),
      "| kSectionFolder:", struct.pack("<I", 0x0E007319))
# 也搜索 ASCII "CNWTEPRG"
print("CNWTEPRG:", hex(raw.find(b"CNWTEPRG")))
print("EPRG:", [hex(i) for i in [raw.find(b"EPRG")]])
# 在 0xc1000-0xc1700 找 4 字节 magic 可能值
import collections
print("\n0xc1240-0xc1320:")
print(raw[0xc1240:0xc1320].hex(" "))
