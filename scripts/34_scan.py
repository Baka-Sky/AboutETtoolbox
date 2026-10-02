# -*- coding: utf-8 -*-
import struct, re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

print("=== 严格扫描内嵌 PE (MZ + 有效 e_lfanew + PE\\0\\0) ===")
found = []
pos = 0
while True:
    i = raw.find(b"MZ", pos)
    if i < 0: break
    pos = i + 1
    if i + 0x40 > len(raw): continue
    lf = struct.unpack_from("<I", raw, i + 0x3C)[0]
    if 0x40 <= lf <= 0x1000 and i + lf + 4 <= len(raw) and raw[i+lf:i+lf+4] == b"PE\x00\x00":
        found.append(i)
        machine, nsec = struct.unpack_from("<HH", raw, i + lf + 4)
        print("  有效内嵌PE @ %08x machine=%04x sections=%d" % (i, machine, nsec))
if not found:
    print("  未发现有效内嵌 PE —— 干净")

print("\n=== 程序声明的 DLL 命令（0xba8d0-0xba9a0） ===")
seg = raw[0xba8c0:0xbaa00]
for m in re.finditer(rb"[\x20-\x7e\x81-\xfe]{3,}", seg):
    print("   %08x %s" % (0xba8c0 + m.start(), m.group().decode("gbk", "replace")))

print("\n=== 所有 'SOFTWARE\\'/注册表路径常量 ===")
for m in re.finditer(rb"(?:SOFTWARE|Software|System|HKEY)[\x20-\x7e\x81-\xfe]{0,90}", raw):
    t = m.group().decode("gbk", "replace")
    print("   %08x %s" % (m.start(), t))

print("\n=== 所有 http(s) 链接 ===")
for m in re.finditer(rb"https?://[\x21-\x7e]+", raw):
    print("   %08x %s" % (m.start(), m.group().decode("latin1")))
