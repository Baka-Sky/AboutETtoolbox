# -*- coding: utf-8 -*-
import struct
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

mz = 0x7c9ab
e_lfanew = struct.unpack_from("<I", raw, mz + 0x3C)[0]
print("embedded MZ @ %x, e_lfanew=%x -> PE @ %x" % (mz, e_lfanew, mz + e_lfanew))
pe_off = mz + e_lfanew
if raw[pe_off:pe_off+4] == b"PE\x00\x00":
    mach, nsec, tds = struct.unpack_from("<HHI", raw, pe_off + 4)
    print("Machine=%04x Sections=%d TimeDateStamp=%08x" % (mach, nsec, tds))
    opt_size = struct.unpack_from("<H", raw, pe_off + 20)[0]
    print("SizeOfOptionalHeader=%d" % opt_size)
    sec_off = pe_off + 24 + opt_size
    for i in range(min(nsec, 8)):
        b = raw[sec_off + i*40: sec_off + i*40 + 40]
        name = b[:8].rstrip(b"\0")
        vs, va, rs, pr = struct.unpack_from("<IIII", b, 8)
        ch = struct.unpack_from("<I", b, 36)[0]
        print("  %-8s VA=%08x VS=%08x RAW=%08x RS=%08x Char=%08x" % (
            name.decode("latin1"), va, vs, pr, rs, ch))
    # 提取该内嵌 PE 大小：取最大段末
    # 打印其入口点与版本资源线索
    ep = struct.unpack_from("<I", raw, pe_off + 24 + 16)[0]
    print("EntryPoint RVA = %08x" % ep)
else:
    print("不是 PE 头，可能是误报")

print("\n=== 内嵌 PE 附近的字符串 ===")
import re
seg = raw[mz - 0x80: mz + 0x400]
for m in re.finditer(rb"[\x20-\x7e]{5,}", seg):
    print("   %08x %s" % (mz - 0x80 + m.start(), m.group().decode("latin1")))

print("\n=== PNG / JPEG / GIF 头 ===")
for n, s in [("PNG", b"\x89PNG\r\n\x1a\n"), ("JPEG", b"\xff\xd8\xff"), ("GIF", b"GIF8"),
             ("BMP", b"BM"), ("WAVE", b"RIFF"), ("OggS", b"OggS")]:
    idx, st = [], 0
    while True:
        i = raw.find(s, st)
        if i < 0: break
        idx.append(i); st = i+1
        if len(idx) > 12: break
    print("  %-6s %s" % (n, [hex(x) for x in idx[:12]]))
