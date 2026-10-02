# -*- coding: utf-8 -*-
import pefile, struct
from capstone import *
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()
IB = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

def at_va(va, n=160):
    off = va - IB
    return raw[off:off+n]

for va in (0x6f92dc, 0x6f92a0, 0x4b4e00):
    d = at_va(va, 100)
    print("VA %08x: %r" % (va, d))
    print("   GBK:", d.split(b"\x00")[0].decode("gbk", "replace"))

print("\n=== 0x2f9200-0x2f9400 字符串区 ===")
import re
seg = raw[0x2f9200:0x2f9400]
for m in re.finditer(rb"[\x20-\x7e\x81-\xfe]{3,}", seg):
    print("   %08x %s" % (0x2f9200 + m.start(), m.group().decode("gbk", "replace")))

print("\n=== SetWindowsHookExA / CreateProcess / WinExec / ShellExecute 上下文 ===")
for name, off in [("SetWindowsHookExA@0xac588", 0xac588), ("SetWindowsHookExA@0xaf428", 0xaf428),
                  ("CreateProcessA@0x19629", 0x19629), ("WinExec@0x22907", 0x22907),
                  ("ShellExecuteA@0x2281a", 0x2281a)]:
    print("### %s" % name)
    # 附近字符串
    for p in range(off - 0x100, off + 0x40):
        if 0xba000 <= p < 0x303218:
            v = struct.unpack_from("<I", raw, p)[0] - IB
            if 0xba000 <= v < 0x303218:
                e = raw.find(b"\x00", v)
                if 0 < e - v <= 120:
                    try:
                        s = raw[v:e].decode("gbk")
                    except Exception:
                        continue
                    if s.strip():
                        print("   str@%08x VA=%08x : %s" % (p, v + IB, s[:80]))
    st = max(0x1000, off - 0x30)
    for ins in md.disasm(raw[st:off + 0x14], IB + st):
        print("   %08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    print()
