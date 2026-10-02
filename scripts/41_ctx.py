# -*- coding: utf-8 -*-
"""分析敏感 API 调用点上下文：附近引用了哪些字符串"""
import pefile, struct, re
from capstone import *
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()
IB = pe.OPTIONAL_HEADER.ImageBase
RD_A, RD_B = 0xba000, 0x303218   # .rdata
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = False

def cstr(rva):
    e = raw.find(b"\x00", rva)
    if e < 0 or e - rva > 200: return None
    try:
        t = raw[rva:e].decode("gbk")
    except Exception:
        return None
    return t if t else None

def nearby_strings(off, back=0x120, fwd=0x80):
    out = []
    for p in range(off - back, off + fwd, 1):
        if RD_A <= p < RD_B:
            v = struct.unpack_from("<I", raw, p)[0] - IB if p + 4 <= len(raw) else 0
            if RD_A <= v < RD_B:
                s = cstr(v)
                if s and len(s) >= 2:
                    out.append((p, hex(v + IB), s))
    # 去重
    seen, res = set(), []
    for p, va, s in out:
        if s not in seen:
            seen.add(s); res.append((p, va, s))
    return res

sites = {
    "RegCreateKeyExA@0xb4f42": 0xb4f42, "RegCreateKeyExA@0xb4fbe": 0xb4fbe,
    "RegSetValueExA@0xb24f1": 0xb24f1, "RegOpenKeyExA@0xb4f28": 0xb4f28,
    "RegOpenKeyExA@0x1abac": 0x1abac, "RegQueryValueExA@0x1abbe": 0x1abbe,
    "RegQueryValueA@0x22750": 0x22750, "RegQueryValueA@0x7d6b5": 0x7d6b5,
    "SetWindowsHookExA@0xac588": 0xac588, "SetWindowsHookExA@0xaf428": 0xaf428,
    "CreateProcessA@0x19629": 0x19629, "WinExec@0x22907": 0x22907,
    "ShellExecuteA@0x2281a": 0x2281a,
}
for name, off in sites.items():
    print("=" * 74)
    print("### %s" % name)
    print("-- 附近字符串 --")
    for p, va, s in nearby_strings(off)[:12]:
        print("   %08x -> %s  :  %s" % (p, va, s[:90]))
    print("-- 反汇编窗口 --")
    start = max(0x1000, off - 0x40)
    for ins in md.disasm(raw[start:off + 0x18], IB + start):
        mark = "  <== 调用点" if ins.address == IB + off else ""
        print("   %08x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
