# -*- coding: utf-8 -*-
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()
for t in ["FlySky", "E_N4", "E_4", "\\E_", "krnln", ".fne", ".fnr", "%temp%", "%TEMP%",
          "GetTempPath", "Software\\FlySky", "Install", "已安装", "独立编译", "静态编译",
          "eAPI", "spec.fne", "krnln.fne", "eyuyan", "eyuyan.com", "www.dywt", "易语言支持库",
          "EPL", "E语言"]:
    b = t.encode("gbk")
    idx = []
    st = 0
    while True:
        i = raw.find(b, st)
        if i < 0: break
        idx.append(i); st = i + 1
        if len(idx) >= 6: break
    print("%-18s %s" % (t, [hex(i) for i in idx]))
print()
# 看 0x990d5 入口的前后汇编
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== EP 0x990d5 disasm ===")
ep = 0x990d5
for ins in md.disasm(raw[ep:ep+120], 0x400000 + ep):
    print("  0x%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
