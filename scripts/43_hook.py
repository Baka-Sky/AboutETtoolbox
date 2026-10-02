# -*- coding: utf-8 -*-
import pefile, struct
from capstone import *
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()
IB = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)

# IAT 地址 -> 名称
addr2name = {}
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in dll.imports:
        addr2name[imp.address] = (imp.name or b"").decode("latin1") or ("ord#%d" % imp.ordinal)

for a in (0x4ba29c, 0x4ba2bc, 0x4ba34c, 0x4ba40c, 0x4ba65c, 0x4ba004, 0x4ba010):
    print("IAT %08x = %s" % (a, addr2name.get(a, "?")))

print("\nstring @VA 0x707d00 =", repr(raw[0x307d00:0x307d40].split(b"\x00")[0].decode("gbk","replace")))

print("\n=== WinExec 调用点（对齐重反汇编） ===")
for ins in md.disasm(raw[0x228e0:0x22920], IB + 0x228e0):
    print("   %08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

print("\n=== ShellExecuteA 调用点（从函数头） ===")
for ins in md.disasm(raw[0x227c0:0x22830], IB + 0x227c0):
    print("   %08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

print("\n=== SetWindowsHookExA 两处（对齐） ===")
for base in (0xac540, 0xaf400):
    print(" -- @%x --" % base)
    for ins in md.disasm(raw[base:base+0x60], IB + base):
        print("   %08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
