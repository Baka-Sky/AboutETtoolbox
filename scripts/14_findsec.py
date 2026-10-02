# -*- coding: utf-8 -*-
import pefile
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()
print("Sections & characteristics:")
for s in pe.sections:
    print("  %-8s VA=%08x VS=%08x RAW=%08x RS=%08x Char=%08x" % (
        s.Name.rstrip(b'\0').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
        s.PointerToRawData, s.SizeOfRawData, s.Characteristics))

for tok in [b"const", b"form", b"code", b"var", b"helpfunc", b"appinfo", b"dllcmd",
            b"resource", b"start", b"info", b"data", b"begin", b"WinForm", b"@const",
            b"form_"] + [t.encode("gbk") for t in ["全局", "常量段", "窗体", "辅助", "代码段"]]:
    idx = []
    st = 0
    while True:
        i = raw.find(tok, st)
        if i < 0: break
        idx.append(i); st = i+1
        if len(idx) >= 10: break
    print("%-10s %s" % (tok.decode('gbk','replace'), [hex(i) for i in idx]))
