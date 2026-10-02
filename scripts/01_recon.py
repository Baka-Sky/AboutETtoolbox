# -*- coding: utf-8 -*-
"""基础 PE 侦察：区段/导入表/资源/易语言特征"""
import pefile, sys, struct

PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\万物工具箱.exe"
pe = pefile.PE(PATH, fast_load=False)

print("=" * 70)
print("FILE:", PATH)
print("Machine:", hex(pe.FILE_HEADER.Machine))
print("TimeDateStamp:", hex(pe.FILE_HEADER.TimeDateStamp))
print("Characteristics:", hex(pe.FILE_HEADER.Characteristics))
print("Subsystem:", pe.OPTIONAL_HEADER.Subsystem)
print("ImageBase:", hex(pe.OPTIONAL_HEADER.ImageBase))
print("EntryPoint(RVA):", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print("SizeOfImage:", hex(pe.OPTIONAL_HEADER.SizeOfImage))
print("Sections:", pe.FILE_HEADER.NumberOfSections)

print("=" * 70)
print("SECTIONS")
for s in pe.sections:
    print(" %-10s VA=%08x VS=%08x RAW=%08x RS=%08x Flags=%08x  entropy=%.2f" % (
        s.Name.rstrip(b"\x00").decode("latin1"), s.VirtualAddress, s.Misc_VirtualSize,
        s.PointerToRawData, s.SizeOfRawData, s.Characteristics, s.get_entropy()))

print("=" * 70)
print("IMPORTS")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        print(" [%s]" % dll.dll.decode("latin1"))
        names = []
        for imp in dll.imports:
            if imp.name:
                names.append(imp.name.decode("latin1"))
            else:
                names.append("ord#%d" % imp.ordinal)
        print("   ", ", ".join(names[:60]))
        if len(names) > 60:
            print("    ... (+%d)" % (len(names) - 60))
else:
    print(" no imports")

print("=" * 70)
print("RESOURCES")
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = t.name if t.name else pefile.RESOURCE_TYPE.get(t.struct.Id, t.struct.Id)
        print(" Type:", tname)
        for rid in t.directory.entries:
            for lang in rid.directory.entries:
                d = lang.data.struct
                print("    id=%s lang=%s offset=%08x size=%d" % (
                    rid.id, lang.id, d.OffsetToData, d.Size))
else:
    print(" no resources")

print("=" * 70)
print("EXPORTS")
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
    print(" Export DLL name:", pe.DIRECTORY_ENTRY_EXPORT.name)
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print("   ", e.ordinal, e.name, hex(e.address))
else:
    print(" no exports")

# 段表之外：搜索易语言签名字符串
raw = open(PATH, "rb").read()
for sig in [b"krnln", b"KRNLN", b"e\0l\0a\0n\0g", b"ELang", b"\xd0\xd2\xd3\xef\xd1\xd4",
            b"35ef", b"ECODE", b".ecode", b"ExuiKrnln", b"LIBRARY", b"\\\xd6\xa7\xb3\xd6\xbf\xe2"]:
    idx = raw.find(sig)
    print("SIG %-20r first_off=%s count=%d" % (sig, hex(idx) if idx >= 0 else None,
          raw.count(sig)))
