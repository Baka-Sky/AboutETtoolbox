# -*- coding: utf-8 -*-
import pefile
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
print("Machine", hex(pe.FILE_HEADER.Machine), "Sections", pe.FILE_HEADER.NumberOfSections)
print("EP", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase))
print("Linked:", pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
for s in pe.sections:
    print(" %-10s VA=%08x VS=%08x RAW=%08x RS=%08x ent=%.2f" % (
        s.Name.rstrip(b"\x00").decode("latin1"), s.VirtualAddress, s.Misc_VirtualSize,
        s.PointerToRawData, s.SizeOfRawData, s.get_entropy()))
print("--- IMPORTS ---")
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    print("[%s] %d funcs" % (dll.dll.decode("latin1"), len(dll.imports)))
    print("   ", ", ".join((i.name or b"#%d" % i.ordinal).decode("latin1") for i in dll.imports))
print("--- RESOURCES ---")
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = t.name if t.name else pefile.RESOURCE_TYPE.get(t.struct.Id, t.struct.Id)
        ids = [(r.id, l.data.struct.Size) for r in t.directory.entries for l in r.directory.entries]
        print(" ", tname, ":", ids)
