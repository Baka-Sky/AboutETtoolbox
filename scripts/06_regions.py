# -*- coding: utf-8 -*-
import pefile, struct
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()

def rva2off(rva):
    return pe.get_offset_from_rva(rva)

print("=== VERSION INFO ===")
if hasattr(pe, "FileInfo"):
    import pprint
    def walk(d, ind=0):
        for item in d:
            if isinstance(item, list):
                walk(item, ind + 1)
            elif isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, (list, bytes)):
                        print(" " * ind + str(k), "=", v if not isinstance(v, bytes) else v.decode("utf-8", "replace"))
                    else:
                        print(" " * ind + str(k), "=", v)
    walk(pe.FileInfo)

print("\n=== MANIFEST (RT_MANIFEST) ===")
for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if pefile.RESOURCE_TYPE.get(t.struct.Id) == "RT_MANIFEST":
        for rid in t.directory.entries:
            for lang in rid.directory.entries:
                d = lang.data.struct
                data = raw[d.OffsetToData - pe.OPTIONAL_HEADER.SizeOfHeaders + pe.OPTIONAL_HEADER.SizeOfHeaders: d.OffsetToData + d.Size]
                # OffsetToData in pefile resource is FILE OFFSET
                data = raw[d.OffsetToData: d.OffsetToData + d.Size]
                print(data.decode("utf-8", "replace"))

print("\n=== region around 0xbac89 (支持库) ===")
for off in (0xbac00, 0xbc7d8, 0xbc000):
    print("--- off %08x ---" % off)
    print(repr(raw[off:off + 256]))

print("\n=== region around 0x3086e8 (子程序, .data) ===")
print(repr(raw[0x3086e8 - 128:0x3086e8 + 256]))

print("\n=== region around 0x313901 (ExuiKrnln) ===")
print(repr(raw[0x313901 - 128:0x313901 + 256]))
