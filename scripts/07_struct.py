# -*- coding: utf-8 -*-
import pefile, re, struct
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()

def sec_data(name):
    for s in pe.sections:
        if s.Name.rstrip(b"\0").decode("latin1") == name:
            return raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
    return b""

print("=== .rdata first 512 ===")
print(repr(sec_data(".rdata")[:512]))
print("=== .data first 512 ===")
print(repr(sec_data(".data")[:512]))
print("=== .text first 256 (entry area) ===")
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print("EP RVA", hex(ep))
print(repr(raw[ep:ep+256]))

# 正确的资源解析
print("\n=== RESOURCES (via pefile offsets) ===")
def dump_res(tid=None, rid=None, maxn=1):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tn = pefile.RESOURCE_TYPE.get(t.struct.Id, None)
        if tid is not None and t.struct.Id != tid:
            continue
        for r in t.directory.entries:
            if rid is not None and r.id != rid:
                continue
            for l in r.directory.entries[:maxn]:
                d = l.data.struct
                off = d.OffsetToData  # pefile: for ADDRESS mode gives offset? convert
                # pefile resource OffsetToData is RVA in some modes; use get_offset_from_rva
                try:
                    fo = pe.get_offset_from_rva(d.OffsetToData)
                except Exception:
                    fo = d.OffsetToData
                data = raw[fo:fo+d.Size]
                print("--- type=%s id=%s size=%d off=%x ---" % (tn, r.id, d.Size, fo))
                return data
    return None

v = dump_res(16, 1)  # RT_VERSION
if v:
    try:
        print(v.decode("utf-16-le", "replace"))
    except Exception:
        print(repr(v))
m = dump_res(24, 1)  # RT_MANIFEST
if m:
    print("--- MANIFEST ---")
    print(m.decode("utf-8", "replace")[:1500])

# TEXTINCLUDE
print("--- TEXTINCLUDE texts ---")
for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if pefile.RESOURCE_TYPE.get(t.struct.Id) != "TEXTINCLUDE":
        continue
    for r in t.directory.entries:
        for l in r.directory.entries:
            d = l.data.struct
            fo = pe.get_offset_from_rva(d.OffsetToData)
            print(r.id, repr(raw[fo:fo+d.Size]))
