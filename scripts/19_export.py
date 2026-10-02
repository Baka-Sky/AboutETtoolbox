# -*- coding: utf-8 -*-
"""导出资源 + 程序常量/字符串清单"""
import pefile, os, re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
OUT = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\out"
os.makedirs(OUT, exist_ok=True)
os.makedirs(os.path.join(OUT, "resources"), exist_ok=True)
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()

EXT = {"RT_ICON": "ico", "RT_BITMAP": "bmp", "RT_DIALOG": "dlg", "RT_MENU": "menu",
       "RT_STRING": "str", "RT_MANIFEST": "xml", "RT_VERSION": "ver", "RT_CURSOR": "cur",
       "RT_GROUP_ICON": "grpico", "RT_GROUP_CURSOR": "grpcur", "TEXTINCLUDE": "txt"}

manifest = []
for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    tn = pefile.RESOURCE_TYPE.get(t.struct.Id, str(t.struct.Id))
    for r in t.directory.entries:
        for l in r.directory.entries:
            d = l.data.struct
            fo = pe.get_offset_from_rva(d.OffsetToData)
            data = raw[fo:fo + d.Size]
            ext = EXT.get(tn, "bin")
            fn = os.path.join(OUT, "resources", "%s_%s.%s" % (tn, r.id, ext))
            open(fn, "wb").write(data)
            manifest.append(fn)

# 程序字符串（.rdata 常量区 0xbe000-0xc1700）
with open(os.path.join(OUT, "program_constants.txt"), "w", encoding="utf-8") as f:
    for m in re.finditer(rb"[\x20-\x7e\x81-\xfe]+", raw[0xbe000:0xc1700]):
        s = m.group()
        try:
            t = s.decode("gbk")
        except Exception:
            continue
        if len(t) >= 2 and re.search(r"[\u4e00-\u9fff0-9A-Za-z]", t):
            f.write("%08x\t%s\n" % (0xbe000 + m.start(), t))

# 全程序 GBK 串（限 .rdata 与 .data）
with open(os.path.join(OUT, "all_strings.txt"), "w", encoding="utf-8") as f:
    for (a, b) in [(0xba000, 0x304000), (0x304000, 0x340000)]:
        for m in re.finditer(rb"[\x20-\x7e\x81-\xfe]+", raw[a:b]):
            s = m.group()
            try:
                t = s.decode("gbk")
            except Exception:
                continue
            if len(t) >= 4:
                f.write("%08x\t%s\n" % (a + m.start(), t[:200]))

print("resources:", len(manifest))
print("written to", OUT)
for fn in sorted(manifest):
    print("  ", os.path.basename(fn))
