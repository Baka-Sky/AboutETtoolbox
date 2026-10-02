# -*- coding: utf-8 -*-
"""聚焦 .rdata/.data 的字符串与结构，判断是否为易格式(E-format)程序"""
import pefile, re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()

def sec(name):
    for s in pe.sections:
        if s.Name.rstrip(b"\0").decode("latin1") == name:
            return s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData
    return 0, 0

# 收集 .rdata 起点的可打印/中文串
for sn in (".rdata", ".data"):
    a, b = sec(sn)
    blob = raw[a:b]
    print("========== %s  0x%x-0x%x ==========" % (sn, a, b))
    out = []
    for m in re.finditer(rb"(?:[\x81-\xfe][\x40-\xfe]|[\x20-\x7e]){4,}", blob):
        s = m.group()
        try:
            t = s.decode("gbk")
        except Exception:
            continue
        # 保留含中文的、或看起来像标识符/路径的 ASCII
        has_cjk = bool(re.search(r"[\u4e00-\u9fff]", t))
        printable = sum(1 for c in t if 32 <= ord(c) < 127 or re.match(r"[\u4e00-\u9fff]", c))
        if has_cjk and len(t) >= 3 and printable / len(t) > 0.8:
            out.append((a + m.start(), t.strip()))
    # 去重
    seen = set(); uniq = []
    for off, t in out:
        if t not in seen:
            seen.add(t); uniq.append((off, t))
    print("unique GBK/中文串:", len(uniq))
    for off, t in uniq[:250]:
        print("  %08x %s" % (off, t[:110]))
