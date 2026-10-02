# -*- coding: utf-8 -*-
"""从解包后的 exe 提取字符串与易语言特征"""
import re, collections
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()
print("size", len(raw))

# 1) 特征签名
sigs = {
    "易语言(GBK)": b"\xd2\xd7\xd3\xef\xd1\xd4",
    "krnln": b"krnln", "KRNLN": b"KRNLN",
    "ExuiKrnln": b"ExuiKrnln", "ExUI": b"ExUI",
    "e.fnr": b".fnr", "e.fne": b".fne",
    "支持库(GBK)": b"\xd6\xa7\xb3\xd6\xbf\xe2",
    "窗口(GBK)": b"\xb4\xb0\xbf\xda",
    "子程序(GBK)": b"\xd7\xd3\xb3\xcc\xd0\xf2",
    "E语言标记{": b"\x1b\x1b",
}
for k, v in sigs.items():
    print("SIG %-14s count=%d first=%s" % (k, raw.count(v), hex(raw.find(v)) if raw.find(v) >= 0 else None))

# 2) ASCII 字符串
def ascii_strings(data, mn=5):
    return re.findall(rb"[\x20-\x7e]{%d,}" % mn, data)

# 3) GBK 中文串（连续的双字节 GBK 或与ASCII混合）
def gbk_strings(data, mn=2):
    out = []
    for m in re.finditer(rb"(?:[\x81-\xfe][\x40-\xfe]|[\x20-\x7e]){%d,}" % mn, data):
        s = m.group()
        try:
            t = s.decode("gbk")
        except Exception:
            continue
        if re.search(r"[\u4e00-\u9fff]", t):
            out.append((m.start(), t))
    return out

asc = ascii_strings(raw)
print("\nASCII strings:", len(asc))
cnt = collections.Counter(asc)
for s in list(dict.fromkeys(asc))[:80]:
    print("  ", s[:100])

gb = gbk_strings(raw)
print("\nGBK(含中文) strings:", len(gb))
# 去重
seen = {}
for off, t in gb:
    seen.setdefault(t, off)
print("unique:", len(seen))
for t in list(seen)[:120]:
    print("   %s" % t.replace("\r", "\\r").replace("\n", "\\n")[:120])
