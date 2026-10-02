# -*- coding: utf-8 -*-
import pefile, math, re, collections
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()

def H(b):
    if not b: return 0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

print("=== windowed entropy (64KB) ===")
W = 65536
for off in range(0, len(raw), W):
    chunk = raw[off:off+W]
    print(" %08x  H=%.2f  %s" % (off, H(chunk), ("HIGH " if H(chunk) > 7.5 else "")))

print("\n=== UTF-16LE 中文串 (>=4 chars) ===")
seen = []
for m in re.finditer(rb"(?:[\x00-\xff][\x4e-\x9f]){4,}", raw):
    try:
        t = m.group().decode("utf-16-le")
    except Exception:
        continue
    if re.search(r"[\u4e00-\u9fff]{3,}", t):
        seen.append((m.start(), t))
print("count", len(seen))
for off, t in seen[:60]:
    print("  %08x %s" % (off, t[:80]))

print("\n=== 关键签名 ===")
for name, pat in {
    "UTF16 易语言": "易语言".encode("utf-16-le"),
    "UTF16 支持库": "支持库".encode("utf-16-le"),
    "GBK 易语言": "易语言".encode("gbk"),
    "GBK 窗口": "窗口".encode("gbk"),
    "GBK 组件": "组件".encode("gbk"),
    "GBK 常量": "常量".encode("gbk"),
    "GBK 程序集": "程序集".encode("gbk"),
    "GBK 模块": "模块".encode("gbk"),
    "KRNLN.fnr": b"KRNLN",
    "krnln": b"krnln",
    "EYUYAN": b"EYUYAN",
}.items():
    idx = [hex(i) for i in range(len(raw)) if raw.startswith(pat, i)][:8]
    print(" %-14s %s" % (name, idx))
