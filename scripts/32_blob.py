# -*- coding: utf-8 -*-
import math, collections, re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

def H(b):
    if not b: return 0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

print("=== 4KB 熵扫描 0x1c0000-0x2c0000 ===")
prev = None
for off in range(0x1c0000, 0x2c0000, 0x1000):
    h = H(raw[off:off+0x1000])
    tag = "HIGH" if h > 7.9 else ""
    if tag != prev:
        print("  %08x H=%.2f %s" % (off, h, tag))
        prev = tag
print("首 64 字节 @0x1d0000:", raw[0x1d0000:0x1d0040].hex(" "))
print("首 64 字节 @0x1e0000:", raw[0x1e0000:0x1e0040].hex(" "))
print("末尾 @0x2aff00:", raw[0x2aff00:0x2aff40].hex(" "))

print("\n=== 内嵌 PE / DOS 头 搜索 ===")
for b in [b"This program cannot be run in DOS mode", b"MZ", b"PE\x00\x00"]:
    idx, st = [], 0
    while True:
        i = raw.find(b, st)
        if i < 0: break
        idx.append(i); st = i+1
        if len(idx) > 30: break
    print("  %-40s count=%d first=%s" % (b[:30], len(idx), [hex(x) for x in idx[:8]]))

print("\n=== 压缩头特征 ===")
for name, sig in [("zlib 78 9C", b"\x78\x9c"), ("zlib 78 DA", b"\x78\xda"),
                  ("gzip 1F8B", b"\x1f\x8b\x08"), ("LZMA 5D0000", b"\x5d\x00\x00"),
                  ("RAR", b"Rar!"), ("7z", b"7z\xbc\xaf"), ("PK", b"PK\x03\x04")]:
    idx, st = [], 0
    while True:
        i = raw.find(sig, st)
        if i < 0: break
        idx.append(i); st = i+1
        if len(idx) > 6: break
    print("  %-14s %s" % (name, [hex(x) for x in idx]))

print("\n=== 0x3041f0 附近（Software\\ 上下文） ===")
print(raw[0x3041e0:0x304280].decode("gbk", "replace").replace("\x00","\\0"))
