# -*- coding: utf-8 -*-
import pefile
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

def hd(off, n, label=""):
    print("=== %s @ %08x ===" % (label, off))
    for r in range(0, n, 16):
        chunk = raw[off+r:off+r+16]
        hexs = " ".join("%02x" % b for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else ("." if b < 128 else "?") for b in chunk)
        try:
            g = chunk.decode("gbk", "replace").replace("\n", " ")
        except Exception:
            g = ""
        print(" %08x  %-47s  %s" % (off+r, hexs, g))
    print()

hd(0xbe820, 256, "程序字符串起点前")
hd(0xba800, 320, "支持库/dll 名称区")
hd(0xc1200, 256, "字符串区尾部")
hd(0xc2e00, 256, "加密块起始附近")
