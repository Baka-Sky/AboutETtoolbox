# -*- coding: utf-8 -*-
import re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

def show(name, b, limit=8, ctx=100):
    out, st = [], 0
    while True:
        i = raw.find(b, st)
        if i < 0: break
        out.append(i); st = i + 1
        if len(out) >= limit: break
    if out:
        print("%-16s %s" % (name, [hex(x) for x in out]))
        for x in out[:limit]:
            print("      ", raw[x-24:x+ctx].decode("gbk", "replace").replace("\x00", "\\0"))

print("############ 注册表（正确写法） ############")
for n, b in [("Software\\", b"Software\\"), ("SOFTWARE\\", b"SOFTWARE\\"),
             ("HKEY_", b"HKEY_"), ("CurrentVersion", b"CurrentVersion"),
             ("\\Run", b"\\Run"), ("RunOnce", b"RunOnce"), ("Classes\\", b"Classes\\"),
             ("Microsoft\\", b"Microsoft\\"), ("Explorer\\", b"Explorer\\"),
             ("\\Environment", b"\\Environment"), ("Winlogon", b"Winlogon"),
             ("\\Shell\\", b"\\Shell\\"), ("\\Services", b"\\Services"),
             ("FlySky", b"FlySky")]:
    show(n, b, 4)

print("\n############ URL / 更新 ############")
for b in [b"http", b"https", b"update", b"\xb8\xfc\xd0\xc2"]:
    show(b.decode("latin1"), b, 6)

print("\n############ 0xc0100-0xc0700 常量区（URL/群号/更新） ############")
for m in re.finditer(rb"[\x20-\x7e\x81-\xfe]{5,}", raw[0xc0000:0xc0750]):
    try:
        t = m.group().decode("gbk")
    except Exception:
        continue
    print("  %08x %s" % (0xc0000 + m.start(), t[:160]))
