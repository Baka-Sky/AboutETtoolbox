# -*- coding: utf-8 -*-
import re, os
OUT = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\out\resources"
for fn in ["RT_MENU_1039.menu", "RT_MENU_127.menu", "RT_DIALOG_1084.dlg",
           "RT_DIALOG_30722.dlg", "RT_STRING_3857.str", "RT_STRING_3867.str",
           "RT_STRING_3843.str"]:
    p = os.path.join(OUT, fn)
    d = open(p, "rb").read()
    print("=== %s (%d bytes) ===" % (fn, len(d)))
    # ASCII
    a = [m.group().decode("latin1") for m in re.finditer(rb"[\x20-\x7e]{3,}", d)]
    # GBK
    g = []
    for m in re.finditer(rb"(?:[\x81-\xfe][\x40-\xfe])+", d):
        try:
            t = m.group().decode("gbk")
        except Exception:
            continue
        g.append(t)
    print(" ASCII:", a[:25])
    print(" GBK  :", g[:25])
    # UTF-16
    u = []
    for m in re.finditer(rb"(?:[\x20-\x7e\x00]|[\x00-\xff][\x4e-\x9f]){4,}", d):
        try:
            t = m.group().decode("utf-16-le")
        except Exception:
            continue
        if re.search(r"[\u4e00-\u9fff]{2,}", t):
            u.append(t.strip("\x00"))
    print(" UTF16:", u[:15])
