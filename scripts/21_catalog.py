# -*- coding: utf-8 -*-
"""整理程序常量：工具目录分类、界面文本、群号等"""
import re, os
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()
seg = raw[0xbe000:0xc1700]

strs = []
for m in re.finditer(rb"[\x20-\x7e\x81-\xfe]+", seg):
    try:
        t = m.group().decode("gbk")
    except Exception:
        continue
    if len(t) >= 2:
        strs.append(t)

tools = [s for s in strs if s.startswith("\\Tools\\") or s.startswith("\\GameTools")]
cats = {}
for t in tools:
    parts = t.split("\\")
    cat = parts[2] if len(parts) > 2 else "?"
    cats.setdefault(cat, []).append(parts[-1])
os.makedirs(r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\out", exist_ok=True)
with open(r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\out\tool_catalog.txt", "w", encoding="utf-8") as f:
    for c, items in cats.items():
        f.write("【%s】(%d)\n" % (c, len(items)))
        for it in items:
            f.write("    %s\n" % it)
        print("【%s】%d: %s" % (c, len(items), ", ".join(items)))

print("\n--- 界面/提示文本 ---")
msgs = [s for s in strs if re.search(r"[\u4e00-\u9fff]", s) and not s.startswith("\\")
        and len(s) <= 60]
for s in dict.fromkeys(msgs):
    print("   ", s)
