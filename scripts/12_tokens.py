# -*- coding: utf-8 -*-
import re
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()

# 搜索易语言事件/子程序命名与命令名
tokens = ["_启动子程序", "_创建完毕", "_被单击", "_被选择", "启动子程序", "信息框", "运行", "执行",
          "取运行目录", "取文本", "到文本", "如果", "计次循环", "变量循环", "返回值", "参考",
          "子程序", "程序集", "全局变量", "局部变量", "类_", "窗口程序集", "DLL命令", "常量",
          "_窗口", "销毁", "载入"]
for t in tokens:
    b = t.encode("gbk")
    idx = []
    start = 0
    while True:
        i = raw.find(b, start)
        if i < 0: break
        idx.append(i); start = i + 1
        if len(idx) > 12: break
    print("%-12s count=%d %s" % (t, len(idx), [hex(i) for i in idx[:12]]))

print("\n=== 0xba900-0xbaf00 (支持库表) ===")
print(raw[0xba900:0xbaf00].decode("gbk", "replace"))
