# -*- coding: utf-8 -*-
import pefile, re, os, struct
EXE = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
DLL = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\硬件检测引擎.dll"
raw = open(EXE, "rb").read()

print("############ A. 主程序全文件重扫（ASCII+GBK+UTF16） ############")
pats = [b"CurrentVersion\\Run", b"RunOnce", b"\\Run\\", b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        b"Winlogon", b"Shell\\Open", b"\\Services\\", b"ImagePath", b"AppInit_DLLs",
        b"schtasks", b"Task Scheduler", b"\\Startup\\", b"hosts", b"netsh", b"firewall",
        b"reg add", b"bcdedit", b"vssadmin", b"wbadmin", b"Defender", b"Antivirus"]
for p in pats:
    idx, st = [], 0
    while True:
        i = raw.find(p, st)
        if i < 0: break
        idx.append(hex(i)); st = i+1
        if len(idx) > 5: break
    if idx:
        print("  %-52s %s" % (p.decode(), idx))
print("  （上面为空的项表示未出现）")
# UTF-16 版本
print("  -- UTF-16 关键字 --")
for kw in ["Run", "SOFTWARE", "CurrentVersion", "Startup", "http"]:
    b = kw.encode("utf-16-le")
    c = raw.count(b)
    if c: print("     %-16s x%d first=%s" % (kw, c, hex(raw.find(b))))

print("\n############ B. 硬件检测引擎.dll 数字签名 / 覆盖数据 ############")
dpe = pefile.PE(DLL)
d = dpe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
dr = open(DLL, "rb").read()
if d.VirtualAddress and d.Size:
    off = dpe.get_offset_from_rva(d.VirtualAddress)
    sig = dr[off:off+min(d.Size, 64)]
    print("  签名目录 RVA=%x off=%x size=%d head=%s" % (d.VirtualAddress, off, d.Size, sig.hex()))
    # 找证书名
    for m in re.finditer(rb"[\x20-\x7e]{6,}", dr[off:off+d.Size]):
        print("    cert-str:", m.group().decode("latin1"))
last = max(s.PointerToRawData + s.SizeOfRawData for s in dpe.sections)
print("  最后一个区段结束=%x 文件大小=%x 覆盖大小=%x" % (last, len(dr), len(dr)-last))

print("\n############ C. 更新日志 JS/HTML ############")
base = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\更新日志"
for fn in ("app.js", "data.js", "index.html", "styles.css"):
    p = os.path.join(base, fn)
    if not os.path.exists(p):
        print("  %s 不存在" % fn); continue
    t = open(p, "rb").read().decode("utf-8", "replace")
    print("  %-12s %d 字节" % (fn, len(t)))
    for kw in ["http", "eval(", "atob(", "XMLHttpRequest", "fetch(", "ActiveX", "document.write",
               "unescape", "iframe", "cookie"]:
        c = t.count(kw)
        if c: print("      %-16s x%d" % (kw, c))

print("\n############ D. debug.log ############")
p = os.path.join(base, "debug.log")
if os.path.exists(p):
    print(open(p, "rb").read()[:800].decode("utf-8", "replace"))
