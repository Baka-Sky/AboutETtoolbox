# -*- coding: utf-8 -*-
"""分析 硬件检测引擎.dll + 全文件重扫 + 本地 JS"""
import pefile, re, os, math, collections
DLL = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\硬件检测引擎.dll"
print("############ 硬件检测引擎.dll ############")
try:
    pe = pefile.PE(DLL)
    raw = open(DLL, "rb").read()
    print("size=%d" % len(raw))
    print("Machine=%04x Sections=%d EP=%08x ImageBase=%08x" % (
        pe.FILE_HEADER.Machine, pe.FILE_HEADER.NumberOfSections,
        pe.OPTIONAL_HEADER.AddressOfEntryPoint, pe.OPTIONAL_HEADER.ImageBase))
    print("TimeDateStamp=%08x  (HEX)" % pe.FILE_HEADER.TimeDateStamp)
    for s in pe.sections:
        print("  %-8s VS=%08x RAW=%08x ent=%.2f char=%08x" % (
            s.Name.rstrip(b'\0').decode('latin1'), s.Misc_VirtualSize,
            s.SizeOfRawData, s.get_entropy(), s.Characteristics))
    print("--- imports ---")
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        print("  [%s] %s" % (d.dll.decode(), ", ".join(
            (i.name or b"#%d" % i.ordinal).decode() for i in d.imports)[:300]))
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("--- exports ---")
        print("  ", [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols][:60])
    print("--- version info ---")
    if hasattr(pe, "FileInfo"):
        for fi in pe.FileInfo:
            for e in fi:
                if hasattr(e, "StringTable"):
                    for st in e.StringTable:
                        for k, v in st.entries.items():
                            print("   %s = %s" % (k.decode(), v.decode("utf-8", "replace")))
    # 签名
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    print("security dir: RVA=%x size=%d" % (d.VirtualAddress, d.Size))
    # 网络/注册表/可疑串
    print("--- 关键字符串 ---")
    for p in [b"http", b"Reg", b"SOFTWARE", b"\\Run", b"CreateRemote", b"GetAsyncKey",
              b"socket", b"connect", b"send", b"cmd", b"powershell", b"temp", b"Temp",
              b"System32", b"Startup"]:
        c = raw.count(p)
        if c:
            print("   %-14s x%d" % (p.decode("latin1"), c))
    print("--- 中文/ASCII 串样例 ---")
    shown = 0
    for m in re.finditer(rb"(?:[\x81-\xfe][\x40-\xfe]|[\x20-\x7e]){5,}", raw):
        try:
            t = m.group().decode("gbk")
        except Exception:
            continue
        if re.search(r"[\u4e00-\u9fff]{2,}", t) and shown < 40:
            print("   %08x %s" % (m.start(), t[:80])); shown += 1
except Exception as e:
    print("ERR:", e)
