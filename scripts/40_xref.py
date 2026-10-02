# -*- coding: utf-8 -*-
"""IAT 交叉引用：确认敏感 API 是否真的存在调用点"""
import pefile, struct
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
pe = pefile.PE(PATH)
raw = open(PATH, "rb").read()
IB = pe.OPTIONAL_HEADER.ImageBase

# 区段信息（本文件 RVA==文件偏移）
secs = [(s.Name.rstrip(b'\0').decode('latin1'), s.VirtualAddress,
         s.VirtualAddress + s.Misc_VirtualSize) for s in pe.sections]
print("ImageBase=%08x  sections:" % IB)
for n, a, b in secs:
    print("   %-8s %08x-%08x" % (n, a, b))

# 建立 名称->IAT地址 映射
iat = {}
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in dll.imports:
        if imp.name:
            iat[imp.name.decode("latin1")] = (imp.address, dll.dll.decode("latin1"))

targets = ["RegCreateKeyExA","RegSetValueExA","RegOpenKeyExA","RegQueryValueExA","RegQueryValueA",
 "RegDeleteKeyA","RegDeleteValueA","CreateProcessA","WinExec","ShellExecuteA","ShellExecuteExA",
 "SetWindowsHookExA","SetWindowsHookExW","CreateRemoteThread","VirtualAllocEx","WriteProcessMemory",
 "GetAsyncKeyState","CreateServiceA","OpenSCManagerA","URLDownloadToFileA","InternetOpenA",
 "InternetReadFile","CreateFileA","WriteFile","CopyFileA","MoveFileA","DeleteFileA",
 "CreateMutexA","TerminateProcess","LoadLibraryA","GetProcAddress","WinExec","CreateThread",
 "WSASocketA","socket","connect","send","gethostbyname","bind","listen","accept","recv","sendto"]

def xref(va):
    """在可执行区段内查找对该 IAT 地址的引用(4 字节 LE)"""
    pat = struct.pack("<I", va)
    hits = []
    for n, a, b in secs:
        if n not in (".text",):
            continue
        st = a
        while True:
            i = raw.find(pat, st)
            if i < 0 or i >= b: break
            hits.append(i); st = i + 1
    return hits

print("\n%-26s %-8s %-8s %s" % ("API", "IAT", "调用点", "数量"))
print("-" * 80)
for t in targets:
    if t not in iat:
        print("%-26s %-8s %-8s %s" % (t, "-", "未导入", 0))
        continue
    va, dll = iat[t]
    h = xref(va)
    print("%-26s %08x %-8s %d  %s" % (t, va, dll, len(h),
          [hex(x) for x in h[:10]]))
