# -*- coding: utf-8 -*-
"""安全分析：注册表、网络、进程、文件、可疑行为"""
import pefile, re, os
PATH = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\万物工具箱_unpacked.exe"
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH)

def find(pat, limit=20):
    b = pat.encode("gbk", "ignore") if isinstance(pat, str) else pat
    out, st = [], 0
    while True:
        i = raw.find(b, st)
        if i < 0: break
        out.append(i); st = i + 1
        if len(out) >= limit: break
    return out

def at(off, n=120):
    try:
        return raw[off:off+n].decode("gbk", "replace").replace("\x00", "\\0")
    except Exception:
        return repr(raw[off:off+n])

print("############ 1. 注册表 ############")
reg_pat = [r"Software\\", r"SOFTWARE\\", r"HKEY_", r"HKEY", r"CurrentVersion\\Run",
           r"\\Run", r"RunOnce", r"CLSID", r"Classes\\", r"Microsoft\\Windows",
           r"ControlSet", r"Explorer\\", r"\\Shell", r"Winlogon", r"Image File",
           r"Policies", r"\\Services", r"Environment", r"Uninstall"]
for p in reg_pat:
    hits = find(p, 8)
    if hits:
        print("  命中 %-22s -> %s" % (p, [hex(h) for h in hits]))
        for h in hits[:3]:
            print("       %s" % at(h-8, 100))

print("\n############ 2. 可疑 API（导入表中） ############")
api_of_interest = ["RegCreateKeyExA","RegSetValueExA","RegOpenKeyExA","RegQueryValueExA","RegQueryValueA",
 "CreateProcessA","WinExec","ShellExecuteA","Shell_NotifyIconA","CreateFileA","WriteFile",
 "WritePrivateProfileStringA","GetPrivateProfileStringA","WinExec","LoadLibraryA","GetProcAddress",
 "VirtualAlloc","VirtualProtect","CreateRemoteThread","SetWindowsHookExA","GetAsyncKeyState",
 "URLDownload","InternetOpen","InternetReadFile","WinHttp","socket","connect","send","recv","recvfrom",
 "gethostbyname","ioctlsocket","WSAAsyncSelect","CreateMutexA","CreateThread","CreateEventA",
 "TerminateProcess","SetWindowLongA","OpenPrinterA","ShellExecuteA","CoCreateInstance","OleRun"]
imports = {}
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in dll.imports:
            if imp.name:
                imports[imp.name.decode("latin1")] = dll.dll.decode("latin1")
for a in api_of_interest:
    if a in imports:
        print("  [有] %-28s <- %s" % (a, imports[a]))
print("  导入表中没有的：", [a for a in api_of_interest if a not in imports])

print("\n############ 3. 网络/URL/域名 ############")
for p in [b"http://", b"https://", b"www.", b".com", b".cn", b".net", b".top", b".xyz",
          b"ftp://", b"\\\\.\\", b"\\", b"upload", b"download", b"shell", b"cmd.exe",
          b"powershell", b"reg add", b"regedit", b"schtasks", b"wscript", b"mshta",
          b"rundll32", b"bitsadmin", b"certutil"]:
    h = find(p, 10)
    if h:
        print("  %-14s %s" % (p.decode("latin1"), [hex(x) for x in h[:6]]))

print("\n############ 4. 关键路径与文件写入 ############")
for p in ["\\System32", "\\Windows\\", "Startup", "启动", "AppData", "\\Temp", "System32\\drivers",
          "hosts", "\\ProgramData", "\\Tasks", "Run", "autorun", "startup", "Task Scheduler"]:
    h = find(p, 6)
    if h:
        print("  %-16s %s" % (p, [hex(x) for x in h]))
        for x in h[:2]:
            print("       %s" % at(x-20, 100))
