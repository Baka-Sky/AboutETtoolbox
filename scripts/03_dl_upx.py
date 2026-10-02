# -*- coding: utf-8 -*-
import urllib.request, json, os, re
api = "https://api.github.com/repos/upx/upx/releases/latest"
data = json.load(urllib.request.urlopen(api, timeout=30))
print("tag:", data["tag_name"])
for a in data["assets"]:
    print(a["name"], a["browser_download_url"])
os.makedirs(r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\tools", exist_ok=True)
for a in data["assets"]:
    if re.search(r"win64\.zip$", a["name"]):
        out = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\tools\upx.zip"
        urllib.request.urlretrieve(a["browser_download_url"], out)
        print("downloaded", out, os.path.getsize(out))
