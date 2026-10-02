# -*- coding: utf-8 -*-
import urllib.request, zipfile, io, os
url = "https://codeload.github.com/aiqinxuancai/e-packager/zip/refs/heads/master"
dst = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\tools\e-packager.zip"
req = urllib.request.Request(url, headers={"User-Agent": "re"})
data = urllib.request.urlopen(req, timeout=180).read()
open(dst, "wb").write(data)
print("downloaded", len(data))
z = zipfile.ZipFile(io.BytesIO(data))
out = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\tools\epkg"
z.extractall(out)
print("extracted to", out)
for n in z.namelist():
    if n.endswith((".cpp", ".h", ".md", ".e")) and not n.endswith("json.hpp"):
        print(n)
