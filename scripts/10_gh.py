# -*- coding: utf-8 -*-
import urllib.request, json, zipfile, io, os
out_dir = r"c:\Users\jh_JL\Desktop\CKTOOLBOX\_re\tools"
os.makedirs(out_dir, exist_ok=True)

def gh(url):
    req = urllib.request.Request(url, headers={"User-Agent": "re"})
    return urllib.request.urlopen(req, timeout=60).read()

try:
    data = gh("https://api.github.com/repos/aiqinxuancai/e-packager")
    j = json.loads(data)
    print("repo:", j.get("full_name"), "|", j.get("description"))
    print("default_branch:", j.get("default_branch"), "lang:", j.get("language"))
    br = j.get("default_branch", "master")
    tree = json.loads(gh("https://api.github.com/repos/aiqinxuancai/e-packager/git/trees/%s?recursive=1" % br))
    for it in tree.get("tree", []):
        print("  ", it["path"], it.get("size"))
except Exception as e:
    print("ERR", e)
