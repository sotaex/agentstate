# SPDX-License-Identifier: Apache-2.0
# 一次性只读扫描：复刻 ci/inbox_guards_0481.py L1 的精确规则，枚举当前缺头/错标文件。
import os, io, re, json

ROOT = os.path.dirname(os.path.abspath(__file__))
mp = json.load(io.open(os.path.join(ROOT, "license-map.json"), encoding="utf-8"))
EXCL = {".git", ".workbuddy", "__pycache__", "build", "dist", "node_modules",
        ".github", ".psl", ".vscode", ".idea"}
PRE = ("antinel-0.", "_backup.away-", "antinel_mcp.away")
EXEMPT = ("rules/", "demo/", ".workbuddy/")
SPDX = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9\-.]+)")


def resolve(rel):
    ov = mp.get("overrides", {})
    if rel in ov:
        return ov[rel]
    parts = rel.split("/")
    for i in range(len(parts) - 1, 0, -1):
        p = "/".join(parts[:i]) + "/"
        if p in ov:
            return ov[p]
    return mp.get("defaults", {}).get(rel.rsplit(".", 1)[-1].lower())


bad = []
for base, dirs, files in os.walk(ROOT):
    rb = os.path.relpath(base, ROOT).replace("\\", "/")
    dirs[:] = [d for d in dirs if d not in EXCL
               and not any((rb + "/" + d).startswith(p) or d.startswith(p) for p in PRE)]
    for f in files:
        rel = (rb + "/" + f) if rb != "." else f
        if rel.startswith(PRE):
            continue
        if not f.rsplit(".", 1)[-1].lower() in ("py", "md", "html"):
            continue
        if rel.startswith(EXEMPT) or rel == "license-map.json":
            continue
        want = resolve(rel)
        text = io.open(os.path.join(base, f), encoding="utf-8", errors="replace").read()
        lines = text.replace("\r\n", "\n").split("\n")[:6]
        m = SPDX.search("\n".join(lines))
        if want is None:
            bad.append((rel, "未覆盖"))
        elif m is None:
            bad.append((rel, "缺头 want=" + str(want)))
        elif m.group(1) != want:
            bad.append((rel, "错标 %s want %s" % (m.group(1), want)))

print("红名单 %d 处:" % len(bad))
for r in bad:
    print("  ", r)
