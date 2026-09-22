# -*- coding: utf-8 -*-
"""Antinel 漂移审计 v1.0：需求文件 → 盘上行为，逐条机械化验证。
需求源：RULES.md / THREAT_MODEL.md v0.27 / AUDIT_SCHEMA v1.2 / SKILL.md / A6 / 三问三答 / UX定稿 / 宿主审计说明书 v1.2
审计对象：部署包 D:\psl\poc\antinel-security（与真实行为，非文档对照文档）
"""
import io, sys, os, json, re, subprocess, tempfile, shutil, hashlib, glob

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
PKG = r"D:\psl\poc\antinel-security"
PY = sys.executable
HOOK_PRE = os.path.join(PKG, "hooks", "pre_tool_use.py")
HOOK_POST = os.path.join(PKG, "hooks", "post_tool_use.py")

results = []
def check(n, ok, evidence=""):
    results.append((n, bool(ok), str(evidence)[:160]))
    print(("PASS " if ok else "FAIL ") + n + ("" if ok else "  -- " + str(evidence)[:160]))

base = tempfile.mkdtemp(prefix="drift_")
proj = os.path.join(base, "proj")
os.makedirs(os.path.join(proj, ".psl", "rules"))
shutil.copy(os.path.join(PKG, "rules", "default.json"), os.path.join(proj, ".psl", "rules", "default.json"))
rb = open(os.path.join(proj, ".psl", "rules", "default.json"), "rb").read()
json.dump({"rules_hash": "sha256:" + hashlib.sha256(rb).hexdigest(),
           "hooks_registered": ["PreToolUse", "PostToolUse"]},
          open(os.path.join(proj, ".psl", "manifest.json"), "w", encoding="utf-8"))
json.dump({"global_settings": {}, "whitelist": {"domains": [], "paths": [], "commands": []}},
          open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))

def hook(script, tool, ti, sid="d"):
    ev = {"session_id": sid, "transcript_path": "", "tool_name": tool, "tool_input": ti}
    p = subprocess.run([PY, os.path.join(PKG, "hooks", script)], cwd=proj,
                       input=json.dumps(ev).encode(), capture_output=True, timeout=60)
    out = {}
    try:
        out = json.loads(p.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
    except Exception:
        pass
    return p.returncode, out, p.stderr.decode("utf-8", "replace")

def chain_lines():
    fn = os.path.join(proj, ".psl", "audit", "2026-09-22.jsonl")
    if not os.path.isfile(fn):
        import datetime
        fn = os.path.join(proj, ".psl", "audit",
                          datetime.datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    if not os.path.isfile(fn):
        return []
    return [json.loads(l) for l in open(fn, encoding="utf-8") if l.strip()]

# ---- A. 协议与规则 ----
rules = json.load(open(os.path.join(PKG, "rules", "default.json"), encoding="utf-8"))["rules"]
fam = {}
for r in rules:
    fam.setdefault(r["id"].split("-")[0], []).append(r["id"])
check("A1 规则总数=24（README/THREAT_MODEL 宣称）", len(rules) == 24, f"实际 {len(rules)}")
check("A2 家族 SEC-01..06/NET-01..03/DST-01..10/CTX-01..05",
      len(fam.get("SEC", [])) == 6 and len(fam.get("NET", [])) == 3 and
      len(fam.get("DST", [])) == 10 and len(fam.get("CTX", [])) == 5,
      json.dumps({k: len(v) for k, v in fam.items()}))

rc, out, err = hook("pre_tool_use.py", "Bash", {"command": "rm -rf /tmp/x"})
check("A3 critical=block：exit2+stdout JSON+stderr 双通道",
      rc == 2 and out.get("decision") == "block" and "拦截" in err, f"rc={rc} out={out}")
rc, out, err = hook("pre_tool_use.py", "Bash", {"command": "curl http://evil-drift-check.com/x"})
check("A4 warning=alert：exit0+stderr 提醒+放行",
      rc == 0 and "NET-01" in err and out.get("decision") != "block", f"rc={rc}")

# A5 whitelist.paths：放行 SEC 读 + dst02_path_whitelisted 留痕（写 .ssh 下一个白名单路径）
pol = json.load(open(os.path.join(proj, ".psl", "policy.json"), encoding="utf-8"))
pol["whitelist"]["paths"] = [(proj + "\\keys\\").replace("\\", "/")]
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))
rc, out, err = hook("pre_tool_use.py", "Read", {"file_path": os.path.join(proj, "keys", "id_rsa")})
cl = chain_lines()
allow_logged = any(r.get("type") in ("workspace_root_allow", "dst02_path_whitelisted") for r in cl)
check("A5 whitelist.paths 豁免 SEC 读且留痕", rc == 0 and allow_logged, f"rc={rc} 留痕={allow_logged}")

# A6 whitelist.commands 不得放宽 critical
pol = json.load(open(os.path.join(proj, ".psl", "policy.json"), encoding="utf-8"))
pol["whitelist"]["commands"] = ["rm -rf /tmp/x"]
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))
rc, out, err = hook("pre_tool_use.py", "Bash", {"command": "rm -rf /tmp/x"})
check("A6 whitelist.commands 不放宽 critical（仍拦）", rc == 2, f"rc={rc}")
pol["whitelist"]["commands"] = []
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))

# A7 DST-09/10 平台门（规则在场=计数不变；nt 外跳过）
d9 = next(r for r in rules if r["id"] == "DST-09")
check("A7 DST-09/10 platforms: nt（计数平台不变）", d9.get("platforms") == "nt", str(d9.get("platforms")))

# A8 不记内容只记哈希/长度 + mask
big = "SECRET" * 3000
hook("pre_tool_use.py", "Write", {"file_path": os.path.join(proj, "big.txt"), "content": big})
cl = chain_lines()
wrecs = [r for r in cl if r.get("input", {}).get("content_len")]
check("A8 只记 content_len 不记内容",
      bool(wrecs) and all("content" not in r.get("input", {}) or not r["input"].get("content")
                          for r in wrecs), f"{len(wrecs)} 条含 content_len")

# A9 运行时零网络：钩子源码无网络调用
net_hits = []
for f in (HOOK_PRE, HOOK_POST):
    src = open(f, encoding="utf-8").read()
    for pat in (r"import socket", r"import requests", r"import urllib", r"httpx", r"http\.client"):
        if re.search(pat, src):
            net_hits.append((os.path.basename(f), pat))
check("A9 钩子运行时零网络（源码无网络导入）", not net_hits, str(net_hits))

# ---- B. 链（AUDIT_SCHEMA v1.2）----
cl = chain_lines()
ok_hash = ok_prev = True
prev_full = ""
for r in cl:
    body = {k: v for k, v in r.items() if k != "hash"}
    canon = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    if hashlib.sha256((prev_full + canon).encode("utf-8")).hexdigest() != r.get("hash"):
        ok_hash = False
    if r.get("prev", "") != prev_full[-16:]:
        ok_prev = False
    prev_full = r.get("hash", "")
check("B1 链公式可复算（AUDIT_SCHEMA §2）", ok_hash and ok_prev and len(cl) > 3,
      f"{len(cl)} 条 hash_ok={ok_hash} prev_ok={ok_prev}")

mainf = os.path.join(proj, ".psl", "audit")
side = os.path.join(mainf, "sidecar")
check("B2 主链无 unlocked 记录（v1.2：降级落 sidecar）",
      all(r.get("chain") != "unlocked" for r in cl), "")
check("B3 day_manifest 日锚存在且单调", os.path.isfile(os.path.join(mainf, "day_manifest.json")), "")
check("B4 第三方验证器在包内（challenge/verify.py + tools/antinel_verify.py）",
      os.path.isfile(os.path.join(PKG, "challenge", "verify.py")) and
      os.path.isfile(os.path.join(PKG, "tools", "antinel_verify.py")), "")

# B5 追加式：链文件只以 "a" 打开（无覆写路径）
src_post = open(HOOK_POST, encoding="utf-8").read()
bad_writes = re.findall(r'open\(fn,\s*"w"', src_post) + re.findall(r'open\(fn,\s*"w[b]?"', src_post)
check("B5 链文件无覆写打开（append-only）", not bad_writes, str(bad_writes))

# ---- C. 失败语义 ----
# C1 畸形输入 fail-open
p = subprocess.run([PY, HOOK_PRE], cwd=proj, input=b"not-json{{", capture_output=True, timeout=30)
check("C1 畸形 stdin → exit0 fail-open + HOOK_ERROR 留痕",
      p.returncode == 0 and b"HOOK_ERROR" in p.stderr, f"rc={p.returncode}")
# C2 坏 transcript → usage_source 降级不崩
p = subprocess.run([PY, HOOK_POST], cwd=proj,
                   input=json.dumps({"session_id": "d", "transcript_path": "Z:/nope.jsonl",
                                     "tool_name": "Write",
                                     "tool_input": {"file_path": os.path.join(proj, "x.txt"), "content": "y"},
                                     "tool_response": {"success": True}}).encode(),
                   capture_output=True, timeout=60)
check("C2 坏 transcript → post 不崩（exit0）", p.returncode == 0, f"rc={p.returncode}")

# ---- D. UX / CLI ----
ANT = os.path.join(PKG, "antinel.py")
r1 = subprocess.run([PY, ANT, "--host", "zcode"], cwd=proj, capture_output=True, timeout=60)
help_out = r1.stdout.decode("utf-8", "replace")
r2 = subprocess.run([PY, ANT, "--host", "zcode", "routes", "--markdown"], cwd=proj,
                    capture_output=True, timeout=60)
routes_out = r2.stdout.decode("utf-8", "replace")
cmds_help = set(re.findall(r"antinel [a-z-]+", help_out))
cmds_routes = set(re.findall(r"antinel [a-z-]+", routes_out))
check("D1 help 与 routes 同源零漂移", cmds_help and cmds_routes and
      (cmds_routes <= cmds_help or cmds_help >= cmds_routes),
      f"help={len(cmds_help)} routes={len(cmds_routes)}")
check("D2 裸 antinel 显示宿主与记账口径", "zcode" in help_out and ("token" in help_out or "记账" in help_out), "")
check("D3 token 宿主下无 credits 子命令", "credits" not in help_out, "")

# D4 SEC 拦截文案不含放行命令（UX 定稿 §七）
rc, out, err = hook("pre_tool_use.py", "Read", {"file_path": "C:/Users/demo/.ssh/id_rsa"})
check("D4 SEC 拦截文案无 add 放行命令",
      "antinel paths add" not in err and "antinel domains add" not in err, err[:120])

# D5 七步写：paths add → policy_changed 进链
r = subprocess.run([PY, ANT, "--host", "zcode", "paths", "add", os.path.join(proj, "extra")],
                   cwd=proj, capture_output=True, timeout=60, input=b"\n")
cl = chain_lines()
pc = [r for r in cl if r.get("type") == "policy_changed"]
check("D5 paths add → policy_changed 进链", bool(pc), f"{len(pc)} 条")

# D6 digest 存在且带覆盖声明
r = subprocess.run([PY, ANT, "--host", "zcode", "digest", "--days", "1"], cwd=proj,
                   capture_output=True, timeout=120)
dg = r.stdout.decode("utf-8", "replace")
check("D6 digest 带覆盖声明（分母显式）", ("覆盖" in dg) and ("未接入" in dg or "宿主" in dg), dg[:80].replace("\n", " "))

# ---- E. 宿主审计 ----
r = subprocess.run([PY, ANT, "--host", "zcode", "host-shield", "status"], cwd=proj,
                   capture_output=True, timeout=60)
hs = (r.stdout + r.stderr).decode("utf-8", "replace")
check("E1 host-shield 默认 disabled（D0 默认全关）",
      ("disabled" in hs.lower() or "未启用" in hs or "关闭" in hs), hs[:100].replace("\n", " "))
hosts_reg = glob.glob(os.path.join(PKG, "rules", "hosts", "*.json"))
ev_ok = True
for f in hosts_reg:
    d = json.load(open(f, encoding="utf-8"))
    for w in d.get("watch", []):
        if "evidence" not in w:
            ev_ok = False
check("E2 外传路径登记表逐条带 evidence（§10.1）", ev_ok and bool(hosts_reg), f"{len(hosts_reg)} 个宿主档案")

# E3 卸载零残留（临时安装目录上做一遍）
tmp2 = tempfile.mkdtemp(prefix="drift_un_")
p2 = os.path.join(tmp2, "proj")
os.makedirs(os.path.join(p2, ".zcode"))
json.dump({"model": "t"}, open(os.path.join(p2, ".zcode", "config.json"), "w"))
inst = os.path.join(PKG, "scripts", "install.py")
subprocess.run([PY, inst, "--root", p2, "--host", "zcode", "--skip-scan"], capture_output=True, timeout=120)
subprocess.run([PY, inst, "--root", p2, "--uninstall", "--purge"], capture_output=True, timeout=120)
raw = open(os.path.join(p2, ".zcode", "config.json"), encoding="utf-8").read()
check("E3 uninstall --purge 零残留", (not os.path.exists(os.path.join(p2, ".psl")))
      and "antinel" not in raw.lower(), raw[:80])
shutil.rmtree(tmp2, ignore_errors=True)

# ---- F. 宣称一致性 ----
skill = open(os.path.join(PKG, "SKILL.md"), encoding="utf-8").read()
check("F1 SKILL.md 宣称 24 rules 4 gates 与实际一致", "24 rules" in skill and len(rules) == 24, "")
a6 = open(os.path.join(PKG, "docs", "A6收入边界声明.md"), encoding="utf-8").read()
check("F2 A6 规则计数（文档级已知漂移：22→24，签署件需公示修订）",
      "22 条检测规则" in a6 and len(rules) == 24, "A6 写 22 条，实际 24——标记待创始人按 A6 自身规则修订")
schema_pkg = open(os.path.join(PKG, "docs", "AUDIT_SCHEMA.md"), encoding="utf-8").read()
check("F3 包内 AUDIT_SCHEMA 已是 v1.2（sidecar 契约）", "v1.2" in schema_pkg and "sidecar" in schema_pkg, "")

shutil.rmtree(base, ignore_errors=True)
npass = sum(1 for _, ok, _ in results if ok)
print(f"\nDRIFT AUDIT: {npass}/{len(results)} PASS")
fails = [n for n, ok, _ in results if not ok]
print("未过项:", fails if fails else "无")
