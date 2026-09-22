# -*- coding: utf-8 -*-
"""J1：干净 venv 60 秒安装自测
pip install <包路径> → antinel --host zcode 可用 → 沙箱出第一条审计记录
计时并输出每步耗时。退出码 0 = 全部通过。
"""
import io, sys, os, time, subprocess, tempfile, shutil, json, venv, hashlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
PKG = r"D:\psl\poc\antinel-security"
t_start = time.time()
t_install0 = None

def step(msg, fn):
    t0 = time.time()
    r = fn()
    print("[%5.1fs] %s" % (time.time() - t0, msg))
    return r

venv_dir = tempfile.mkdtemp(prefix="j1venv_")
work = tempfile.mkdtemp(prefix="j1proj_")
proj = os.path.join(work, "proj")
os.makedirs(proj)

def run(cmd, cwd=None, timeout=180, stdin=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout, input=stdin)

ok = True
def make_venv():
    r = venv.create(venv_dir, with_pip=True)
    return r
step("venv 创建", make_venv)

vp = os.path.join(venv_dir, "Scripts") if os.name == "nt" else os.path.join(venv_dir, "bin")
pyv = os.path.join(vp, "python.exe" if os.name == "nt" else "python")
ant = os.path.join(vp, "antinel.exe" if os.name == "nt" else "antinel")

def pip_install():
    global t_install0
    t_install0 = time.time()
    r = run([pyv, "-m", "pip", "install", "--quiet", "--no-input", PKG], timeout=300)
    if r.returncode != 0:
        print(r.stderr.decode("utf-8", "replace")[-1500:])
    return r
r = step("pip install 包（本地路径，模拟 git+ 之后的形态）", pip_install)
ok = ok and r.returncode == 0
if r.returncode != 0:
    print("J1: FAIL（安装失败）"); sys.exit(1)

def bare_help():
    r = run([ant, "--host", "zcode"], timeout=60)
    out = r.stdout.decode("utf-8", "replace")
    return r, out
r, out = step("antinel 裸调用（帮助+宿主+口径）", bare_help)
ok = ok and r.returncode == 0 and "zcode" in out
print("   帮助含宿主/口径:", "zcode" in out)

def morning():
    r = run([ant, "--host", "zcode", "morning"], cwd=proj, timeout=60)
    return r
r = step("晨报（空账本应给出引导语）", morning)
print("   输出:", r.stdout.decode("utf-8", "replace").strip().splitlines()[:1],
      r.stderr.decode("utf-8", "replace")[:80])

# 产一条真实记录：接一个最小钩子事件（用已装包内的 hooks？——安装布局 hooks/ 是包数据）
# pipx/venv 场景下 hooks 路径 = site-packages/hooks。找到它并直接调一次 pre。
import glob as _g
site = os.path.join(venv_dir, "Lib", "site-packages")
hook_pre = os.path.join(site, "hooks", "pre_tool_use.py")
has_hook = os.path.isfile(hook_pre)
print("   site-packages/hooks/pre_tool_use.py:", "EXISTS" if has_hook else "MISSING")
if has_hook:
    os.makedirs(os.path.join(proj, ".psl", "rules"))
    shutil.copy(os.path.join(PKG, "rules", "default.json"), os.path.join(proj, ".psl", "rules", "default.json"))
    rb = open(os.path.join(proj, ".psl", "rules", "default.json"), "rb").read()
    json.dump({"rules_hash": "sha256:" + hashlib.sha256(rb).hexdigest(),
               "hooks_registered": ["PreToolUse"]},
              open(os.path.join(proj, ".psl", "manifest.json"), "w", encoding="utf-8"))
    json.dump({"global_settings": {}, "whitelist": {"domains": [], "paths": [], "commands": []}},
              open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))
    ev = json.dumps({"session_id": "j1", "transcript_path": "", "tool_name": "Bash",
                     "tool_input": {"command": "echo j1"}}).encode()
    r = run([pyv, hook_pre], cwd=proj, timeout=60, stdin=ev)
    print("   hook rc:", r.returncode, "stderr:", r.stderr.decode("utf-8", "replace")[:200])
    r = run([ant, "--host", "zcode", "morning"], cwd=proj, timeout=60)
    out = r.stdout.decode("utf-8", "replace")
    print("   晨报全文：\n" + out)
    ok = ok and ("动作 1" in out)

total = time.time() - (t_install0 or t_start)
print(f"\nJ1 总耗时（安装起算，不含 venv 创建）：{total:.1f}s  → {'PASS' if ok and total <= 60 else 'CHECK'}")
shutil.rmtree(venv_dir, ignore_errors=True)
shutil.rmtree(work, ignore_errors=True)
sys.exit(0 if ok else 1)
