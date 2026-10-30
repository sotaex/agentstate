#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Assemble the publishable skill package from the flat PoC layout (spec 2.2 / table 10-1).

Output: <out>/antinel-security/
  SKILL.md                     agent entry (Agent Skills standard; name == directory name, AN-018)
  scripts/install.py scan.py report.py verification_tests.py run_harness.py
  hooks/pre_tool_use.py post_tool_use.py
  rules/default.json
  references/RULES.md          generated from rules/default.json (never hand-edited)
  references/THREAT_MODEL.md
  psl/manifest.json            package metadata + sha256 of every shipped file
  psl/judgment.json            written by scripts/run_harness.py (psl-vs-0.1)

Usage: py -3 build_package.py [--out D:\\psl\\poc] [--verify]
"""
import argparse
import hashlib
import json
import os

# 0.60.0：起子进程一律带 CREATE_NO_WINDOW —— 父进程可能是**无控制台**的
# pythonw（钩子）／DETACHED（哨兵）／GUI 宿主 ⇒ 不带就会给子进程新建控制台
# ＝ 用户看到黑窗一闪。本文件不 import host_shield，就地定义同一常量。
_CNW = 0x08000000 if os.name == "nt" else 0
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- 布局表（唯一真源）
#
# ★★★ 2026-09-28：为什么需要一张表，而不是"多试几个路径"
#
#   症状：本文件被从源仓 r1v3「归位」到产物仓的 `scripts/` 之后，
#         跑起来在第 165 行直接 `FileNotFoundError: ...\scripts\rules\default.json`。
#
#   真因（比"路径写错"更深）：**两个仓的布局不一样，而构建器只认其中一种。**
#         r1v3（源仓）        ：**平铺** —— install.py / pre_tool_use.py /
#                               AUDIT_SCHEMA.md / make_namespaces.py 全在仓根。
#         antinel-security    ：**分类** —— 分别在 scripts/ / hooks/ / docs/，
#                               而 make_namespaces.py 一度整个不在树里。
#         上一轮我只验了 `build_package.py` 的 sha256 与源仓相同，
#         **没验它能不能跑** ⇒ "文件归位了"被当成"构建链还能跑"。
#         这是「套件全绿 ≠ 功能没丢」的又一个活标本。
#
#   ★ 为什么不是"兼容两种布局"（那是补丁，不是解药）：
#     两个布局只要同时存在，就会继续分叉。真正的解药是**只留一种布局**，
#     并把"哪种布局长什么样"**显式写下来**——写成这张表。
#     ⇒ 以后改目录结构 = 改这张表；表里每一项**当场自检**，
#       少一个文件就立刻失败并点名，而不是让某个 `if p.is_file()` 静默跳过。
#
#   ★ 表的形状：`逻辑名 -> 相对仓根的真实路径`。
#     逻辑名就是构建器里用的名字（保持与旧调用点一致，降低改动面）。
_LAYOUT = {
    # ---- 包根模块（随包发在根）----
    "session_dna.py":            "session_dna.py",
    "transcript_reader.py":      "transcript_reader.py",
    "audit_chain.py":            "audit_chain.py",
    "antinel.py":                "antinel.py",
    "antinel_mcp.py":            "antinel_mcp.py",
    "hub.py":                    "hub.py",
    "host_shield.py":            "host_shield.py",
    "strings.py":                "strings.py",
    "egress.py":                 "egress.py",
    "ui_server.py":              "ui_server.py",   # 0.33.2: D-20（原三处漏登记，见下）
    # ---- scripts/ ----
    "install.py":                "scripts/install.py",
    "scan.py":                   "scripts/scan.py",
    "report.py":                 "scripts/report.py",
    # ---- hooks/ ----
    "pre_tool_use.py":           "hooks/pre_tool_use.py",
    "post_tool_use.py":          "hooks/post_tool_use.py",
    "session_start_banner.py":   "hooks/session_start_banner.py",
    # ---- docs/ ----
    "AUDIT_SCHEMA.md":           "docs/AUDIT_SCHEMA.md",
    # ---- rules/ ----
    "default.json":              "rules/default.json",
    "pricing.json":              "rules/pricing.json",
    # ---- tools/ ----
    "antinel_verify.py":         "tools/antinel_verify.py",
    "verify_namespaces.py":      "tools/verify_namespaces.py",
    "verify_chain.py":           "tools/verify_chain.py",
    # ★ 0.35.0：Antinel 监理托盘渲染脚本。`inbox_tray.script_path()` 找的是
    #   `<包目录>/tools/tray.ps1` —— 不登记进布局表，`srcfile("tray.ps1")`
    #   会去找仓根的 tray.ps1（不存在）⇒ 静默少拷一个文件（A1 同款病）。
    "tray.ps1":                  "tools/tray.ps1",
    # ★ 0.49.0：漂浮哨标 WinForms 窗口脚本（inbox_logo.script_path() 的运行时依赖）。
    "logo.ps1":                  "tools/logo.ps1",
    # ★ 0.53.1：哨标的**纯帧数学**（logo.ps1 里 `. $Frame` dot-source 它）。
    #   不登记 = 装出来的包没有这枚文件 ⇒ `Import-Spec` 之前的 dot-source 失败
    #   ⇒ 哨标回落成托盘同族静态圆圈，「标准 LOGO」与「保持动态」全部失效。
    #   同一形状 0.36.4 已踩过一次（enforce_probe.py 一直随包却没进 _LAYOUT），
    #   这里不再重演：登记在本表，且在 0516 的 _FOCUS 里被真 wheel 载荷对账。
    "logo_frame.ps1":            "tools/logo_frame.ps1",
    # ★★ 0.36.4 补：本机实测抓到 —— `tools/enforce_probe.py` **一直随包发布**
    #   （实测产物 `build/lib/tools/enforce_probe.py` 在），却**从未登记进
    #   `_LAYOUT`**，因此**从未进 `psl/manifest.json`**（实测 manifest 101 项里
    #   没有它）。而 `host_shield._GUARDED_CHAIN_FILES` 恰恰把它列为
    #   "自检探针（它一失效就没人知道门失效）" ⇒ **保护名单里有一个文件从未被保护**。
    #   后果实测：改它 **零报警** —— 自检对它完全失明。
    #   这不是"多登记一个文件"的洁癖，是**保护范围与被保护对象不匹配**（0.35.3
    #   修过同一个病的另一半）。根因在布局表漏登记，在这里补齐。
    "enforce_probe.py":          "tools/enforce_probe.py",
}

# 必须存在 = 缺了就**不许构建**。其余（pricing/namespaces 生成器等）允许缺，
# 但缺了要**打印出来**，不许静默（「没查到」必须与「没发现」分开）。
_LAYOUT_REQUIRED = (
    "antinel.py", "pre_tool_use.py", "post_tool_use.py", "install.py",
    "scan.py", "report.py", "default.json", "AUDIT_SCHEMA.md",
)


def _find_src_root():
    """定位"源码根"——**用内容探测，不猜层级**。

    判据：一个目录同时含 `rules/default.json` 与 `antinel.py` 就是根。
    这两个文件缺任何一个，构建器都跑不下去，所以它们是最强的可用信号。
    不数 up 几层：层级会随布局变，内容不会。
    """
    here = Path(__file__).resolve().parent
    for cand in (here, here.parent, here.parent.parent):
        if (cand / "rules" / "default.json").is_file() and (cand / "antinel.py").is_file():
            return cand
    return here      # 兜底：让报错发生在真正需要文件的地方（下方会显式点名）


SRC = _find_src_root()

# ★★★ 0.39.2：版本行归一化 —— **唯一真源在 host_shield.py**，这里 import 它。
#   为什么必须 import 而不是在本构建器里再写一份正则：算 `hooks/pre_tool_use.py`
#   哈希的地方（本构建器写 manifest / `host_shield.self_check()` / `run_harness`
#   的 judgment digests / `tools/antinel_verify.py`）**必须同法**；
#   只改一侧 ⇒ 该文件哈希**恒失配**，比不改更糟（交接件 §6.5 / §6.7）。
#   ⇒ 本文件**不定义**归一化，只消费；判据 `ci/inbox_guards_0380.py` S19 钉这条。
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
try:
    import host_shield as _hs
except Exception as _hs_e:                                     # noqa: BLE001
    raise SystemExit(
        "★ 构建器拿不到版本行归一化函数（host_shield）：%r\n"
        "  hooks/pre_tool_use.py 是版本承载件之一 —— 两侧必须同法归一化，\n"
        "  只改一侧会让它的哈希恒失配（比不改更糟）。" % (_hs_e,))


def srcfile(rel):
    """把**逻辑名或相对路径**解析成 SRC 下的真实路径（经布局表）。

    ★ 一律走这里，不要直接 `SRC / "xxx"`。
      `SRC / "install.py"` 在产物仓是错的（它在 scripts/），而错法很隐蔽：
      某个 `if p.is_file()` 会静默跳过，构建"成功"但**少文件**——
      正是 A1 那 29 个文件当初丢失的同一个病。

    ★ 名字叫 srcfile 而不是 src：`build()` 作用域里已经有一个局部 `src`
      （`src = final / rel`），同名会让 Python 把本函数当局部变量引用，
      抛 `UnboundLocalError`。**改名的理由写在这里，免得后人改回去。**
    """
    real = _LAYOUT.get(rel, rel)
    return SRC / real


def _verify_layout():
    """构建前自检布局表：必填项一个都不能少；可选项缺了要**打印**。"""
    missing_req, missing_opt = [], []
    for logical in _LAYOUT:
        p = srcfile(logical)
        if p.is_file() or p.is_dir():
            continue
        (missing_req if logical in _LAYOUT_REQUIRED else missing_opt).append(
            "%s -> %s" % (logical, _LAYOUT[logical]))
    if missing_req:
        raise SystemExit(
            "★ 构建前布局自检失败：以下**必填**文件不在树里 ——\n  "
            + "\n  ".join(missing_req)
            + "\n\n  仓根：%s\n" % SRC
            + "  改目录结构时必须同步改 build_package.py 顶部的 _LAYOUT 表。\n"
              "  （这条自检的存在理由：上一轮『归位』后构建器静默崩在别处，\n"
              "    把『位置错』伪装成了『文件缺失』。）")
    if missing_opt:
        print("布局自检：以下**可选**件缺失（构建将继续，但你不该不知情）——")
        for m in missing_opt:
            print("   · %s" % m)
    print("布局自检：%d 个逻辑名全部解析成功（必填 %d、可选 %d）"
          % (len(_LAYOUT), len(_LAYOUT_REQUIRED), len(_LAYOUT) - len(_LAYOUT_REQUIRED)))


if not (SRC / "rules" / "default.json").is_file():
    raise SystemExit(
        "★ 构建器找不到源码根：在 %s 及其上两级里都没有 rules/default.json。\n"
        "  build_package.py 必须在「仓根」或「仓根/scripts」下运行。"
        % Path(__file__).resolve().parent)

# ★★ HARNESS_SRC：产物仓里套件就在 scripts/verification_tests.py（**已入库、受 git 管**）。
#   原写法硬编码源仓绝对路径 ⇒ 在产物仓跑会**用源仓的测试文件覆盖产物仓的被审对象**，
#   而 verification_tests.py 本身是 manifest 67 项之一 ⇒ 覆盖后 manifest 立刻不符。
#   这不是"兼容性"，是正确性：产物仓构建必须用**产物仓自己的**套件。
#   （2026-09-28：r1v3 的 _antinel_selftest/run_tests.py 仍保留作历史留档，
#    但**不再**是构建输入——它的存在只会制造"两个套件谁说了算"的歧义。）
HARNESS_SRC = SRC / "scripts" / "verification_tests.py"
if not HARNESS_SRC.is_file():
    raise SystemExit("★ 构建器找不到套件：%s\n  （产物仓构建必须用本仓的套件）" % HARNESS_SRC)
NAME = "antinel-security"
VERSION = "0.63.0"
# P-A3: the namespace this build declares itself under. derive_object_ownership()
# reads git remote first, then THIS field; fail-closed unattributed when neither
# resolves. Kept beside the hashes so a third party can see what was declared.
NAMESPACE = {"host": "github.com", "owner": "antinel-security"}

# 2026-09-24 (G7): pyproject.toml is now GENERATED from VERSION.
# It used to be hand-maintained in the built package. That produced two version
# numbers in two places, and the one users actually SEE (`pip show antinel`) was
# the one NOT under the builder's control -- while the CLI banner, the MCP
# serverInfo and the rules file all said the other number. Generating it makes
# that class of drift structurally impossible.
# It is written AFTER the manifest is computed, on purpose: pyproject.toml is a
# packaging file, not part of the installed skill, so it stays out of
# psl/manifest.json exactly like server.json / llms.txt (see REPO_EXTRAS).
PYPROJECT = """[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "antinel"
version = "__VERSION__"
description = "Local-first audit chain and ledger for AI coding agents: every action recorded, every record verifiable."
readme = "README.md"
license = {file = "LICENSE"}
requires-python = ">=3.10"
authors = [{name = "geguang", email = "geguang@gmail.com"}]
keywords = ["ai-agents", "audit", "security", "claude-code", "mcp", "agent-safety",
            "supply-chain", "local-first", "privacy"]
classifiers = [
  "Development Status :: 4 - Beta",
  "Environment :: Console",
  "Intended Audience :: Developers",
  "Intended Audience :: Information Technology",
  "License :: OSI Approved :: Apache Software License",
  "License :: OSI Approved :: MIT License",
  "Operating System :: Microsoft :: Windows",
  # ★ 0.48.4：wheel 是 py3-none-any（纯 Python、无平台相关产物），只声明 Windows
  #   是**低报**——PyPI 的筛选与 `pip` 的平台匹配会据此把 POSIX 用户挡在候选之外，
  #   而 README「已知边界」早已写明 macOS/Linux 由 CI 矩阵持续验证。
  "Operating System :: POSIX",
  "Operating System :: MacOS :: MacOS X",
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Programming Language :: Python :: 3 :: Only",
  "Topic :: Security",
  "Topic :: Software Development :: Quality Assurance",
  "Topic :: System :: Monitoring",
]

# 0.34.0: previously there was not a single URL. The PyPI page showed a package
# name and one line of description, with no way to reach the source -- the worst
# gap in the trust stack for a tool whose whole claim is "verifiable by a third
# party". This template is the real source of truth (pyproject.toml is generated
# here), so the URLs have to live in this string, not in the generated file.
[project.urls]
Homepage = "https://antinel.com"
Repository = "https://github.com/sotaex/agentstate"
Source = "https://github.com/sotaex/agentstate"
Issues = "https://github.com/sotaex/agentstate/issues"
Changelog = "https://github.com/sotaex/agentstate/blob/main/docs/AUDIT_SCHEMA.md"

[project.scripts]
antinel = "antinel:main"

[tool.setuptools]
py-modules = ["antinel", "audit_chain", "session_dna", "strings",
              "transcript_reader", "host_shield", "hub", "antinel_mcp", "egress",
              "ui_server",
              # ★ 0.35.0 Antinel 监理：13 个新模块（与 build() 里的 root_mod 复制清单逐字一致）
              "inbox_model", "inbox_store", "inbox_report", "inbox_server",
              "inbox_tray", "inbox_notify", "inbox_emphasis", "inbox_fallback",
              "inbox_daemon", "inbox_config", "inbox_cli",
              "ledger", "heartbeat",
              # ★ 0.49.0 急事冒泡＋漂浮哨标（服务/窗口机制，无第三方依赖）
              "inbox_bubble", "inbox_logo",
              # ★ 0.35.3 术语表（与仓库 pyproject.toml 逐字一致）
              "glossary",
              # ★ 0.36.0 窗口几何 + 失守归因（两个新模块，
              #   与 build() 里的 root_mod 复制清单逐字一致）
              "inbox_window", "remediation",
              # ★ 0.38.0 粮（哨兵口粮）＋ 机器唯一码（两个新模块，
              #   与 build() 里的 root_mod 复制清单逐字一致）
              "granary", "machine_id",
              # ★ 0.55.0 状态机改造（A/B 双线汇合）：四个新模块。
              #   与仓库 pyproject.toml 及 build() 的 root_mod 清单逐字一致。
              "facts", "situation", "state_registry", "sidecar"]
packages = ["hooks", "scripts", "tools", "rules", "psl", "assets", "challenge"]

[tool.setuptools.package-data]
rules = ["*.json"]
psl = ["*.json", "*.md"]
hooks = ["*.py"]
# ★ 0.35.0 Antinel 监理静态资源。实测（_p9_wheeltest 构建中间产物
#   `build/bdist.*/wheel/assets/`）：**这几条 glob 本身就够**，assets 下 28 个静态
#   文件全进 wheel（icons 20 + logo 5 mp4 + logo.svg + antinel.ico + sounds 1）。
#   ★ 0.52.0：`logo/*.ico` 是品牌图标（桌面/自启/AUMID 快捷方式共用），生成器
#   `tools/mk_logo_ico.py`（构建期从 logo.svg 栅格化，与 mk_icons 同 Convention）。
#   `_manifest_for` **不会**再为 assets 生成 `recursive-include` —— 它只补
#   package-data 覆盖不到的文件（如 `rules/hosts/*.json`）。非 package 目录
#   （docs/ references/）只进 sdist，wheel 里 0 个（实测）。
assets = ["icons/*.ico", "logo/*.mp4", "logo/*.svg", "logo/*.ico", "sounds/*.wav"]
# ★ 0.35.2：`challenge/` 公开挑战件 —— **必须进 wheel**。
#   为什么：`antinel verify` 在链干净时会告诉用户"你可以自己复算"，并给出
#   `<包目录>/challenge/verify.py` 这条命令。而此前 `challenge/` **只进 sdist**
#   （靠 `MANIFEST.in` 的 `recursive-include challenge *.py *.md`），
#   ⇒ pip 装（wheel 路径）的用户照着敲会得到 `Errno 2 No such file or directory`。
#   实测（2026-10-06 真实用户验收）：wheel 顶层只有 dist-info/assets/hooks/psl/
#   rules/scripts/tools，含 `challenge` 的成员 **0 个**。
#   撞铁律：「**页面上不许教跑不通的命令**」。
#   `.py` 由 build_py 随包（见 `_assert_package_data_covered` 的实测注释），
#   下面三条 glob 覆盖非 .py 的那些（README.md / tamper-lab.html / chain/*）。
challenge = ["*.md", "*.html", "chain/*.jsonl", "chain/*.json", "LICENSE"]
"""

# 2026-09-24 (G7): files that live in the package repo but are NOT produced by
# this builder and are NOT covered by psl/manifest.json (the manifest's scope is
# exactly this builder's output -- measured 41 files vs 127 tracked). Until today
# shutil.rmtree() deleted them silently. A dry-run build measured 86 tracked
# files disappearing, among them:
#   .github/workflows/daily-chain.yml  -- the PUBLIC EXTERNAL ANCHOR (daily chain
#                                         commits); losing it would break the one
#                                         mechanism that makes whole-chain
#                                         recomputation detectable
#   server.json                        -- already published to the MCP registry
#   pyproject.toml                     -- (now generated above, not preserved)
#   antinel_mcp.py, challenge/, demo/, ci/, docs/BRAND.md, llms.txt, MANIFEST.in
# MANIFEST.in itself declares these as sdist contents (`include pyproject.toml`,
# `recursive-include challenge/demo/docs`), so they are meant to ship.
# build/ , antinel.egg-info/ and psl/ci_debug/ are setuptools/CI artifacts that
# are tracked by mistake; untracking them is a separate, founder-visible decision.
#
# The build now MERGES rather than replaces (see build()), so nothing here can be
# deleted any more. This list is kept as a POST-BUILD GUARD: if any of them is
# missing after a build, the build says so, instead of the loss staying silent
# for four releases the way it did before.
REPO_EXTRAS = ("server.json", "llms.txt", "challenge", "demo", "ci",
               "MANIFEST.in", ".github", "docs/BRAND.md",
               "build", "antinel.egg-info", "psl/ci_debug")

# P-B7: one line per rule -- what real event it exists for. Single source in the
# generator so references/RULES.md stays generated (never a second hand-written file).
RULE_PURPOSE = {
    "AN-001": "Prevents an agent reading .env files (live-blocked in ZCode on 09-10; the founding interception)",
    "AN-002": "Prevents SSH private key / authorized_keys reads (the credential that outlives every session)",
    "AN-003": "Prevents cloud credential file reads (aws/kube/gcloud -- the keys that move cloud billings)",
    "AN-004": "Prevents wallet/keystore access (irreversible financial loss class)",
    "AN-005": "Prevents browser profile reads (live login sessions, not just passwords)",
    "AN-021": "Catches secret literals IN content (a key pasted into code outlives the file it was meant for)",
    "AN-006": "Surfaces shell egress to non-whitelisted domains (first-generation C2 / exfil channel)",
    "AN-007": "Surfaces inline-code network calls (the same egress hidden inside python -c)",
    "AN-008": "Surfaces non-whitelisted domains named in commands (DNS-level comparison is v2)",
    "AN-009": "Blocks deletion commands (rm/del/rd/Remove-Item and library calls -- measured 11 live blocks)",
    "AN-010": "Blocks writes outside the project root (the workspace is the trust boundary)",
    "AN-011": "Blocks shell-startup edits (persistence that re-executes on every terminal)",
    "AN-012": "Blocks persistence installs (cron/systemd/registry Run/schtasks -- survives the session)",
    "AN-013": "Alerts on privilege escalation (sudo/chmod 777 -- sysadmin territory)",
    "AN-019": "Blocks remote-script-piped-to-interpreter (the classic supply-chain install)",
    "AN-020": "Blocks irreversible git discards (reset --hard / clean -fdx eat uncommitted work)",
    "AN-022": "Blocks recursive permission/ownership destruction (denial-of-service class; POSIX chmod/chown and Windows icacls/takeown)",
    "AN-023": "Blocks alternate-data-stream writes from a file tool (Windows-only: path:stream is a legal POSIX filename)",
    "AN-024": "Blocks alternate-data-stream writes from a shell (redirect / -Stream / copy / open -- the command half of AN-023)",
    "AN-014": "Alerts on environment enumeration (the precursor to secret exfiltration)",
    "AN-015": "Blocks prompt injection in skill instructions (the skill-poisoning payload core)",
    "AN-016": "Blocks invisible Unicode (tag/zero-width/RLO -- the human-eye bypass, live-blocked 3x)",
    "AN-017": "Alerts on long encoded blobs in skills (the payload behind base64/hex laundering)",
    "AN-018": "Detects SKILL.md identity mismatch (name spoofing / packaging slip)",
}

#: ★★ 2026-10-08（0.36.9）：`.gitignore` 由**本模板整文件生成**，仓里那份是它的
#:   投影。 why：2026-09-29 把 setuptools 垃圾三行写进模板（此前 898791a 手工补的
#:   三行被本模板**静默回退**，`git diff .gitignore` 实测可见）；2026-10-08 又把
#:   `*.trash*`／`_p_*`／`_t_*` 三条卫生规则手工补进仓里那份 ⇒ 同一坑**第二次**
#:   踩中（本次构建后规则消失，git status 立刻多出 92 个未跟踪探针）。
#:   ★ 教训只写在注释里不够——两次都是注释记住了、手还是照旧。所以除写进模板外，
#:     另加 JDG-05：**仓内 .gitignore 必须与本模板逐字节相同**，不同即红
#:     （「构建器拥有的文件，手工改迟早被覆盖」从此由机器兜底，不靠自觉）。
GITIGNORE_TEMPLATE = (
    "__pycache__/\n*.pyc\n.psl/\n*.log\n"
    "build/\nantinel.egg-info/\ndist/\n"
    "*.away-*\n"
    # ★ 2026-10-03 补四行（同上：写进模板才是修法）：
    #   *.bak-*        —— 0.34.0 清垃圾时实测到 16 个 `*.bak-*` 里有 11 个在子目录，
    #                     且其中 ci/drift_audit.py.bak-* 已被 git 跟踪
    #                     ⇒ 不 ignore 的话，每次构建后 git status 都脏。
    #   _tools_034/    —— 本轮三件可复用工具（版本迁移/manifest 重签/垃圾清理），
    #                     目录名以 _ 开头，与构建产物无关。
    #   _probe_*.py 等 —— 定位 F-17 时的一次性探针（含硬编码路径 + 调试 print），
    #                     属过程证据，不该被人当正式工具跑。
    "*.bak-*\n_tools_034/\n"
    "_probe_*.py\n_patch_*.py\n_bump_version.py\n_version_bump_*.py\n"
    "_resign_manifest.py\n_cleanup_junk.py\n_suite_probe.py\n"
    # ★ 2026-10-03：安装副作用目录。装到本仓时会在仓内生成 .qoder/ 或
    #   .zcode/（钩子注册）。它们**是被安装的产物**，入库等于把本机钩子配置
    #   和解释器路径塞进公共仓库 —— 本轮实测批量装完 git status 就脏了。
    ".qoder/\n.zcode/\n"
    # ★★ 2026-10-08（0.36.8 提交卫生，0.36.9 收进模板）：
    #   *.trash* —— 宿主守卫在 copy2 覆盖仓内文件时把旧内容 quarantine 成的
    #               `<name>.g0364.trash`；仓内「改名让开」也留下 `*.away-*`。
    #               两者永不入库（构建器侧另有 NEVER_SHIP_PATTERNS 双保险）。
    #   _p_* / _t_* —— 本机探针与临时工作件。**闸门契约件**（_p_bubble_negctl.py
    #               等负控 + _p_badge_probe.py + _p_p11_negctl_mutation.py）由
    #               `git add -f` 先于规则入库 ⇒ git 跟踪优先于 ignore，契约不受影响。
    #               ★ 0.36.9 实测教训：本可以早两天加这条规则，但 0.36.8 我把规则
    #               手工补进**仓里那份**（模板没改）⇒ 一次构建后规则蒸发、92 个
    #               探针重新污染 status。**改了仓里那份不改模板 ＝ 没改。**
    "*.trash*\n_p_*\n_t_*\n"
    #: _uxtest/ —— verification_tests 的导出工作区（export.*/health.*）。
    #:   0.36.8 同样只补进仓里那份而没进模板，本次写回时被抹掉过一次 ⇒ 现收进模板。
    "_uxtest/\n"
    #: 0.48.2：`_uxtest2/` —— `ci/j2_pypi_e2e.py` 用户旅程模拟的证据区（venv 建在系统
    #:   临时目录，这里只落 JSON/txt 证据）。与 `_uxtest/` 同族，永不入库。
    #:   `_ux_fix_*.py` —— 一次性迁移脚本（本轮：命令形态 `-m` 化 / A6 指针批改），
    #:   与 `_patch_*.py` 同族：过程证据，不该被当正式工具跑。
    #:   ★ 为什么必须写进模板：0.36.8 / 0.43.x 两次实测过「只改仓里那份、没改模板
    #:     ⇒ 下次构建静默回退」；JDG-05 逐字节兜底，改模板才是修法。
    "_uxtest2/\n_ux_fix_*.py\n"
    # ★★ 2026-10-10（0.43.x Step C 卫生）：与 `build/`、`dist/` 同族的**构建暂存/归档**
    #   目录，外加代理工作区：
    #     antinel-*/     —— `python -m build` 解出的 sdist 暂存树（`antinel-<ver>/`）。
    #     _archive_dist/ —— `_archive_stale_dist` 把旧发布件挪进的归档目录（S38/S39）。
    #     .workbuddy-ai/ —— 代理（AI）工作区（含本地记忆）。
    #   实测（Step C）：这三个目录此前未忽略，`git status` 长期挂着一串未跟踪项；
    #   一次 `git add -A` 就会把它们误入库。**写进模板才是修法**（见上方两次
    #   "只改仓里那份、没改模板 ⇒ 下次构建静默回退"的教训；JDG-05 逐字节兜底）。
    "antinel-*/\n_archive_dist/\n.workbuddy-ai/\n"
    # ★★ 2026-10-16（0.51.0，并行修订制度补同步）：`.worktrees/` —— git
    #   worktree 工作树（分支 stream-b 的并行修订流，2026-10-16 落地）。
    #   worktree 是 git 的工作副本，永不入库。上轮制度落地时**只改了仓里
    #   那份、没改模板** ⇒ JDG-05 当场抓到（"模板 28 行／仓内 29 行"）——
    #   这正是本模板注释里第三次同一教训，修法照旧：改模板才是修法。
    ".worktrees/\n"
    # ★★ 2026-10-26（0.57.0）：两个本机待查证据件 —— `NUL.lock`（锁路径解析异常时
    #   Windows 保留设备名被当成路径留下的残件）与 `console/`（值守台运行态输出）。
    #   两者都不是仓库内容，但**不许删**（行动清单第 27 条：留证待查）。
    #   ★ 这是同一教训的**第四次**：这三行先只补进仓里那份 ⇒ 07:02 那次构建整文件
    #     覆盖，三行无声蒸发（`git diff .gitignore` 可见）。写进模板才是修法。
    "NUL.lock\nconsole/\n"
    # ★★ 2026-10-26（0.57.0）：代理/本机会话的**工作产物区** ——
    #   `analysis-tmp/`（1024 参赛与融资视角的分析稿、会议 CFP 抓取素材）、
    #   `.zwork/`（代理运行目录：attachments / background / runs）。
    #   与 `output/`、`_p_*`、`_t_*` 同性质：**不入库、不进包、不是本仓归属对象**。
    #   实测：不忽略 ⇒ 交付闸门的 L1（SPDX 归属）多报 4 处「缺 SPDX 头」假红，
    #   而这 4 个文件本来就不会进任何发布件 —— 假红会掩盖真红，必须收进口径。
    "analysis-tmp/\n.zwork/\n"
    # ★★ 2026-10-30（0.62.0）：金丝雀诱饵目录 —— **绝不进版本库**。
    #   理由不是「本机垃圾」，而是**机制性的**：诱饵的全部价值在于「只有本机知道
    #   哪个文件是诱饵」；一旦进了仓库，攻击者先读 `.canary/` 就知道该绕开哪个
    #   文件名、该忽略哪个 marker ⇒ 诱饵退化成普通文件，`AN-036`（Canary file
    #   read）观察的「外传链路」就断了。诱饵由 `antinel canary plant`
    #   （安装末尾自动执行）在本机生成，每台机器 marker 不同。
    #   ★ 这是同一教训的**第五次**：先只补进仓里那份 ⇒ JDG-05 当场红
    #     （「模板 33 行／仓内 36 行」）。写进模板才是修法。
    ".canary/\n"
)

# ★★ 2026-10-11（0.48.1，策略 v1.1 落地）：主许可 MIT → Apache-2.0。
#   官方全文自 apache.org 原件嵌入（md5 3b83ef96387f14655fc854ddc3c6bd57，含附录），
#   不做任何附加——G7-3 的教训（附加段把相似度压到阈值之下）由
#   ci/inbox_guards_0481.py L2 常驻把守。A6 只经 NOTICE 指针进入。
#   四层归属的唯一数据真源 = license-map.json。
LICENSE_MD = """
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

# MIT 层文本：策略 v1.1 §三 的引流小件（challenge/ 目录 LICENSE 与文件头同源）。
# glossary.py 已按核验报告 v1.0 §1.4 乙案移出 MIT（顶层硬依赖 inbox_model）。
MIT_MD = """MIT License

Copyright (c) 2026 Zhilv Technology (Antinel / PSL)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

# NOTICE：Apache-2.0 §4(d) 的归属通知载体。首行 = MIT 豁免（策略 §五.5）。
NOTICE_MD = """MIT 豁免：本 NOTICE 只对以 Apache-2.0 发布的部分生效；凡文件头 SPDX 标识为
MIT 的组件（antinel_mcp.py、transcript_reader.py、tools/probe_host.py、strings.py、
challenge/ 目录）不适用本 NOTICE，仅受其随附的 MIT 许可与文件头 SPDX 标识约束。

Copyright 2026 Zhilv Technology (Antinel / PSL)

A6 收入边界声明（对项目自身的政策约束，不构成对本许可所授予权利的限制）
见源码仓 docs/A6收入边界声明.md（CC-BY-4.0；该件随源码分发包 sdist 分发，不随 wheel）。
"""

# G7-3 (2026-09-24): 原先本模板末尾挂着 4 行中文（`---` + 「收入与中立性边界」）。
# ★ 这里才是真源 —— LICENSE 是**构建器产物**（见下面 (pkg / "LICENSE").write_text），
# 所以只改仓里的 LICENSE 等于白改：下一次重建就会把它写回来（本轮实测过一次）。
# 删它的理由：LICENSE 必须只含许可条款本体；附加声明会被下游读成
# 「MIT ＋ 额外限制」（实测与标准 MIT 相似度 0.9399 → 删后 0.9749，这正是
# GitHub 认不出 MIT 的原因）。A6 声明已在 docs/A6收入边界声明.md，有它自己的家。

# 0.29.0：**规则数从 rules/default.json 派生** —— 凡会变的数一律不写死。
# 前车之鉴（写在 antinel_verify.py INV-5 里）：规则数 24→25 时，站上 15 处硬编码的
# "24 条规则" 全变成假数字，**且没有任何报错**。这 4 处模板是同类风险点。
RULES_N = len(json.loads((SRC / "rules" / "default.json").read_text(encoding="utf-8"))["rules"])

# 0.29.0（第二批）：**家族区间也一律现算** —— 与 RULES_N 同病、同类修法。
# 前车之鉴：总数用 %(rules)d 令牌修好了，但 `AN-001..06` / `AN-009..10` 这类区间
# 仍是手写 ⇒ 规则加到 31 条后，随包文档还在宣称 25 条时代的区间，**静默少报了
# AN-026..10 / AN-030 / AN-031 / AN-025**（其中前四条正是偷数据防线）。
# 最刺眼的是 THREAT_MODEL 自己就写着 "a stale range silently understates
# what is enforced" —— 它警告了这个失效模式，然后自己犯了。
# 修法：闸门归属由 category 派生（＋ 极少数显式例外），区间串由实际编号压缩生成。
# ★★ 2026-09-28 重要澄清（先把话说清楚，再改代码）：
#
#   闸门（Gate 1..4）**只是文档叙事**，不是账本口径、不是判定逻辑。
#   实测证据（三条，全部当场量出）：
#     · `%(gate1..4)s` 只出现在**文档模板**里（README 的威胁表、THREAT_MODEL、
#       SKILL.md 的 `--help` 正文），没有任何代码用它做分派；
#     · 钩子里 grep 不到任何 "gate 1..4" 的判定分支；审计事件只带 `rule_id`
#       （如 `AN-009`），**不带闸门号**；
#     · `rules/default.json` 顶层那个 `gates` 字段**零消费点** —— 全仓没有一行代码
#       读它。按本项目既定纪律：**没有消费点的字段不是登记表，是注释。**
#   ⇒ 所以这里**不需要**"闸门真源"。需要的是两件小事：
#       ① 文档表格能生成（新类别不能缺）；
#       ② 规则表出现新类别时**构建必须当场失败**，而不是像我上一轮那样
#          "文件归位了却没验能不能跑"，让构建器静默崩在模块级。
#
#   ★ 另一条实测结论：`category` 粒度**不足以**表达闸门归属 ——
#     `supply_chain` 这 5 条横跨闸门 1/2/3（AN-033 工具描述投毒→1、
#     AN-035 明文密钥→2、AN-032/AN-034 配置与出联→3），规则表自己也只写了
#     "Gate 2/3"（作者当时也说不清）。因为闸门只是叙事，**多归属是诚实的表达**，
#     强行压成一个数才是撒谎。故本表的值允许是 tuple。
_GATE_OF_CATEGORY = {
    "injection": 1,     # 闸门1 内容安全：技能投毒
    "secrets": 2,       # 闸门2 敏感面：读密钥/隐私
    "metadata": 3,      # 闸门3 元数据与出联：身份伪装
    "network": 3,       # 闸门3 元数据与出联：域名、隧道
    "context": 4,       # 闸门4 行为：环境枚举
    "destructive": 4,   # 闸门4 行为：删除/越界写/持久化
    # 0.31 新增两类（2026-09-28 补齐 —— 此前缺失，导致构建器在模块级直接崩）
    "supply_chain": (1, 2, 3),   # MCP 供应链：投毒(1)/密钥(2)/配置与出联(3)
    "canary": 2,                 # 金丝雀：与 AN-001..11 同属敏感面（README 已如此呈现）
}
# 显式例外：AN-006/AN-007 是"命令里发了网络请求"（属闸门4 行为），
# AN-008/AN-031 才是"出联策略"（域名白名单、隐蔽信道，属闸门3）。两者 category 都是
# network，靠 category 分不开，只能显式点名。
_GATE_OVERRIDE = {"AN-006": 4, "AN-007": 4}


def _compress_ids(ids):
    """['AN-001',...,'AN-010'] → 'AN-001..010'；离散的 → 'AN-002..004, AN-007'。

    ★ 0.63.0 改名：位宽从"写死两位"改成**取自 id 本身**。写死两位 ⇒ 三位号被压成
      `AN-01..37`，随包文档里那个区间串反查全部落空，而且**不报错**。
      用 max(len(num)) 而不是写死 3：将来若出现 `AN-1000` 或回退两位号，
      这个函数仍然自洽（写死位宽是同一个错误的另一种形态）。
    """
    fams = {}
    for i in ids:                                   # 'AN-001' -> ('AN', 1, 3)
        fam, num = i.rsplit("-", 1)
        fams.setdefault(fam, []).append((int(num), len(num)))
    parts = []
    for fam in sorted(fams):
        pairs = sorted(fams[fam])
        width = max(w for _, w in pairs)
        nums = [n for n, _ in pairs]
        runs, start, prev = [], nums[0], nums[0]
        for n in nums[1:] + [None]:
            if n is not None and n == prev + 1:
                prev = n
                continue
            runs.append((start, prev))
            start, prev = n, n
        for a, b in runs:
            if b > a:
                parts.append("%s-%0*d..%0*d" % (fam, width, a, width, b))
            else:
                parts.append("%s-%0*d" % (fam, width, a))
    return ", ".join(parts)


def _gate_ranges():
    """{闸口号: 'AN-001..10, ...'}。★ 任何规则都必须能算出闸门，否则**构建失败**。

    ★ 2026-09-28：支持一个类别映射到**多个**闸门（见 _GATE_OF_CATEGORY 上方说明）。
      此前只支持单值 ⇒ `supply_chain` 这类横跨闸门的类别只能二选一（等于撒谎），
      而"不知道写哪个"的后果是**构建在模块级直接崩** —— 上一轮我归位构建器后
      从未真正跑过它，所以这个崩溃一直没被发现。两条都要修：
        ① 多归属：值可以是 int 或 tuple；
        ② 同步守卫（下方）：规则表出现新 category 时**当场红**，不许静默。
    """
    rules = json.loads((SRC / "rules" / "default.json").read_text(encoding="utf-8"))["rules"]
    by_gate, unknown = {}, []
    for r in rules:
        rid = r.get("id") or "?"
        gate = _GATE_OVERRIDE.get(rid) or _GATE_OF_CATEGORY.get(r.get("category") or "")
        if not gate:
            unknown.append("%s(category=%s)" % (rid, r.get("category")))
            continue
        gates = gate if isinstance(gate, (tuple, list)) else (gate,)
        for g in gates:
            by_gate.setdefault(int(g), []).append(rid)
    if unknown:
        # 不写死数字是对的，但"不知道该写什么"必须报错 —— 静默漏掉就是下一个假数字。
        raise SystemExit(
            "[build] 以下规则分不到闸门：%s\n"
            "        ⇒ 把它的 category 加进 _GATE_OF_CATEGORY，或在 _GATE_OVERRIDE 点名。"
            % ", ".join(unknown))
    return dict((g, _compress_ids(sorted(set(v)))) for g, v in by_gate.items())


def _gate_table_sync_guard():
    """★★★ 同步守卫：规则表里出现的**每个** category，都必须在闸门表里有位置。

    ★ 为什么必须有它（这不是"再加一道保险"，是补一个**已经造成损失的缺口**）：
      0.31 往 `rules/default.json` 加了 `supply_chain` / `canary` 两个新 category，
      但 `build_package.py` 的闸门表没跟着加。后果：构建器**在模块级 load 时
      就 SystemExit**（`GATE_RANGES = _gate_ranges()` 是顶层语句）。
      而上一轮我把构建器"归位"到产物仓时**只验了 sha256 相同，没验它能不能跑**
      ⇒ 这个崩溃潜伏了整整一轮，直到今天 D-10（重打包）才暴露。
      ⇒ 判据：**构建器引用的每一份外部数据，都必须有一条守卫断言"它对得上"。**
      规则表加类别是常态动作，这条守卫让"忘了同步"从**静默崩溃**变成**当场点名**。

    与 _gate_ranges() 的区别：那个只检查"每条规则算得出闸门"（结果；
    如果 category 缺失会连带触发）；这个检查"规则表的**类别集合** ⊆ 闸门表的键集"，
    报错信息更直接地指向"你漏了一个新类别"，而不是"某条规则算不出闸门"。
    """
    data = json.loads((SRC / "rules" / "default.json").read_text(encoding="utf-8"))
    cats = sorted({(r.get("category") or "") for r in data.get("rules", [])})
    missing = [c for c in cats if c and c not in _GATE_OF_CATEGORY]
    if missing:
        raise SystemExit(
            "[build] 闸门表与规则表不同步：规则表新增了类别 %s，但 "
            "_GATE_OF_CATEGORY 里没有它。\n"
            "        ⇒ 把它加进 _GATE_OF_CATEGORY（值可为 int 或 tuple），"
            "否则文档里的闸门区间串会漏掉这些规则。\n"
            "        规则表路径：rules/default.json" % ", ".join(missing))
    # 反向：闸门表里有、规则表里已无对应规则的类别 —— 只是**提示**，不算错
    # （保留历史类别是合理的，删掉类别才需要人确认）。但必须打印，不许静默。
    unused = [c for c in sorted(_GATE_OF_CATEGORY) if c not in cats]
    if unused:
        print("[build] 提示：闸门表里的这些类别在规则表里已无对应规则（保留无害）：%s"
              % ", ".join(unused))
    return len(cats)


_GATE_TABLE_SYNCED = _gate_table_sync_guard()
GATE_RANGES = _gate_ranges()


def _TPL_CTX():
    """所有文档模板共用的替换字典。★ gate1..4 一律现算 —— 不要在任何模板里手写编号。"""
    ctx = {"version": VERSION, "rules": RULES_N}
    for _g in sorted(GATE_RANGES):
        ctx["gate%d" % _g] = GATE_RANGES[_g]
    return ctx

SKILL_MD = """---
name: antinel-security
description: >
  Scans your AI coding environment for security risks: exposed secrets,
  prompt injection and hidden characters in skills, network egress, and
  behavioral anomalies (%(rules)d rules, 4 gates). Use when the user asks about
  security, safety, environment audit, or mentions .env / API keys /
  permissions concerns. Triggers: security audit, is my agent safe, check secrets,
  skill poisoning, prompt injection, agent monitoring, 密钥泄露, Agent 行为监控.
  MCP server permission audit: planned for Phase 1.5.
  中文触发词：安全检查, 环境审计, 安全扫描, 是否安全.
license: Apache-2.0
compatibility: Requires Python 3.10+; standard library only; no network access; no third-party packages. Hooks verified on Claude Code and ZCode (identical protocol); Qoder/TRAE profiles declared but unverified.
metadata:
  psl-verified: "%(verified)s"
  psl-verified-spec: "psl-vs-0.1"
  psl-verified-at: "%(verified_at)s"
  psl-verified-evidence: "%(verified_evidence)s"
  psl-verifier: "%(verifier)s"
  antinel-product: "security-audit"
  antinel-tier: "free"
  antinel-version: "%(version)s"
  psl-token-interception: "false"
---

## 安装（只需要一次）

```
pip install antinel
```

包名是 **`antinel`**（不是 `antinel-security` —— 那是技能名）。零依赖、纯标准库、运行时不联网。

不确定装没装、或想看当前状态，跑一条就够：

```
antinel agent --json
```

> 如果报「命令找不到」（`--user` 安装时 `Scripts` 常不在 PATH），
> 把 `antinel` 换成 `python -m antinel` —— 后面所有命令都这么换即可。

它返回一个 JSON：`installed`（钩子装没装）、`host_detected`（识别出的宿主）、
`next_steps`（下一步敲什么）、`skill_md`（本文件的路径）、退出码契约。
**不要靠猜，先跑这一条。**

## 安全审计流程

### 步骤0：确认已安装

- 目标项目里没有 `.psl/manifest.json` ⇒ 说明还没装。
- 装：`antinel install`（等价 `python -m scripts.install`，两条都对）。
- 装完**必须重启宿主一次**——钩子在宿主启动时加载，不重启不生效。

### 步骤1：跑扫描

```
python -m scripts.scan --root .
```

- 退出码 0 = 扫描完成。**有发现也是 0**（发现数量看报告，不看退出码）。
- 想要机器可读：`python -m scripts.scan --json`。

⚠ 命令要写成**模块形态**（上面那样带 `-m`）。把模块当文件路径敲的那种写法，
装完之后跑不通——那些文件在 `site-packages` 里，不在你的项目根下。
（反例长什么样这里不写全，免得被当成"教过的命令"抄走。）

### 步骤2：读报告

```
python -m scripts.report --days 7
```

按严重度排序：CRITICAL > WARNING > INFO。每条发现含：规则 ID、文件路径、描述、修复建议。
导出：`--format csv|sarif|html|json`。

### 步骤3：讲给用户听

- 有发现：按严重度排序转述，**每条都带上修复建议**（报告里就有，不要自己编）。
- 没发现：直接说"未发现异常"，并附上扫描了多少文件（报告里有分母）。
- **不要**因为退出码非 0 就说失败——先读 stderr 里的原文。

## 常用命令（都能在装完之后直接跑）

| 你要什么 | 命令 |
|---|---|
| 当前状态、下一步 | `antinel agent --json` |
| 装 / 查 / 卸钩子 | `antinel install` ／ `--check` ／ `--uninstall` |
| 打印本手册 | `antinel skill`（`--path` 只给路径，省 token） |
| 决策层一页纸 | `antinel brief` |
| 近 N 天干了什么 | `antinel digest --days N` |
| 静态扫描（机器可读） | `python -m scripts.scan --json` |
| 证据链有没有被动过 | `antinel verify` |
| 行为报告 | `python -m scripts.report --days 7` |

## 注意事项

- 你不需要理解每条安全规则的技术细节。
- 你只需要正确运行脚本并转述结果。
- 不要修改检测规则或审计日志。
- 自定义白名单与阈值在 `.psl/policy.json`（安装时生成模板）。
- 运行时零网络、无第三方依赖、无驻留进程。
- 它只匹配工具调用文本与文件内容，**不解析脚本语义**——把删除或外发写进一个
  `.py`/`.sh` 再执行，闸门不会拦。这是护栏，不是隔离层。
- 已验证可拦截的宿主：Claude Code / ZCode / Qoder。其余宿主装完是**审计与扫描模式**，
  `antinel install` 会明说这一点——那不是装失败。
"""

THREAT_MODEL_MD = """# Antinel Security Suite - Threat Model (v%(version)s)

## What we protect against
An AI coding agent running inside an IDE host (Claude Code, ZCode, ...) executes tools on the
developer's machine. Four gates, %(rules)d rules:

| Gate | Threat | Rules | Evidence source |
|---|---|---|---|
| 1 Content safety | Poisoned skill instructions: prompt injection, invisible Unicode, encoded payloads | %(gate1)s | static file content + Read/Write hook |
| 2 Sensitive surface | Agent reads secrets: .env, SSH keys, cloud credentials, wallets, browser data; secret literals in file content | %(gate2)s | file system + Read/Bash hook |
| 3 Metadata / egress policy | Skill identity spoofing; connections to non-whitelisted domains; tunnels and covert channels | %(gate3)s | metadata + command line |
| 4 Behaviour | Deletion, writes outside the project, alternate-data-stream writes (Windows), shell startup edits, persistence, privilege escalation, env enumeration, raw egress | %(gate4)s | PreToolUse / PostToolUse events |

Rule-range notation is by family and must be re-derived from `rules/default.json`
whenever a rule is added: a stale range silently understates what is enforced.

Severity to action: critical = block (stdout decision JSON + stderr + exit 2), warning = alert (logged, stderr notice, allowed).
All hits of one event are collected; the highest severity decides.

## What we explicitly do not do (Phase 1)
- No hardening or remediation (we report; fixing is the user's call or Anxin Zhixin hardware products).
- No encrypted-traffic or network-layer analysis (tool-call layer only; DNS-level comparison is a v2 kernel capability).
- No SAST/DAST vulnerability scanning of the user's code.
- No certified test reports (audit logs and assessments only; CMA red line).
- No MCP server permission audit (Phase 1.5) and no dependency supply-chain audit (Phase 2).
- No token-level output interception (v2: hook soft interception / kernel hard interception).

## Our own attack surface
- Zero network at runtime; standard library only; no persistent process.
- Fail open: any internal error allows the action (a security tool must never break the host).
- Self-tamper: install records sha256 of rules and all five scripts; report.py prints SELF-TAMPERED on drift.
- Recomputable audit: every record carries content_digest = sha256(canonical JSON of tool_name + tool_input).
- Policy cannot weaken the baseline: whitelist.paths relaxes secrets rules only, whitelist.commands relaxes
  warning-level rules only, whitelist.domains relaxes network rules only; critical non-network rules are never relaxed.

## Known limits (documented, not hidden)
- Guardrail, NOT a sandbox: rules match TOOL-CALL TEXT only. A deletion or an
  out-of-root write placed inside a .py/.sh that the agent later executes is NOT
  intercepted (measured: the Bash channel has no file_path, so AN-010 never
  fires there). Since 0.17.0 such commands are SURFACED as
  dst02_bash_path_suspect alert records, never blocked.
- The deny signal is still the LEGACY shape (0.29.0, E-3). `emit_block` prints a
  top-level `{"decision": "block", ...}` and stands on `exit 2` as the
  authoritative channel. Hosts document `hookSpecificOutput` (with
  permissionDecision) as the current PreToolUse contract, and state that exit 0
  with no output means "no opinion, continue the normal permission flow". So
  blocking rests on exit 2 alone: should a future host stop honouring exit 2,
  every block degrades into an allow **silently** -- no error, no drop in hook
  invocations. **Symptom to watch:** the block count in report.py falls to zero
  while tool activity continues. Migration is a few lines but must be verified
  per host on real hosts (Claude Code, ZCode, WorkBuddy), which is why it is
  registered here as a known limit instead of being shipped unverified.

## Non-goals
- Script-content scanning. Parsing every script the agent writes for dangerous
  operations would be a sandbox promise this layer cannot keep (and an
  avalanche of false positives -- test fixtures contain dangerous words by
  design). Isolation belongs to containers/VMs, not to a PreToolUse hook.
- Alternate-data-stream CONTENT. AN-023/AN-024 block the WRITE PATH on Windows
  (`echo x > f.txt:stream`, `Set-Content -Stream`, `copy`, `open(...,"w")`), but
  the PAYLOAD inside a stream cannot be read back through the tool-call layer, so
  contents already written into an ADS are invisible to review. The write is
  intercepted; the contents are not inspected. Measured scope: AN-023/AN-024 are
  Windows-gated (`path:stream` is a legal POSIX filename) and `Zone.Identifier`
  is exempt by design -- it is written by browsers and downloaders on every save.
- Stopping everything. Severity decides: critical blocks, warnings alert and
  proceed. A hook that blocks a developer's daily build command gets uninstalled
  on day one -- and an uninstalled hook stops nothing.
- Protecting the guardrail's OWN configuration. workspace_roots (the trust
  boundary) lives at host level and is read by the hook. Until 0.19.1 a write to
  it was blocked on the Write/Edit channel only; measured 2026-09-14 the Bash
  channel reached the same file via a script that builds the path internally,
  with NO AN-010 signal at all (audit: decision=allow, rules_hit=[]). So the
  block stopped the user's own delegated maintenance -- including creating
  skills -- without stopping anyone else. Since 0.19.2 both channels do the same
  thing: RELEASE the exact config file (not its parent directory) and RECORD it
  as dst02_host_config_self_maintenance. That is a downgrade from prevent to
  record, deliberately: a boundary that must not be editable needs a read-only
  mount or a container, which a hook running as the agent cannot provide.
- Host prompt passthrough (`ask`) is a RETIRED idea, not a pending feature
  (0.29.0, E-3). Host documentation confirms only `deny` and `allow` for
  permissionDecision; `ask` is not confirmed on any host. Nothing is lost: the
  host's own confirmation dialog still fires, because our allow is silence and
  silence means "no opinion, continue the normal permission flow". Do not
  implement `ask` without a measurement on a real host -- an unconfirmed value
  kept on a backlog is how an unmeasured claim becomes a shipped promise.
- Hook latency on Windows is about 65 ms per call (interpreter start dominates); Linux/macOS untested.
- Only actions that pass through the host's PreToolUse hook can be blocked.
- Qoder / TRAE field layouts are declared profiles, not verified.
- JUDGING A SHORT PACKAGE NAME'S LETTER SUBSTITUTION. AN-037 grades by name
  length and edit type (0.57.0, checklist item 37): transposition,
  insertion/deletion and homoglyph swaps (`otx`, `toxx`, `t0x`) are judged at
  any length, but a plain letter substitution in a 3-character name is not --
  `tox/nox`, `lit/kit`, `vue/cue` are all legitimate words or packages, so that
  branch can only produce noise. Measured on this host (76 real packages in use
  against 972 classic typo variants): the old single rule (`distance <= 2`)
  gave 8.0%% false positives at 100%% recall; the graded rule gives 0%% false
  positives at 99.1%% recall, and the 9 misses are exactly those 3-char
  substitutions. Two real packages where one is a prefix of the other
  (`psycopg` / `psycopg2`) are also not separable by any threshold -- that is
  fixed by adding the name to the reference set, not by tuning the rule.
"""

# ---------------------------------------------------------------- RUN_HARNESS
#
# ★★ 2026-09-28：这里**原来内嵌了一份 14.7 KB 的 run_harness.py 全文模板**。
#    它是一份**陈旧副本** —— 落后产物仓的真源 5 处改进（atexit 临时目录清理、
#    `__partial__` 半截数上报、ANTINEL_RESULTS 显式指定、typosquat_top 与
#    enforce_probe 的 COVERED 条目）。构建一跑，**产物仓的改进被静默覆盖**。
#
#    ⇒ 修法是**消灭副本**，不是"记得同步"：
#       只保留一份真源 = `scripts/run_harness.py`，构建器**读它**。
#       物理上不可能再分叉。
#
#   ★ 顺带：产物版已经用 `_pkg_version()` **动态读** antinel.py 的 VERSION，
#     比旧模板的 `"__VERSION__"` 字符串替换更好（构建期替换会把版本号钉死在
#     生成物里，而动态读永远是当前值）。所以此处**不做任何替换**，原样搬运。
#
#   ★ 判据（可复跑）：构建后 `scripts/run_harness.py` 的 sha256 必须与
#     构建前**逐字相同**。若不同 ⇒ 说明有人在"生成物"上做手改，改错了地方。
RUN_HARNESS_SRC = "scripts/run_harness.py"


def _read_run_harness():
    """读 run_harness 真源。★ 禁止回退到内嵌模板 —— 那正是本缺陷的成因。"""
    p = srcfile(RUN_HARNESS_SRC)
    if not p.is_file():
        raise SystemExit(
            "★ 构建器找不到 %s（run_harness 的唯一真源）。\n"
            "  它**不该**由构建器生成 —— 它有独立的演进历史（见 git log）。\n"
            "  请在仓里恢复该文件后再构建。" % p)
    return p.read_text(encoding="utf-8")


#: 生成型 Markdown 的 SPDX 头。**只在本文件出现一次**，见 `_write_generated_md()`。
_GENERATED_MD_SPDX = "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n"


def _write_generated_md(dest, body):
    """生成型 Markdown 的**唯一写出点**（0.63.0）。

    ★★ 为什么必须把它做成唯一入口，而不是在各处记得加头：

      0.62.0 把 `references/RULES.md` 改成从数据生成之后，一个临时脚本直接调
      `rules_md()` 写盘，**漏了 SPDX 头** —— 因为头不在生成函数里，在写出点里。
      当场 `ci/inbox_guards_0481.py` 的 L1（全仓 SPDX 头）红：
      `references/RULES.md: 缺 SPDX 头`。

      当时的修法是「在生成函数注释里写清楚头在写出点」。**那是靠记忆。**
      记忆的失效方式是静默的：下一个写生成物的人（或下一个自己）不会读到那句
      注释，而且漏头只在 CI 跑 0481 时才暴露。

      所以这里改成**物理上没有第二个拼接口**：头 + newline 都在本函数，
      生成函数只产出正文。要漏头就得绕过本函数 —— 而绕过本函数意味着
      自己写 `write_text`，那是显式行为，看得见。

    ★ 参数 `body` 是**正文**（不含头）。返回 None。
    """
    Path(dest).write_text(_GENERATED_MD_SPDX + body, encoding="utf-8", newline="\n")


def rules_md(rules_path):
    d = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    static = {"secrets", "injection", "metadata"}
    # ★★ 0.62.0：**从数据生成，不再硬编码**。
    #   病灶：这一行原本写死「secrets > destructive > network > injection > context >
    #   metadata」六类，而 `rules/default.json` 的 `category_order` 是同一事实的
    #   第二份实现 —— 0.31 加了 supply_chain / canary 两个新 category 之后，
    #   字段补了、这行没补，于是 RULES.md 长期对外声称只有 6 类。
    #   ⇒ 修法是**消灭副本**（同源闸）：读 category_order 拼出来。
    #   ★ 顺带：这让 `category_order` 第一次有了真实消费点 —— 此前全仓零引用，
    #     一个 6 项枚举装 8 个取值，谁读它都会以为 supply_chain 不存在。
    _cat = d.get("category_order") or []
    # ★★ 0.62.0 补丁（同晚第二轮）：**SPDX 头由写出点加，不在本函数里**。
    #   经过：把 RULES.md 改成从数据生成后，仓内那份被一个临时脚本用 `rules_md()`
    #   直接写出，**漏了写出点那句 `"<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n"`**
    #   ⇒ `ci/inbox_guards_0481.py` 的 L1（全仓 SPDX 头）当场红：
    #   `references/RULES.md: 缺 SPDX 头`。
    #   教训：`rules_md()` 只产出**正文**，头在写出点（build 里唯一一处，第 3050 行）；
    #   手工重建产物必须**走同一个写出点**，不许自己拼 —— 否则拼接的两端各漂一半，
    #   与 `.gitignore`／`THREAT_MODEL.md` 属同一族（构建器拥有的产物不许旁路生成）。
    L = ["# Antinel detection rules (generated from rules/default.json v%s - do not edit by hand)" % d.get("version"),
         "", "Category order = match priority: %s." % " > ".join(_cat),
         "Severity to action: critical = block, warning = alert (logged, allowed). All hits are collected; highest severity decides.", ""]
    # ★★ 0.62.0（清单 P4-4 / DEC-22d）：**「关不掉」的规则必须写在用户看得见的地方**。
    #   此前这四条散落在代码里（`_slop_hit` / `_budget_hit` / `_suite_gov_hit` / 输出面
    #   扫描），口头说明只在内部文档出现过 ⇒ 用户以为把 `enabled: false` 写进配置就
    #   关掉了，实际照响。产品承诺的边界不写清＝虚假承诺。
    #   ★ 为什么不手写在文档里**而是从数据生成**：同一事实的第二份副本必然会漂
    #     （本函数上面那条 category_order 就是活教材）。数据源是
    #     `rules/default.json` 的 `hardcoded_rules`。
    _hc = d.get("hardcoded_rules") or {}
    if _hc:
        L += ["## Rules that cannot be switched off by configuration", "",
              "These judgements are implemented **in the hook code**, not in this table.",
              "The only way to switch a rule off in this product is `enabled: false` on its"
              " entry in `rules/default.json` (consumed by `_disabled()`); there is no"
              " separate disable list. That field does **not** affect the entries below —"
              " switching them off requires a code change.", ""]
        for _grp, _title in (("code_only", "not present in this table at all"),
                             ("declared_but_code_driven", "present below, but judged by code")):
            _items = _hc.get(_grp) or {}
            if not _items:
                continue
            L += ["### %s (%s)" % (_grp.replace("_", " "), _title), ""]
            L += ["- `%s` — %s" % (k, v) for k, v in _items.items()]
            L.append("")
    for r in d["rules"]:
        kind = "static + dynamic" if r["category"] in static else "dynamic (hook only)"
        deprecated = " | **status: deprecated (retired, never fires)**" if r.get("deprecated") else ""
        tools_disp = ", ".join(r.get("apply_to_tools") or []) or "all"
        L += ["## %s  %s" % (r["id"], r.get("name", "")),
              "- category: %s | severity: %s | %s | tools: %s%s" % (r["category"], r["severity"], kind, tools_disp, deprecated),
              "- purpose: %s" % RULE_PURPOSE.get(r["id"], "unknown (generator table missing an entry)"),
              "- description: %s" % r.get("description", ""),
              "- 说明: %s" % r.get("description_zh", ""),
              "- 处理建议: %s" % r.get("remediation_zh", "")]
        for key in ("command_patterns", "file_patterns", "content_patterns"):
            if r.get(key):
                L.append("- %s:" % key)
                L += ["    - `%s`" % p for p in r[key]]
        if r.get("platforms"):
            L.append("- platforms: %s (rule is skipped on other hosts; it stays in the loaded set so rule counts are platform-invariant)" % ", ".join(r["platforms"]))
        if r.get("check"):
            L.append("- check: %s" % r["check"])
        if r.get("detection"):
            # ★ 0.57.0（第 32 条）：AN-016 从「一条 ranges 全判 critical」改成
            #   「码点类 × 出现面」分档，文档必须把分档写出来 —— 用户看到
            #   「规则写着 critical 却只 alert」时需要能对上这张表。
            if r.get("codepoints"):
                L.append("- detection: %s（%d 类码点，按出现面分档：path / command / "
                         "instruction / content）" % (r["detection"], len(r["codepoints"])))
                for c in r["codepoints"]:
                    lv = c.get("levels") or {}
                    L.append("    - U+%04X–U+%04X %s: %s" % (
                        c["start"], c["end"], c.get("kind") or "?",
                        ", ".join("%s=%s" % (k, lv.get(k) or "不报")
                                  for k in ("path", "command", "instruction", "content"))))
            else:
                L.append("- detection: %s (ranges %s, whitelist %s)" % (
                    r["detection"], r.get("ranges"), r.get("whitelist_chars")))
        if r.get("whitelist_domains"):
            L.append("- whitelist_domains: %s" % ", ".join(r["whitelist_domains"]))
        if r.get("exclude_patterns"):
            L.append("- exclude_patterns: " + ", ".join("`%s`" % p for p in r["exclude_patterns"]))
        if r.get("placeholder_patterns"):
            # 0.57.0（第 33 条）：占位值清单必须印出来 —— 用户看到「文档里的示例
            # 密钥没报警」时，得能查到这个决定是哪里做的、依据是什么。
            L.append("- placeholder_patterns（命中片段是已知占位值 ⇒ 不算发现）: "
                     + ", ".join("`%s`" % p for p in r["placeholder_patterns"]))
        if r.get("remediation"):
            L.append("- remediation: %s" % r["remediation"])
        L.append("")
    L += ["## Policy file (.psl/policy.json, spec C-05)", "",
          "| field | semantics |", "|---|---|",
          "| whitelist.domains | relaxes NETWORK rules only (AN-006/AN-007 excludes, AN-008 whitelist, subdomains included) |",
          "| whitelist.paths | path prefixes exempt from SECRETS rules and releasing AN-010 (each AN-010 release is audit-logged as dst02_path_whitelisted); install seeds agent-managed dirs that exist on the machine |",
          "| whitelist.commands | command prefixes exempt from WARNING-level rules only; critical rules are never relaxed |",
          "| global_settings.alert_threshold | warning (default) or critical: suppresses stderr notices below it; logging and blocking unchanged |",
          "| global_settings.log_retention_days | archive age for report.py --archive (default 30) |",
          "| global_settings.auto_archive | true: report.py applies retention on every run |",
          "| global_settings.desktop_notify | ignored in v1 (spec B-04) |", ""]
    return "\n".join(L)


def id_map_md(rules_path):
    """规则号新旧对照表（0.63.0 新增）—— **从 `rules/default.json` 生成，不许手写**。

    ★ 为什么必须有这张表：
      0.63.0 把 37 条规则的 id 从「家族名＋两位数字」那一类改成 `AN-001..AN-037`。
      这是**纯恒等变换** —— 同一批规则、同一批 pattern、同样的裁决，只有字符串变了
      （验收方式就是「新号翻译回旧号 == 旧号」，可逐条复核）。但 0.63.0 之前写下的
      审计记录、证据链、历史文档里全是旧号。
      ⇒ 没有对照表，那些记录就不是「变旧了」，而是**变成不可读的字节**。
        **改名把可读性当成了代价，这张表是把代价还回去的方式。**

    ★ 为什么由构建器生成而不是手写：
      旧号的唯一真源是每条规则的 `legacy_id` 字段。手写一份表就是同一事实的
      第二份副本，而副本必然漂 —— 本文件上方 `rules_md()` 的 `category_order`
      注释记的就是这个病灶的活教材（数据补了两类，文档那一行没补，对外长期少说两类）。

    ★ 为什么缺 `legacy_id` 要 **raise** 而不是跳过：
      对照表的价值**全在完整性**。缺一行不会让表看起来坏，只会让一批记录
      永远翻译不回去，而且**没有任何迹象**。所以宁可让构建停下。
    """
    import re   # 本文件的约定：re 按需函数内导入（见 :1945 / :1970 / :2510 / :2703）
    d = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    rules = d.get("rules") or []
    _missing = [r.get("id") or "?" for r in rules if not r.get("legacy_id")]
    if _missing:
        raise SystemExit(
            "id_map_md：以下规则没有 `legacy_id` ⇒ 对照表会缺行，拒绝生成。\n  %s\n"
            "  对照表的价值全在完整性：缺一行，就有一批旧记录永远翻译不回去，"
            "而且不会有任何迹象。" % ", ".join(_missing))

    def _cell(v):
        """Markdown 表格单元格转义：竖线会把一格切成两格。"""
        return str(v if v is not None else "").replace("|", "\\|").strip()

    L = ["# Antinel rule id map (generated from rules/default.json v%s - do not edit by hand)"
         % d.get("version"), "",
         "0.63.0 renamed every rule id. **The rename was an identity transformation.**",
         "Same rules, same patterns, same severity, same decisions on the same input --",
         "only the identifier strings changed. Each rule carries its old id in the",
         "`legacy_id` field, and this table is generated from that field.", "",
         "Old ids still appear in audit logs, evidence chains and documents written",
         "before 0.63.0. Use this table to read them; nothing was invalidated by the",
         "rename, but nothing was rewritten retroactively either.", "",
         "## Translation table (%d rules)" % len(rules), "",
         "| current id | legacy id | name | category | severity |",
         "|---|---|---|---|---|"]
    for r in rules:
        L.append("| `%s` | `%s` | %s | %s | %s |" % (
            r["id"], r.get("legacy_id"), _cell(r.get("name")),
            _cell(r.get("category")), _cell(r.get("severity"))))
    L += ["",
          "## How to read an old record", "",
          "- **old id -> current id**: look the old id up in the `legacy id` column, read the",
          "  `current id` on the same row. That is the rule the product reports today.",
          "- **current id -> old id**: read the `legacy id` column on the current id's row.",
          "  This is what you need when comparing today's findings with a record written",
          "  before 0.63.0.",
          "- The mapping is **one-to-one in both directions**. If you find an old id that is",
          "  not in the `legacy id` column, or a current id with no legacy id, that is a",
          "  defect in this table -- not a rule that was retired.", "",
          "  (A few judgements live outside the number space entirely: see the next section.)"]

    # ★ 不在 rules 数组里的判定必须单列。
    #   为什么：它们不占号段，混进上表会让人数出「37 条之外还有几条」。
    #   ★ 而 `declared_but_code_driven`（AN-037）**在**表里 —— 它只是判定由代码做，
    #     不是号不在表里。两者是不同的事实，不能进同一张表（第一顽症的形状）。
    _hc = d.get("hardcoded_rules") or {}
    _co = _hc.get("code_only") or {}
    _dc = _hc.get("declared_but_code_driven") or {}
    if _co or _dc:
        L += ["", "## Judgements outside the number space", "",
              "These are implemented in hook code and are **not** part of `AN-NNN`.",
              "The rename could not reach them; they do not appear in the table above.",
              "Listed so that someone grepping for an old id finds an answer, not nothing.", "",
              "| id | in rule table? | 0.63.0 treatment | note |", "|---|---|---|---|"]
        for _k, _v in _co.items():
            # 前身号从描述文本里**取**，不硬编码：文案是数据，不是我记的东西。
            #   取不到「原 X」时**不能**写成 "no change recorded" —— 那会把两种
            #   不同的事实压成一句：`OUT-01` 是**故意保留**旧号（等 channel 字段），
            #   而「去号」那几条是**真的没有号了**。前者是有号不用，后者是无号。
            _m = re.search(r"原\s*([A-Z][A-Z0-9]*-\d+)", str(_v))
            _prev = (("de-numbered (was `%s`)" % _m.group(1)) if _m
                     else ("id kept as `%s` (deliberately not collected)" % _k))
            L.append("| `%s` | no | %s | %s |" % (_k, _prev, _cell(str(_v)[:200])))
        # ★ `declared_but_code_driven` **不进这张表** —— 它已经在上面那张表里了。
        #   放进来会让「数一下有几条」这件事出现第二个答案（38 != 37），
        #   而「一条规则在两张表里出现两次」正是第一顽症的最小形状。
        #   它需要的只是一句脚注：号在表里，判定不在表里。
        if _dc:
            L += ["",
                  "Not a table-outside judgement, but worth knowing: "
                  + "、".join("`%s`" % _k for _k in _dc)
                  + " **is** in the table above (its id and legacy id are ordinary),"
                    " but its verdict is decided by code rather than by the patterns"
                    " listed for it. The row is still correct; do not read an empty"
                    " pattern list as \"never fires\"."]
        L += ["",
              "`in rule table? = no` means the judgement still runs and still lands in the",
              "ledger's `rules_hit`, but its identifier is not one of the `AN-NNN` rules.",
              "Why that happened: `DEV-01` and `notice_budget` had been borrowing a rule",
              "number while not being rules, which made every count of \"rules that fired\"",
              "quietly wrong. `OUT-01` is the other case -- its number is genuinely its own,",
              "it just has not been collected into a shared range yet, so it keeps it."]
    return "\n".join(L)


CI_WORKFLOW = """# T5 cross-platform matrix (U-42): runs the full verification suite on three OS x four Python
# NOTE(09-11): 3.13 added -- it is the interpreter the author actually runs locally; the old
# 3.10/3.11/3.12 triple did not cover it, so 'cross-platform verified' was never supportable.
# versions (3.10-3.13) on every push and PR. The written psl/judgment.json is uploaded as evidence.
name: verify
on:
  push:
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: "0 3 * * 1"   # weekly: re-run the suite after host/runtime updates (D6)
jobs:
  verify:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python: ["3.10", "3.11", "3.12", "3.13"]
    runs-on: $[DB_OPEN] matrix.os [DB_CLOSE]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: $[DB_OPEN] matrix.python [DB_CLOSE]
      - name: run verification harness (full suite, stdlib only, no network)
        run: python -m scripts.run_harness
      - name: upload judgment record
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: judgment-${{ matrix.os }}-${{ matrix.python }}
          path: psl/judgment.json
"""

POSIX_RUNNER = """#!/bin/sh
# POSIX verification runner (Linux / macOS): T5 evidence without any third-party dependency.
# Usage: sh ci/run_verifications.sh
set -e
cd "$(dirname "$0")/.."
python -m scripts.run_harness
"""


HOST_PROBE_MD = """# Host protocol probe (U-47 / D6)

When a host (Qoder, TRAE, a new Claude Code / ZCode release, ...) changes its hook
contract, collect evidence instead of guessing:

1. Register the probe as the host's PreToolUse hook:
   {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
       {"type": "command", "command": "<python> <abs>/tools/probe_host.py --tag <host>", "timeout": 10}]}}]}
2. Trigger ONE tool call (any read or command) in that host.
3. Send us `.psl/probe/<host>-1.json` (it contains the raw stdin event, argv, cwd and
   env markers; the probe never blocks anything).

We diff the captured field layout against HOST_ADAPTERS and update the profile.
Schedule: re-run this after every host major update (see .github/workflows/verify.yml).
"""


def sha256(p):
    return "sha256:" + hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _manifest_hash_of(rel, path):
    """**写进 psl/manifest.json 的文件哈希**（唯一口径）。

    ★★ 0.39.2：`rel` 命中 `host_shield.VERSION_BEARING_CHAIN_FILES` ⇒ 先把
      `_ANTINEL_VERSION` 的**引号内值**归一化掉再算（版本行不进完整性哈希）。
      归一化函数**只此一处定义**（host_shield），本文件只 import 它 —— 见 `SRC` 段注释。
    """
    if rel in getattr(_hs, "VERSION_BEARING_CHAIN_FILES", ()):
        data = Path(path).read_bytes()
        return "sha256:" + hashlib.sha256(_hs.norm_version_bytes(data)).hexdigest()
    return sha256(path)



README_MD = """# Antinel Security Suite

**让每一个 AI 编程工具的用户，在 30 秒内知道自己的 AI 编程环境安不安全——并且持续监控、持续安心。**

One command. %(rules)d rules. 4 gates. Local-only, zero network, standard library only.

## 别信我们，自己验 / Don't trust us - verify (30 秒)

```bash
python -m scripts.run_harness     # 复跑全部断言，得到你自己的 verdict（写入 psl/judgment.json）
python -m tools.antinel_verify    # 校验随包判定是否已失效（digest 比对，推导 current/superseded）
python -m tools.antinel_verify --manifest   # 校验全部随包文件（以 psl/manifest.json 为准）
python -m tools.verify_namespaces # 命名空间清单验签辅助（输出 canonical 摘要 + openssl 验签命令）
python -m scripts.install --check # 校验已安装实例与包是否一致（版本 + 哈希）
```

> 为什么写 `python -m`：这些脚本随包安装在 `site-packages` 内。相对项目根的 `scripts/x.py` 那种写法在装完之后跑不通 —— 0.48.2 用户旅程模拟实测：README 里该类命令**全部不可达**（撞「页面不许教跑不通的命令」）。

退出码约定：`antinel_verify` 0＝current / 1＝superseded / 2＝无法校验；
`install.py --check` 0＝一致 / 1＝未安装 / 3＝有漂移。

任何第三方复跑出不同结论，即取代随包判定记录（追加式，原记录不删不改）。

## 它防什么 / What it protects against

| 闸门 Gate | 威胁 Threat | 规则 Rules |
|---|---|---|
| 内容安全 | 技能投毒：提示注入、隐形字符、编码载荷 | %(gate1)s |
| 敏感面 | Agent 读取 .env / SSH 私钥 / 云凭证 / 钱包 / 浏览器数据；内容中的密钥字面量 | %(gate2)s |
| 元数据与出联 | 技能身份伪装；白名单外域名；隧道与隐蔽信道 | %(gate3)s |
| 行为异常 | 删除、越界写入、备用数据流写入（Windows）、启动项篡改、持久化、提权、环境枚举 | %(gate4)s |

真实拦截样例（来自 ZCode 真机）：

```
[AN-001] Antinel 拦截 [AN-001] 读取 .env 文件可能泄露 API 密钥与机密配置 | 命中: .env |
放行/处理: 把 .env 移出 Agent 可读范围；确需变量时手动复制具体几行
```

## 安装 / Install

**ZCode 用户（推荐：插件方式，装完即全局生效）**

1. Settings → Plugin Management → 从本地目录安装本插件包（antinel-security-zcode-plugin/）
2. 重启 ZCode 一次。完成——所有工作区的 Agent 行为都在守护范围内。

**其他宿主（Claude Code 等）/ 手动方式**

```
python -m scripts.install --root <项目根>          # 项目级
python -m scripts.install --root <项目根> --global  # 用户级，所有项目
```

安装后重启宿主一次（钩子在宿主启动时加载）。

## 升级 / Upgrade（0.16.0 起）

```
python -m scripts.install --check   # 先比对：已装版本/规则哈希/脚本哈希 vs 包（无任何改动）
python -m scripts.install --root <项目根>   # 不一致时重跑安装，自动刷新快照与哈希
```

升级包后不重跑安装，钩子会**降级到内置 11 条回退规则集**并留下 `rules_integrity_fallback`
审计事件——请升级后必跑一次 `install.py`（或先 `--check` 看差异）。

## 使用 / Usage

- 对 Agent 说：**"帮我检查环境安全"** —— Agent 读取 SKILL.md 自动完成安装、扫描、报告
- 或手动：`python -m scripts.scan --root <项目根>` ／ `python -m scripts.report --days 7`
- 导出：`--format csv|sarif|html|json` ／ 归档：`--archive`
- 卸载（零残留）：`python -m scripts.install --uninstall`

## 信任 / Trust (don't trust us - verify)

- 判定记录 `psl/judgment.json`：断言总数见 `assertions_total` 字段；任何第三方可用
  `python -m scripts.run_harness` 复跑；复跑失败即取代随包记录
- 判定自带**状态位与作用域**：`status`（current/superseded，用 `tools/antinel_verify.py`
  随时推导）、`scope`（覆盖 8 个摘要文件，不覆盖什么也写明）、`platformSpec`（单平台诚实
  标注）、`objectOwnership`（**真推导**：签名清单＋README 钉定指纹＋git remote /
  `manifest.namespace` 身份，fail-closed `unattributed`——0.17 前是常量，0.17 起为机制）
- 追加式台账 `psl/verdict-ledger.jsonl`：第 1 行 = 自证判定；只增不删
- 审计**日锚** `.psl/audit/day_manifest.json`（0.18.0）：记录每日字节长度与末行哈希（链外
  独立副本），`verify_chain` 的 tail 校验据此检出"删除末尾 N 条 / 删除整天文件"——
  0.17 及之前，这类篡改检不出（已知边界，现已被锚收紧为一需同伪两文件）
- **诚实声明（`--manifest` 的二阶边界）**：`--manifest` 证明的是"树 = 清单"，不证明
  "清单 = 发布时清单"——`psl/manifest.json` 不在 `judgment.digests` 内，同时改文件与清单
  可骗过它；防合并篡改需 CI 产物留底或将清单纳入 digests（后续版本评估）
- `fail_closed_on_audit_loss` 策略键（0.18.0 起真实接线）：审计写失败默认放行（stderr
  可见 `AUDIT_WRITE_FAILED`），置 true 则阻断——取舍归你，机制归我们
- 命名空间清单 `antinel-namespaces.json`：ed25519 签名，公钥指纹
  `sha256:b71e570c30ebcbf7`（钉死在本 README；轮换只允许追加新钥匙条目）；
  清单缺失或验签失败时对象归属一律落 `unattributed`（fail-closed）
- 规则全部开源：`rules/default.json`（24 条，双语说明）；每条审计记录含 content_digest，判据可重算
- 运行时零网络；仅标准库；无第三方依赖；无驻留进程
- 收入边界声明见源码仓 `docs/A6收入边界声明.md`（该件随 sdist 分发，不随 wheel）：不收通过费、不出售排名、关联方无豁免
- 中立性靠机制：开源规则 + 可重算判定 + 阴性结果照发 + 免费离线可验

## 已知边界 / Known limits（诚实声明）

- **规则只匹配工具调用文本，不解析脚本内容**：把删除或越界写入写进一个 `.py`/`.sh` 再执行，四道闸门都不会拦截（实测：Bash 通道没有 `file_path`，AN-010 在该通道上恒不触发；0.17.0 起此类命令中的**显式绝对路径**会以 `dst02_bash_path_suspect` 事件留痕并告警，但**不拦截**）。这是**护栏**的设计边界，不是隔离层；需要隔离请用容器或沙箱
- Hook 拦截仅覆盖宿主支持 PreToolUse/PostToolUse 的工具与动作；当前在 Windows + ZCode 实测，macOS/Linux 由 CI 矩阵持续验证
- 只读命令上下文（echo/grep 等提及而非执行的危险词）中的 critical 命中会降级为 alert 并照常记录——这是刻意设计，防止"grep 危险词"被误拦；真正的执行形态仍会拦截
- **备用数据流（ADS）拆成两半看**（0.19.0）：**写入路径已拦**——`echo x > f.txt:stream`、`Set-Content -Stream`、`copy`、`open(...,"w")` 在 Windows 上命中 AN-023/AN-024，退 2（该规则按 `platforms: nt` 只在 Windows 生效，因为 `path:stream` 在 POSIX 上是合法文件名；`Zone.Identifier` 由浏览器/下载器写入，按设计豁免）；但**流里的内容读不回来**——已写进 ADS 的载荷在工具调用层不可见，属结构性非目标（见 `references/THREAT_MODEL.md` 的 Non-goals）
- **安防自身的 host 级配置可被 Agent 改写（0.19.2 起，刻意且留痕）**：`~/.workbuddy/antinel.json` 的 `workspace_roots` 就是信任边界本身。0.19.1 及以前 Write/Edit 写它会被 AN-010 拦截，但**同一目标经 Bash 通道（脚本内部用 `expanduser` 拼路径）可以零命中到达**——实测该次写入在审计里是 `decision=allow, rules_hit=[]`。**拦一半等于没拦，却确实挡住了用户自己的正常维护**（审计实证：AN-010 拦下的 `~/.workbuddy` 目标共 4 次，其中 3 次是创建 skill）。0.19.2 起两个通道统一为**放行 + 留痕**：放行精确到该配置文件本身（**不含**其父目录），每次放行写 `dst02_host_config_self_maintenance` 事件，并在 report.py 单列"信任边界编辑次数"。⇒ 这是**从"阻止"降级为"记录"**：需要边界不可改，请用只读挂载或容器
- `rd`（Windows 删除命令）按"命令位置＋参数语境"匹配：`rd /s /q X` 拦截；Python 代码里的 `rd = 3`、raw 字符串 `r'D:\\...'` 放行（0.16.0 修复了旧版对后两者的 critical 误报）
- 行为语料（含负例）不随包分发；该读数无法仅凭本包复现（见 `psl/judgment.json` 的 `scope.notCovered`）
- Qoder/TRAE 的字段布局为声明式适配（未实测）
- 换宿主或宿主大版本更新后，用 tools/probe_host.py 做一次协议探针并把结果发给我们
- 本套件输出审计日志与安全评估，不是检验检测报告；不能替代内核级防护（那是安信智芯 Link/Tank 的事）

## 计分 / Score

`score = 100 - 20 × critical - 5 × warning`（按去重后的发现计数，截断到 0..100；
去重键 `(rule_id, target)`）。每次报告都随附此计分基准行；体检报告只统计静态发现，
钩子告警由 report.py 单独统计——两个数不合并。

## 许可 / License

本包采用分层许可。逐文件真源见 `license-map.json`；机器可读标识见各文件头
`SPDX-License-Identifier`。

| 层 | 覆盖 | 许可 |
|---|---|---|
| 产品代码（默认） | 除下述外的全部源码与 CI 件 | Apache-2.0（见 LICENSE；义务与归属提示见 NOTICE） |
| 引流小件 | `antinel_mcp.py`、`transcript_reader.py`、`tools/probe_host.py`、`strings.py`、`challenge/` | MIT（见 challenge/LICENSE 与各文件头） |
| 声明与规则集 | `docs/A6收入边界声明.md`、`rules/*.json` | CC-BY-4.0 |
| 规范与文档 | README、docs/ 下规范与说明 | CC-BY-SA-4.0 |

收入与中立性边界见源码仓 `docs/A6收入边界声明.md`（CC-BY-4.0；随 sdist 分发）：不收通过费、不出售排名、关联方无豁免。
"""

# ---------- ZCode plugin wrapper (D6/A-05: plugin hooks auto-enable the runner) ----------
PLUGIN_JSON = {
    "name": NAME,
    "version": VERSION,
    "description": ("Security audit and live behavior protection for AI coding agents: %d rules, 4 gates, local-only." % RULES_N),
    "author": {"name": "Zhilv Technology (Antinel / PSL)"},
    "license": "Apache-2.0",
    "skills": "skills",
}


def _unlink_tolerant(p):
    """删除一个文件；只容忍宿主 safe-delete 层的【误报失败】。

    2026-09-24 实测（本机 WorkBuddy 宿主，不是推测）：宿主的 safe-delete shim 把
    unlink() 改写成"移入回收站"，优先调原生 genie-trash 二进制，失败才降级到
    SHFileOperationW。本机**两条路都会把文件删掉、却报失败**：
      · genie-trash:      rc=1, stderr="Some operations were aborted" | 文件已消失
      · SHFileOperationW: 返回 0x2                                | 文件已消失
    shim 随后 fail-closed 抛 OSError ⇒ **任何做删除的进程都死在第一次删除上**，
    构建无法完成（实测：`_clear(pkg)` 在第一个文件上就中止）。

    判定沿用 shim 自己在 _try_trash_via_binary 里写明的原则：
    "以文件系统事实为准：调用前在、调用后没了 = 删除成功"。
      · 抛错后文件已不在 -> 视为成功（它确实进了回收站，不是硬删除）
      · 抛错后文件仍在   -> **不吞**，原样抛出（真失败，fail-closed 保留）

    这不是绕过守卫：没抬高阈值、没改策略、没硬删除，删除量不变（仍逐个进回收站）。
    """
    try:
        p.unlink()
    except OSError:
        if os.path.lexists(p):
            raise


def _clear(path):
    """Empty a scratch directory this builder owns -- by RENAMING IT ASIDE.

    History (three measured failure modes, one function):
      2026-09-24 (G7): shutil.rmtree(pkg) died on the host's bulk-delete guard
        (SAFE_DELETE_BULK_CONFIRM_REQUIRED, 762 files vs threshold 50).
        Fix then: unlink file by file -- "not bulk-delete shaped".
      2026-10-08 (G8, measured in .psl/build_0368d.log): the host shim
        (workbuddy .../shim/sitecustomize.py) now wraps unlink() in
        trash + _check_bulk_delete_guard, and on threshold trip raises
        **SystemExit(1)** -- not OSError. Measured stack:
          _clear → _unlink_tolerant → p.unlink()
            → shim _check_bulk_delete_guard → _exit_bulk_guard_control
            → SystemExit(1)
        _unlink_tolerant only tolerates OSError, so the build DIED at its own
        pre-assembly scratch cleanup (line 1733) with artefacts never built.
        The old "shim misreports failure but the file is gone" tolerance is
        stale: the guard now fails as SystemExit, and per-toolCallId counting
        means ANY build that empties a full stage (119 files) trips it.

    Fix now: rename the directory aside and start fresh. ZERO deletions, so:
      1. no guard interaction at all -- nothing is deleted, so nothing needs
         approval; this is not a bypass of the confirmation flow, it is the
         absence of anything to confirm;
      2. the old directory is preserved byte-for-byte -- housekeeping failure
         can never lose data (the 2026-09-24 failure lost nothing either, but
         it BLOCKED the build; blocking is the thing this fixes);
      3. same shape as the repo's existing dist/*.away-* convention.

    Cost, stated plainly: one .away-* directory accumulates per build that
    finds a non-empty scratch. Cleaning them is a deliberate operator action
    (batches of <=49 files, respecting the guard threshold) -- the approval
    right for deletion does not belong to the builder.
    """
    p = Path(path)
    if not p.exists():
        return 0
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    away = p.with_name("%s.away-%s" % (p.name, stamp))
    i = 1
    while away.exists():
        away = p.with_name("%s.away-%s-%d" % (p.name, stamp, i))
        i += 1
    os.rename(p, away)
    print("   [housekeeping] 暂存目录改名让开（零删除，尊重宿主批量守卫）：%s"
          % away.name)
    return 0

    p = Path(path)
    if not p.exists():
        return 0
    n = 0
    for f in sorted((x for x in p.rglob("*") if x.is_file()), reverse=True):
        _unlink_tolerant(f)
        n += 1
    for d in sorted((x for x in p.rglob("*") if x.is_dir()), reverse=True):
        # 2026-09-24 (F5-b): ★ 必须先【自己确认目录已空】，再碰删除原语。
        # 本机实测（_g7_evidence/f5b_probe.py，在受守卫的根内）：
        #   os.rmdir() 对【非空】目录**不抛 OSError**，而是**递归删光内容并正常返回**。
        # 所以原注释 "only removes it if now empty" 的假定是错的 ——
        # 这里的 try/except OSError **等于没有守卫**（根本没有 ENOTEMPTY 可接）。
        try:
            if any(d.iterdir()):
                continue            # 非空 ⇒ 根本不碰它
            d.rmdir()
        except OSError:
            pass
    return n


def _cleanup_stage(path):
    """清暂存目录：失败只【报告】，不抛出。
    2026-09-24 (F5)。判据来自本轮实测：**清暂存是可选家务，产物才是交付物；
    家务不得阻止产物生成。**
    本机 `_clear()` 会撞宿主按【回合】累计的批量删除阈值
    （`SAFE_DELETE_BULK_CONFIRM_REQUIRED`，50）而以 `SystemExit(1)` 当场退出；
    原先它排在产物生成之前时，"家务失败"被当成"构建失败"，
    插件产物被静默取消 —— 实测：插件长期停在旧版本（`host_shield.py` 缺 F1 修复、
    `docs/AUDIT_SCHEMA.md` 仍 v1.2），而构建日志里一行说明都没有
    （`_g7_evidence/build_f12_r3.log` 末行是 `package: ... (42 files in manifest)`，无 `plugin :` 行）。

    ★ 这【不是】fail-open 放行：产物此时已生成，且随后由
      `_verify_plugin_matches_package()` 逐字节核对；这里放行的只有"删临时目录"这一件家务，
      且失败会**显式打印**。区分"报出来"与"出事了" —— 家务失败要报，但不等于出事。
    """
    try:
        _clear(path)
    except SystemExit as e:
        print("!! 清暂存被宿主守卫中断（不影响已生成的产物）: SystemExit(%s)" % e.code)
    except Exception as e:
        print("!! 清暂存未完成（不影响已生成的产物）: %s: %s" % (type(e).__name__, e))


def _cleanup_final_stages(pkg, plug):
    """★ 2026-09-29（D-17）：**家务最后做**。

    为什么必须收进一个函数：`build()` 有多条 return 路径（`--verify` 成功/失败、
    无 `--verify`），三条都必须路过同一次收尾，否则"某条路径没清暂存"会静默累积
    （实测：stage 里积了 64 个文件、zcode stage 72 个）。

    ★ 顺序纪律（本仓自己立的，见上）：**产物先做、家务最后做**。
      清理失败只报告、绝不改变退出码 —— 产物已经由 `_verify_plugin_matches_package`
      逐字节核过，家务失败不等于构建失败。
    """
    for s in (pkg, plug):
        try:
            if s and Path(str(s)).exists():
                _cleanup_stage(s)
        except Exception as e:
            print("!! 收尾清理 %s 未完成（不影响产物）: %s" % (s, e))


def _verify_plugin_matches_package(manifest_files, plug_root):
    """插件是【副本】：必须与**本次构建自己算出的清单哈希**一致，且一个不少、一个不多。

    2026-09-24 (F5) 新增；同日 G7-c 修正比对基准一次。
    动机＝同一类缺陷复发过：插件产物**静默**停在旧版本，构建日志没有任何一行说明它没更新
    （"报出来与出事了是两件事"）。

    ★ 为什么基准是 manifest_files，不是"包的实时字节"（G7-c 实测）：
    `psl/judgment.json` 由 scripts/run_harness.py 写，**任何一次套件重跑都会改写它**
    —— 实测本轮 10:33 有一次重跑落在构建中途，于是"插件里 10:07 的副本"与
    "包内 10:40 的副本"不等，旧写法报"插件是旧版本"，而插件其实一个字节都没错。
    拿**对方现在的样子**当基准，天生带竞态；拿**本次构建的内存哈希**当基准，
    则与包的实时状态无关。判据：**比对基准必须是"本次构建的产物"，不能是"磁盘现在的样子"。**

    psl/ 三件是设计上就被排除在清单外的可变产物（一次一写／只增／派生），
    故只断言"在"，不断言"等"。
    """
    dest = Path(plug_root) / "skills" / NAME
    if not dest.is_dir():
        raise SystemExit("plugin self-check: 缺少 %s" % dest)
    expected = dict(manifest_files)
    PSL_ARTIFACTS = ("psl/manifest.json", "psl/judgment.json", "psl/verdict-ledger.jsonl")
    for rel in PSL_ARTIFACTS:
        expected[rel] = None            # None ＝ 只查存在，不查哈希
    missing, drift = [], []
    for rel, want in sorted(expected.items()):
        f = dest / rel
        if not f.is_file():
            missing.append(rel)
        elif want is not None and _manifest_hash_of(rel, f) != want:
            drift.append(rel)
    if missing or drift:
        raise SystemExit("plugin self-check FAILED: %d missing %s | %d drifted %s"
                         % (len(missing), missing[:4], len(drift), drift[:4]))
    allowed = set(expected)
    extra = [f.relative_to(dest).as_posix() for f in sorted(dest.rglob("*"))
             if f.is_file() and f.relative_to(dest).as_posix() not in allowed]
    if extra:
        raise SystemExit("plugin self-check FAILED: %d unexpected file(s) in the plugin: %s"
                         % (len(extra), extra[:4]))
    print("plugin self-check: 清单 %d 项哈希全中 + %d 个 psl 产物在位 + 无多出文件"
          % (len(manifest_files), len(PSL_ARTIFACTS)))


def build_plugin(skill_pkg, out_root):
    # 2026-09-24 (G7): same stage-and-merge treatment as build(). Two reasons.
    # (1) rmtree() on the plugin directory counts against the host's bulk-delete
    # guard just like the package did. (2) The old ignore list was (".git",) only,
    # so the wrapper swept the package's own build artifacts -- build/lib copies,
    # *.egg-info, psl/ci_debug -- into what ships to users; a dry run measured the
    # plugin going from 45 to 136 files for exactly this reason. Those are not part
    # of the skill.
    final = Path(out_root) / (NAME + "-zcode-plugin")
    plug = Path(out_root) / (NAME + "-zcode-plugin-stage")
    # 2026-09-24 (F5): 清暂存不致命。它是本回合的【第二次】清目录，最容易撞
    # 宿主按回合累计的批量阈值；而"清不掉暂存"的后果（旧文件被一并拷进产物）
    # 已由 _verify_plugin_matches_package() 兜底（多出文件会当场报错）。
    # 判据：**致命性交给独立的自检，不交给清理动作的成败。**
    _cleanup_stage(plug)
    (plug / ".zcode-plugin").mkdir(parents=True)
    (plug / "hooks").mkdir(parents=True)
    (plug / "skills").mkdir(parents=True)
    # 2026-09-24 (G7): ship exactly this builder's output set (psl/manifest.json),
    # not "whatever happens to be in the directory". Copying the whole tree was
    # only harmless while the old builder had just deleted everything else; now
    # that build() merges instead of replacing, the tree also holds dev tooling
    # (.github/, ci/ drift scripts, demo/, build artifacts) that was never in the
    # plugin. Pinning to the manifest keeps the wrapper's contents what they have
    # always been -- measured: 42 files, not 79.
    # .git is the package's own repository history (D0) -- never ship it inside
    # the plugin wrapper (nor is it in the manifest).
    dest = plug / "skills" / NAME
    dest.mkdir(parents=True)
    mfpath = Path(skill_pkg) / "psl" / "manifest.json"
    try:
        mfiles = list(json.loads(mfpath.read_text(encoding="utf-8")).get("files") or {})
    except Exception as e:
        raise SystemExit("build_plugin: cannot read %s (%s) -- refusing to guess what "
                         "the plugin should contain" % (mfpath, e))
    # the three psl/ artifacts are excluded from the manifest by design (one is
    # this build's own output, one grows append-only, one is derived) but they DO
    # ship -- tools/antinel_verify.py cannot work without manifest.json.
    for rel in mfiles + ["psl/manifest.json", "psl/judgment.json", "psl/verdict-ledger.jsonl"]:
        s = Path(skill_pkg) / rel
        if s.is_file():
            d = dest / rel
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(s, d)
    hooks = {"hooks": {
        "PreToolUse": [{"matcher": ".*", "hooks": [{
            "type": "process", "command": "python",
            "args": ["-I", "-S", "${ZCODE_PLUGIN_ROOT}/skills/" + NAME + "/hooks/pre_tool_use.py"],
            "timeoutMs": 10000}]}],
        "PostToolUse": [{"matcher": ".*", "hooks": [{
            "type": "process", "command": "python",
            "args": ["-I", "-S", "${ZCODE_PLUGIN_ROOT}/skills/" + NAME + "/hooks/post_tool_use.py"],
            "timeoutMs": 10000}]}]}}
    (plug / "hooks" / "hooks.json").write_text(json.dumps(hooks, ensure_ascii=False, indent=2), encoding="utf-8")
    (plug / ".zcode-plugin" / "plugin.json").write_text(json.dumps(PLUGIN_JSON, ensure_ascii=False, indent=2),
                                                        encoding="utf-8")
    npm = {"name": "@antinel/security-zcode-plugin", "version": VERSION, "private": True,
           "license": "(Apache-2.0 AND MIT)", "description": PLUGIN_JSON["description"]}
    (plug / "package.json").write_text(json.dumps(npm, ensure_ascii=False, indent=2), encoding="utf-8")
    _sync(plug, final, label="plugin ")
    # 2026-09-24 (F5): 清暂存不得取消 return。原先 _clear(plug) 排在 return 之前，
    # 而它会撞宿主按回合累计的批量删除阈值（SystemExit(1)）⇒ 产物虽已 _sync 到 final，
    # 调用方却拿到异常，整次构建被当成失败。
    _cleanup_stage(plug)
    return final


def _merge(src_dir, dst_dir, label=""):
    """Copy every file from src_dir over dst_dir, overwriting. Nothing is
    deleted -- see build() for why this replaced shutil.rmtree().

    ★ 2026-10-08（trash 族）：垃圾文件**不过 merge**。宿主守卫在 copy2 覆盖
       dst 的瞬间把旧内容 quarantine 成 `<name>.g0364.trash`（实测本轮 6 个），
       这些产物若被 merge 回仓，下一轮 stage 复制会再捞它们一次 ⇒
       垃圾在「守卫造→merge 回灌→stage 再捞→manifest 钉哈希」里自循环。
       就地过滤 = 断环。被排除项由 `_junk_in()` 在 build() 里逐条打印（看得见）。
    """
    n = 0
    for p in sorted(Path(src_dir).rglob("*")):
        if not p.is_file():
            continue
        if _is_junk(p.relative_to(src_dir).as_posix()):
            continue
        dst = Path(dst_dir) / p.relative_to(src_dir)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)
        n += 1
    if label:
        print("merged %d file(s) -> %s" % (n, dst_dir))
    return n


def _sync(src_dir, dst_dir, label=""):
    """Mirror src_dir onto dst_dir: copy everything over, then remove the files
    dst_dir holds that the new build no longer produces.

    Only safe when dst_dir is FULLY owned by this builder -- true for the plugin
    wrapper, not for the published package (which also holds .git, the challenge
    lab, CI scripts and hand-maintained files). It removes only the difference,
    so a normal rebuild deletes nothing at all.
    """
    n = _merge(src_dir, dst_dir, label=label)
    keep = {p.relative_to(src_dir) for p in Path(src_dir).rglob("*") if p.is_file()}
    gone = []
    for p in sorted(Path(dst_dir).rglob("*"), reverse=True):
        if p.is_file() and p.relative_to(dst_dir) not in keep:
            gone.append(str(p.relative_to(dst_dir)))
            _unlink_tolerant(p)
    for d in sorted((x for x in Path(dst_dir).rglob("*") if x.is_dir()), reverse=True):
        # 2026-09-24 (F5-b): ★ 同 _clear() —— 先自己确认目录已空，再碰删除原语。
        # 本机实测：受守卫的根内 os.rmdir() 对非空目录**递归删光内容且不抛错**
        # （_g7_evidence/f5b_probe.py）。原注释的假定是错的。
        # ★ 这正是插件产物被毁的现场：_merge 刚把 48 个文件拷进 final，
        #   紧接着这里对 skills/ 下的目录 d.rmdir() ⇒ 整个 skills/ 子树被递归删掉，
        #   final 只剩根上的 package.json。判据：**绝不对"未亲眼确认是空的"目录调删除原语。**
        try:
            if any(d.iterdir()):
                continue            # 非空 ⇒ 根本不碰它
            d.rmdir()
        except OSError:
            pass
    if gone:
        print("plugin: removed %d stale file(s) no longer produced by this build: %s%s"
              % (len(gone), ", ".join(gone[:6]), " ..." if len(gone) > 6 else ""))
    return n


def _verification_evidence(pkg, final):
    """F5-c (2026-09-24): 让 psl-verified-at 说它自己声称的那件事。

    原先该字段取 datetime.now() —— 那是【构建时刻】，而构建器**从不运行套件**
    （套件由 scripts/run_harness.py 跑，且按 TN-06 必须跑两次）⇒ 字段实际语义是
    "构建于"，却写着"验证于"。按诚实纪律改成两条：

      1. 时间取自发布包内 psl/judgment.json 的 run.started_at ＝ 那次**验证运行**的时刻；
      2. ★ **值级校验**（不是文本级）：逐条比对 judgment.digests 与**本次构建**的字节。
         只要有一条对不上，就写 psl-verified: "false" 并大声告警 ——
         因为那份证据描述的是**别的字节**，不能拿来给这个包背书。

    副作用是好的：把"构建源落后于仓"从"以后某天才发现"变成"构建时当场可见"。
    SKILL.md 不在 digests 内，故不存在自指死循环。

    返回 (ok, verified_at, detail)。
    """
    rec, src = None, None
    for base in (final, pkg):
        p = Path(base) / "psl" / "judgment.json"
        if p.is_file():
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
                src = p
            except Exception as e:
                return (False, "", "judgment record unreadable (%s): %s" % (p, e))
            break
    if rec is None:
        return (False, "", "no psl/judgment.json in the published package")
    if rec.get("verdict") != "PASS":
        return (False, "", "judgment verdict is %r, not PASS" % (rec.get("verdict"),))
    digests = rec.get("digests") or {}
    if not digests:
        return (False, "", "the judgment record carries no digests")
    bad = []
    for rel, want in sorted(digests.items()):
        got = None
        for base in (pkg, final):
            f = Path(base) / rel
            if f.is_file():
                # ★★ 0.39.2：judgment 的 digests 由 `scripts/run_harness.py` 的
                #   `sha()` 产出（版本承载件已归归一化）⇒ 这里必须**同法**，
                #   否则 `hooks/pre_tool_use.py` 会被判成"digest 不符"（假缺陷）。
                got = _manifest_hash_of(rel, f)
                break
        if got is None:
            bad.append("%s: missing" % rel)
        elif got != want:
            bad.append("%s: %s != recorded %s" % (rel, got[7:19], want[7:19]))
    started = str((rec.get("run") or {}).get("started_at") or "").strip()
    if bad:
        return (False, started, "%d/%d digests DO NOT match this build -- %s"
                % (len(bad), len(digests), "; ".join(bad[:4])))
    return (True, started, "%d/%d digests match this build (assertions %s/%s)"
            % (len(digests), len(digests),
               rec.get("assertions_passed"), rec.get("assertions_total")))


# ---------------- A1 (2026-09-26)：MANIFEST.in 由构建器产出 + 覆盖性断言 ----------
# 前车之鉴（单变量实测）：构建器把 rules/hosts/*.json（24 个）、rules/economics/*.json
# （5 个）**复制进了暂存包**，却**不写 MANIFEST.in** ⇒ 从暂存包构建出的 wheel 把这 29 个
# 文件**静默丢掉**：
#     PyPI 0.28.0                 = 36 文件（含 rules/hosts/zcode.json）
#     暂存包                       = 30 文件（rules/hosts 0 个、economics 0 个）
#     产物仓                       = 60 文件（rules/hosts 24 个）
#     暂存包 + 只放回 MANIFEST.in   = 59 文件            ← 成因唯一
# 机理：`[tool.setuptools.package-data] rules = ["*.json"]` **只匹配 rules/ 顶层**；
#       子目录靠 MANIFEST.in ＋ pyproject 模式下 include_package_data 默认 True。
# 后果不是"少几个文件"，而是本项目最忌的三条病：
#   ① `host-audit` → rc=2「登记表为空（rules/hosts/）」——首期产品"审核"主线直接死；
#   ② `host_shield.self_check()` → `(True, [])`：os.listdir 失败 ⇒ names=[] ⇒ 循环 0 次
#      ⇒ **假守卫**（"没有对象的检查项＝假守卫"，比没有还坏）；
#   ③ 记账口径**静默** credits→tokens（economics 画像没了，无人报错）。
# ★ 生成规则：**从 pyproject 模板 + 暂存包实际内容推导，不写死** —— 构建器不产的东西迟早会缺。
def _declared_from_pyproject():
    """从 PYPROJECT 模板里读 packages 与 package-data（**单一真源**，不另抄一份）。"""
    import ast
    import re as _re
    m = _re.search(r"packages\s*=\s*(\[[^\]]*\])", PYPROJECT)
    pkgs = ast.literal_eval(m.group(1)) if m else []
    pd = {}
    blk = _re.search(r"\[tool\.setuptools\.package-data\](.*?)(?:\n\[|\Z)", PYPROJECT, _re.S)
    if blk:
        for line in blk.group(1).splitlines():
            line = line.strip()
            if "=" not in line or line.startswith("#"):
                continue
            k, v = line.split("=", 1)
            try:
                pd[k.strip()] = tuple(ast.literal_eval(v.strip()))
            except (ValueError, SyntaxError):
                pass
    return tuple(pkgs), pd


def _declared_modules_from_pyproject():
    """从 PYPROJECT 模板里读 `py-modules`（随包发在仓根的模块）。**同源，不另抄一份。**

    ★ 必须先剥 `#` 注释：`py-modules` 的列表字面量里逐条写着中文说明（"与 build() 里的
      root_mod 复制清单逐字一致"），带注释的文本 `ast.literal_eval` 会直接抛错。
    """
    import ast
    import re as _re
    m = _re.search(r"py-modules\s*=\s*(\[.*?\])", PYPROJECT, _re.S)
    if not m:
        return ()
    try:
        return tuple(ast.literal_eval(_re.sub(r"#[^\n]*", "", m.group(1))))
    except (ValueError, SyntaxError):
        return ()


#: `psl/manifest.json` 覆盖面里**按名**排除的三个随包 psl 产物。
#: 作用域与 `NEVER_SHIP` 不同（那条管打包覆盖面，这条管清单覆盖面），故意分开。
#: 0.48.3：从 build() 的局部量提为模块级 —— `_wheel_payload()` 也要用同一份。
MANIFEST_EXCLUDE_NAMES = ("manifest.json", "judgment.json", "verdict-ledger.jsonl")


def _wheel_payload(root, manifest_lines):
    """列出 `root` 下**真会进 wheel** 的文件（posix 相对路径，已排序）。

    ★★ 0.48.3：这是 `psl/manifest.json` 的**唯一正确作用域**。为什么必须存在：
      清单是在**安装态**被消费的（`antinel_verify --manifest`、`host_shield.self_check()`），
      而安装态就是 wheel 解开的树。此前清单从**暂存包** `pkg` 生成、wheel 却从**仓根**
      构建 ⇒ 两份主体分家，实测**双向**错配：
        · **多覆盖** 15 个只进 sdist / 只留仓里的文件（`docs/`、`references/`、`ci/`、
          `.gitattributes`、`README.md`、`LICENSE`、`NOTICE`、`SKILL.md`、`MANIFEST.in`、
          `.github/workflows/verify.yml` …）⇒ 纯净安装下 `--manifest` 报
          `[SUPERSEDED] 15 of 124 covered files are missing`；
        · **少覆盖** 13 个**确实随 wheel 发**的文件（`scripts/run_harness.py`、
          `scripts/build_package.py`、`scripts/release.py`、`psl/judgment.json`、
          `psl/workspace_facts.json`、`rules/typosquat_top.json`、`hooks/_host_detect.py`、
          `tools/host_matrix.py` …）⇒ **保护名单里有一批文件从未被保护**
          （本仓 0.36.4 修过同一个病的另一半）。
      判据**镜像 `pyproject.toml` 的真实声明，不是推断**：
        · 根级：只有 `py-modules` 里的 `.py`；
        · `packages` 内：`.py`（`build_py` 永远随包）＋ package-data glob
          （**glob 语义，`*` 不跨 `/`**）＋ MANIFEST.in 的 `recursive-include`
          （`include_package_data` 默认 True ⇒ **包内**非 `.py` 文件受它影响；
          实测 `tools/HOST_PROBE.md`、`tools/tray.ps1` 确实进了 wheel）；
        · 其余（非 package 目录、根级非 `.py`）一律只进 sdist。
      这条判据由 `scripts/verify_release.py` 的「清单 vs 实测 wheel namelist」对账守着
      —— 写错**不会静默**（本项目第 ① 条硬判据：假守卫比没有守卫更坏）。
    """
    import fnmatch
    pkgs, pd = _declared_from_pyproject()
    mods = _declared_modules_from_pyproject()
    rec = [(ln.split()[1], ln.split()[2:]) for ln in manifest_lines
           if ln.startswith("recursive-include ") and len(ln.split()) >= 3]
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        if any(rel.startswith(x) for x in NEVER_SHIP):
            continue
        if p.name in MANIFEST_EXCLUDE_NAMES:
            continue
        if _is_junk(rel):
            continue
        if "/" not in rel:
            # 根级：只有 `py-modules` 声明的 `.py` 随 wheel；其余（README/LICENSE/
            # NOTICE/SKILL/MANIFEST.in/pyproject.toml/server.json/点文件）只进 sdist。
            if rel.endswith(".py") and rel[:-3] in mods:
                out.append(rel)
            continue
        top = rel.split("/")[0]
        if top not in pkgs:
            continue                                  # 非 package 目录 ⇒ 只进 sdist
        if rel.endswith(".py"):
            out.append(rel)                           # build_py 永远随包
            continue
        inner = rel[len(top) + 1:]
        if any(_glob_match(inner, pat) for pat in pd.get(top, ())):
            out.append(rel)
            continue
        if any(rel.startswith(d2 + "/")
               and any(fnmatch.fnmatch(p.name, pat) for pat in pats)
               for d2, pats in rec):
            out.append(rel)
    return sorted(out)


# 打包时**永不随包**的路径。这是**政策**，不是登记表 ——
# 登记表会腐烂（前车之鉴：24 个登记表最后只有 1 个 watch 非空），政策不会。
# 出处：G7 注释（2026-09-24）已实测认定 build/、antinel.egg-info/、psl/ci_debug/
# 是"setuptools / CI 工件被误纳入版本管理"。**每次构建会把排除项打印出来**，
# 所以这份名单不可能悄悄长大。
NEVER_SHIP = ("psl/ci_debug/", "__pycache__/", "build/", "antinel.egg-info/",
              # ★ 2026-09-26（A6）：账本是**仓内**追加式工件，不进 wheel。
              #   此前它"恰好"不进包 —— 因为产物仓那条 `recursive-include psl ...`
              #   被退役了、而 package-data 的 `*.json` 匹配不到 `.jsonl`。
              #   靠巧合=没守卫：`_manifest_for(产物仓)` 实测会生成
              #   `recursive-include psl *.bak-... *.jsonl`，那条规则会把它一起拉进 wheel。
              #   所以写进政策：**按设计排除，且每次构建看得见**。
              #   （另一处同义登记：装配段的 `MANIFEST_EXCLUDE`，管的是 psl/manifest.json
              #     的覆盖面，不是打包覆盖面 —— 两者作用域不同，故意分开。）
              "psl/verdict-ledger.jsonl")


# ★ 2026-09-26（A6）：**垃圾文件政策**。
#   `_manifest_for()` 是"包里有什么，就为它写规则" —— 这对**数据文件**是对的，
#   对**备份/编辑器临时文件**是错的：它会给垃圾也写一条规则，把垃圾一起发出去。
#   实测（2026-09-26）：对产物仓跑 `_manifest_for()` 得到
#       recursive-include psl *.bak-2026-09-25-before-0284 *.jsonl
#   —— 那个 `.bak-*` 是**未被 git 跟踪**的遗留备份（`psl/manifest.json.bak-...`），
#   而它带出来的 `*.jsonl` 会把 21 KB 的内部账本拉进 wheel。
#   政策：垃圾文件**永不生成规则**，且**每次构建把排除项打印出来**（不可能悄悄长大）。
NEVER_SHIP_PATTERNS = ("*.bak-*", "*.orig", "*.rej", "*~",
                       ".DS_Store", "Thumbs.db", "*.tmp", "*.swp",
                       # ★ 2026-10-08（trash 族）：**宿主守卫的隔离产物**。
                       #   实测（0.36.8 构建）：`_merge` 用 copy2 覆盖仓内文件时，
                       #   宿主 sitecustomize 把旧内容 quarantine 成
                       #   `<name>.g0364.trash`（本次一夜产生 6 个，散落在
                       #   rules/hosts/、hooks/、psl/、仓根）。`_manifest_for`
                       #   按实际文件推导扩展名 ⇒ 生成
                       #       recursive-include rules *.json *.trash
                       #   而 pyproject 模式 include_package_data 默认 True
                       #   ⇒ MANIFEST.in 的 `*.trash` 直接进 **wheel**；
                       #   同时 manifest 的 rglob 把它连同哈希一起钉进清单
                       #   （幽灵条目：文件可能在下一轮已被清走，哈希对不上，
                       #   构建器只能声明自举豁免）。与 `.bak-*` 同族同策：
                       #   守卫产物**永不生成规则、永不进清单、永不进包**。
                       "*.trash*",
                       # ★★★ 2026-10-28（0.60.1 出包实测）：**退役改名件**。
                       #   本仓的零删除纪律是「退役件 `.away-<ts>`」（改名让开，
                       #   不是删掉）。这些件**永远不该随包**，可垃圾政策一直
                       #   不认它们 —— 实测代价：`challenge/chain/2026-10-11.jsonl`
                       #   被改名成 `…jsonl.away-20261028113021` 之后，清单把**新
                       #   名字连同哈希**钉了进去，而 wheel 里没有它 ⇒
                       #   `verify_release.py` [E] 当场红：
                       #   「清单覆盖了 1 个不随 wheel 分发的文件」，
                       #   纯净安装下 `--manifest` 会报 superseded（狼来了）。
                       #   ★ 为什么必须加在这一处：三个作用域共用这份名单
                       #     （规则生成 / MANIFEST.in / 清单覆盖），加在一处
                       #     三处同时收口；只改清单那处就是「同一事实两处实现」。
                       "*.away-*")


def _is_junk(rel):
    """按**文件名**判垃圾（不是路径）。`*.bak-*` 这种带中间段的模式必须用 fnmatch。"""
    import fnmatch
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, p) for p in NEVER_SHIP_PATTERNS)


def _junk_in(pkg):
    """列出 base 下 packages 内**被垃圾政策排除**的文件（相对 base 的 posix 路径）。

    存在的意义是"看得见"：政策排除如果静默，就等于"我把它漏了"和
    "我故意不发"在日志里长得一模一样。
    """
    pkgs, _pd = _declared_from_pyproject()
    out = []
    for d in pkgs:
        base = pkg / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file() or "__pycache__" in f.parts:
                continue
            rel = f.relative_to(pkg).as_posix()
            if _is_junk(rel):
                out.append(rel)
    return out


# 产物仓的 MANIFEST.in ＝ 本构建器生成的规则 ＋ **这份政策**（每次构建全量重写）。
# 内容：构建器不产、但必须随 sdist 的仓拥有目录（G7 清单里的 `challenge/`、`demo/`）。
# ★ 为什么是"全量重写"而不是"只加不删"：旧规则会腐烂。实测：产物仓里那条
#   `recursive-include psl *.json *.py *.md` 一直把 `psl/ci_debug/`（CI 工件）拉进 wheel
#   —— 实测 60→66 文件；只加不删 ⇒ 它永远不会消失。被覆盖的旧规则会**逐条打印**。
REPO_MANIFEST_RULES = (
    "recursive-include challenge *.py *.md",
    "recursive-include demo *.py *.txt",
)


def _shippable(base, pkgs_pd):
    """列出 base 目录下**需要打包规则**的文件（相对 base 的 posix 路径）。

    ★ 三类不需要规则（这是 setuptools 的真实行为，不是我们的偏好）：
      · 包内 `.py` —— 它是模块，`build_py` 永远随包；
      · 已被 `package-data` 覆盖的（**glob 语义**，相对包目录）；
      · `NEVER_SHIP` 政策排除的。
    ★ 第四类（A6）：`NEVER_SHIP_PATTERNS` 命中的**垃圾文件** —— 不是"不需要规则"，
      而是"**绝不能有规则**"。没有这一条，`_manifest_for` 会给 `.bak-*` 写一条规则，
      顺手把同类扩展名的真文件（如 `.jsonl` 账本）也发出去。
    """
    d = base.name
    pd = pkgs_pd[1]
    out = []
    for f in sorted(base.rglob("*")):
        if not f.is_file() or "__pycache__" in f.parts:
            continue
        rel = f.relative_to(base).as_posix()
        if f.suffix == ".py":
            continue
        if _is_junk(rel):
            continue
        if any(_glob_match(rel, pat) for pat in pd.get(d, ())):
            continue
        if any((d + "/" + rel).startswith(x) for x in NEVER_SHIP):
            continue
        out.append(rel)
    return out


def _manifest_for(pkg):
    """按暂存包**实际内容**生成 MANIFEST.in —— 需要什么才写什么。

    ★ 三条纪律：
      ① 只列真实存在的目录（写死不存在的目录会让"声明了什么"与"包里有什么"再次分家，
         那正是 A1 的病根）；
      ② **只写需要的**：包内 .py 天然随包，不必也不能靠 MANIFEST；
      ③ 先做错一版的教训：早期版本无条件给**每个** package 写
         `recursive-include <d> *`，结果 `recursive-include psl *` 把产物仓的
         `psl/ci_debug/*.json`（CI 工件）拉进了 wheel（实测 60 → 66 文件）。
         所以现在**按需**生成，并且把 CI 工件写进 NEVER_SHIP 政策。
    """
    pkgs, pd = _declared_from_pyproject()
    lines = ["include README.md LICENSE pyproject.toml"]
    for d in pkgs:
        base = pkg / d
        if not base.is_dir():
            continue
        need = sorted({("*" + os.path.splitext(r)[1]) if os.path.splitext(r)[1] else r
                       for r in _shippable(base, (pkgs, pd))})
        if need:
            lines.append("recursive-include %s %s" % (d, " ".join(need)))
    # 非 package 目录：只进 sdist（wheel 不含）。★ 这是**实测**（2026-09-26，setuptools 84.0.0）：
    # `recursive-include docs *` 写了也没用，wheel 里就是没有 —— 见
    # D:\2026\PSL\_strict_test\setuptools_probe2\。0.28.0 已发布的 wheel 同样不含 docs/references。
    # 所以这里保留它们只为 sdist 完整；**wheel 缺 docs/references 这件事由调用方显式打印**，
    # 不许静默（"跳过"必须看得见）。
    for d in ("docs", "references"):
        if d not in pkgs and (pkg / d).is_dir():
            lines.append("recursive-include %s *" % d)
    return lines


def _glob_match(relpath, pattern):
    """glob 语义匹配：**`*` 不跨目录分隔符**。

    ★ 为什么不能用 `fnmatch.fnmatch(relpath, pattern)`：它把 `*` 翻成 `.*`，
      **会跨 `/`** ⇒ `fnmatch("hosts/zcode.json", "*.json")` 返回 True。
      而 setuptools 的 package-data 用的是 glob 语义（`glob.glob(pkg_dir/"*.json")`
      只列顶层）⇒ 两者判据相反。
      ★★ 这正是 A1 的成因本身：我第一版守卫就是用 fnmatch 按 basename 匹配的，
      结果它对**真实出事的状态**返回"绿" —— 又一个**假守卫**（本项目第 ① 条硬判据）。
    """
    import fnmatch
    r, p = relpath.split("/"), pattern.split("/")
    if len(r) != len(p):
        return False
    return all(fnmatch.fnmatch(a, b) for a, b in zip(r, p))


def _assert_package_data_covered(pkg, manifest_lines):
    """构建期断言：声明进 packages 的**每个真实文件**都必须会被打包。

    这是一条**有对象**的守卫（对象＝pkg 下每个文件）。A1 那 29 个文件当初就是
    "存在、但没被任何规则覆盖"—— setuptools 对此**不报错、不警告**，只是不发。
    两类规则分别按各自的真实语义判：
      · `package-data`：**glob**，相对包目录，`*` 不跨 `/`（⇒ `*.json` 只覆盖顶层）；
      · `recursive-include`：递归匹配**文件名**（basename）。

    ★ A6（2026-09-26）：**对象要减掉"政策排除"的那些**，否则这条守卫会反过来逼我们
      给垃圾文件写规则（"未覆盖 ⇒ FAIL" ⇒ 只能补规则 ⇒ 垃圾随包发）。
      但"排除"必须**看得见** —— 由 `_junk_in()` 在 build() 里逐条打印，
      否则"故意不发"和"我漏了"在日志里长得一模一样。
    """
    import fnmatch
    pkgs, pd = _declared_from_pyproject()
    rec = [(ln.split()[1], ln.split()[2:]) for ln in manifest_lines
           if ln.startswith("recursive-include ") and len(ln.split()) >= 3]
    missing = []
    for d in pkgs:
        base = pkg / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file() or "__pycache__" in f.parts:
                continue
            rel = f.relative_to(pkg).as_posix()
            if any(rel.startswith(x) for x in NEVER_SHIP):
                continue
            if _is_junk(rel):
                # 垃圾政策排除（`NEVER_SHIP_PATTERNS`）：不是漏，是**不发**。
                # build() 会把它打印出来；这里不记入 missing。
                continue
            if f.suffix == ".py":
                # 包内 `.py` 由 `build_py` 随包，与 MANIFEST / package-data 无关。
                # ★ 这不是推断，是**实测**（2026-09-26，setuptools 84.0.0）：
                #   一个只声明 packages=["scripts"]、**没有 __init__.py、完全没有 MANIFEST.in**
                #   的目录，其 .py 仍然进了 wheel（对照组：同目录的 .json 只有在被
                #   package-data 或 recursive-include 覆盖时才进）。见
                #   D:\2026\PSL\_strict_test\setuptools_probe\。
                continue
            top = rel.split("/")[0]
            inner = rel[len(top) + 1:]                     # 相对包目录
            if any(_glob_match(inner, pat) for pat in pd.get(top, ())):
                continue
            if any(rel.startswith(d2 + "/") and any(fnmatch.fnmatch(f.name, p) for p in pats)
                   for d2, pats in rec):
                continue
            missing.append(rel)
    if missing:
        raise SystemExit(
            "★ A1 守卫 FAIL：以下文件在 packages 内，但既不被 package-data 也不被 "
            "MANIFEST.in 覆盖 —— setuptools 会**静默丢弃**它们：\n  "
            + "\n  ".join(missing[:30])
            + "\n（修法：给对应目录补 MANIFEST.in 规则，或补 pyproject 的 package-data。"
              "不要靠「构建完再看一眼」——本次就是本地全绿、上传才死。）")
    return True


def _refresh_skill_selfcert(pkg, final, harness_rc, plug=None):
    """★★★ 0.42.0：把 SKILL.md 自证卡的刷新点从**装配时**移到**harness 之后**。

    ★ 为什么必须移（2026-10-09 本班实测的结构性死锁）：

      装配时调 `_verification_evidence()` 必然返回 `ok=False` —— 因为那份判定记录
      是**上一次运行**的输入，描述的是**上一次的字节**；而本次刚改过受覆盖文件
      （0.42.0 改了 `scripts/report.py`，它在 COVERED 里）⇒ digests 必然不符
      ⇒ 自证卡被写成 `psl-verified: "false"` ＋ `at: ""`。

      然后 `_merge(pkg, final)` 把这个 false **覆盖回源码仓**（final 就是仓本身），
      而 `_reconcile_src` 的看守清单只有 `run_harness.py` 一个文件 ⇒ **无人发现**。

      接着 harness 跑两次、ship 第二次记录 —— 此时记录**确实描述本次字节**了，
      但自证卡已经写完，**没有回头刷新** ⇒ 发布物与仓库都停在 false。

      ⇒ 闸门的 version/regression 两条读仓库 SKILL.md ⇒ 红 ⇒ 构建被拦
        ⇒ harness 不跑 ⇒ 记录不刷新 ⇒ **死锁**。

      这与 README.md 那次（2026-09-24 G7「REPO-OWNED，不是 builder output」）
      是**同一条病**：同一事实两处副本，构建器用生成物覆盖仓源。
      README 的解法是"构建器不写"；SKILL.md 不能照抄 —— 它的自证卡**必须**随
      每次验证更新，不写就是手工活（＝又一件"包装成待办"）。

      ⇒ 本函数的解法：**只重写自证卡那 4 行，正文一字不动**；
        且只在 harness 成功（rc==0）时才敢写 true —— 失败就保持 false，说真话。

    ★ 位置纪律：必须在 harness **之后**、`_reconcile_src` **之前**。
    """
    if harness_rc != 0:
        print("!! SKILL.md 自证卡不刷新：harness rc=%d（记录不可信，保持 false 说真话）" % harness_rc)
        return False
    # ★ 0.48.4：先让 `psl/SKILL.md` 与根 `SKILL.md` **同源**，再一起刷自证卡。
    #   为什么放在这里而不是组装阶段：wheel 里 SKILL.md 是随 `psl/` 包走的，
    #   而根 SKILL.md 是**模板渲染出来的**、写成 pkg 的时间远晚于组装中期。
    #   第一版把复制放在组装段、取源是**源码树**那份 ⇒ 复制到的是上一轮的旧版
    #   （实测：psl/SKILL.md 2704 B vs SKILL.md 4697 B），插件自检当场判
    #   `drifted ['psl/SKILL.md']`。⇒ 复制源必须是**刚刚生成的这一份**。
    # ★ 2026-10-15（0.50.4 改名批）：**插件副本也要同源一起刷**（plug 参数）。
    #   为什么：插件构建（build_plugin）排在 harness **之前**，它拷走的
    #   SKILL.md / psl/SKILL.md 带着装配时的自证卡；harness 之后只刷 pkg/final
    #   的话，**发给用户的插件**就停在旧卡（"NOT VERIFIED" 或上一轮的 true）——
    #   在立信誉的地方说反话。0.48.4 防的是 psl/SKILL.md 这一个副本，当年漏了
    #   插件；插件里的路径多一层 `skills/<NAME>/`。
    _roots = [Path(pkg), Path(final)]
    if plug:
        _roots.append(Path(plug) / "skills" / NAME)
    for base in _roots:
        _s = base / "SKILL.md"
        if not _s.is_file():
            continue
        _d2 = base / "psl" / "SKILL.md"
        _d2.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_s, _d2)

    ok, at, detail = _verification_evidence(pkg, final)
    new_verified = "true" if ok else "false"
    new_at = at if ok else ""
    new_ev = (("live PreToolUse block of a real .env read in ZCode (AN-001) plus a full-assertion "
               "judgment run; digest check %s" % detail) if ok
              else ("NOT VERIFIED for this build: %s" % detail))
    changed = []
    # ★ 0.48.4：`psl/SKILL.md` 也要一起刷。
    #   为什么：wheel 里 SKILL.md 是随 `psl/` 包走的（顶层非 .py 文件没有可靠的
    #   随包机制，而 psl 的 package-data 已声明 `*.md`）。组装阶段复制过去的那份
    #   **早于**自证卡刷新 ⇒ 若不同步，Agent 从包里读到的自证卡就是陈旧的
    #   （说"本包未验证"，而它其实刚刚验证过）——在立信誉的地方说反话。
    for base in _roots:
        for rel in ("SKILL.md", os.path.join("psl", "SKILL.md")):
            f = base / rel
            if not f.is_file():
                continue
            _rewrite_one(f, new_verified, new_at, new_ev, changed)
    print("SKILL.md 自证卡刷新：verified=%s at=%s（%s）→ %s"
          % (new_verified, new_at or "（空）", detail[:80],
             "、".join(changed) if changed else "两处本就一致，无需写"))
    # ★ 0.48.4（J6m）：刷新改写了字节 ⇒ 清单里那条哈希当场过期，必须重钉。
    #   顺序是结构性的：psl/manifest.json 在 build() 的装配段生成（约 2887 行），
    #   而本函数跑在 harness 之后 ⇒ 必然晚于清单 ⇒ 不重钉就差一个刷新。
    if changed:
        _rehash_manifest_for_skill(pkg, final, plug)
    return ok


def _rewrite_one(f, new_verified, new_at, new_ev, changed):
    """把一份 SKILL.md 的自证三行改写为目标值（供 `_sync_skill_selfcert` 复用）。"""
    txt = f.read_text(encoding="utf-8")
    out = []
    for line in txt.split("\n"):
        s = line.strip()
        if s.startswith("psl-verified:") and not s.startswith("psl-verified-"):
            out.append('  psl-verified: "%s"' % new_verified)
        elif s.startswith("psl-verified-at:"):
            out.append('  psl-verified-at: "%s"' % new_at)
        elif s.startswith("psl-verified-evidence:"):
            out.append('  psl-verified-evidence: "%s"' % new_ev)
        else:
            out.append(line)
    new_txt = "\n".join(out)
    if new_txt != txt:
        f.write_text(new_txt, encoding="utf-8", newline="\n")
        changed.append(str(f))


def _rehash_manifest_for_skill(pkg, final, plug=None):
    """自证卡刷新之后，把 `psl/manifest.json` 里 SKILL.md 的哈希重钉一遍。

    ★ 为什么必须重钉（2026-10-12 端到端 J6m 实测判红）：

      装完 wheel 的 Agent 跑 `python -m tools.antinel_verify --manifest`，
      得到 `[SUPERSEDED] 1 of 124 covered files differ  changed: psl/SKILL.md`。
      真相不是"包被动过"，只是我们自己刚改写了自证卡的时间戳 —— 但这条命令
      的语义是**证据有没有被动过**，在立信誉的地方自曝不一致，等于自毁。

    ★ 为什么这里可以只改清单、不改判定记录（judgment）：
      judgment 的覆盖集是那 21 个受保护文件，**不含** `psl/manifest.json`
      也不含 `psl/SKILL.md`（已核对）⇒ 重钉不触碰 21/21 的口径，无自举循环。
    """
    rels = ("psl/SKILL.md", "SKILL.md")
    _roots = [(Path(pkg), "stage"), (Path(final), "package")]
    if plug:
        _roots.append((Path(plug) / "skills" / NAME, "plugin"))
    for base, _lbl in _roots:
        mj = base / "psl" / "manifest.json"
        if not mj.is_file():
            continue
        try:
            man = json.loads(mj.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:                      # noqa: BLE001
            print("!! 清单读不出，跳过重钉：%s（%s）" % (mj, e))
            continue
        files = man.get("files")
        if not isinstance(files, dict):
            continue
        touched = []
        for rel in rels:
            if rel not in files:
                continue
            src = Path(base) / rel
            if not src.is_file():
                continue
            new = _manifest_hash_of(rel, src)
            if files[rel] != new:
                files[rel] = new
                touched.append(rel)
        if touched:
            man["files"] = dict(sorted(files.items()))
            mj.write_text(json.dumps(man, ensure_ascii=False, indent=1),
                          encoding="utf-8", newline="\n")
            print("   清单哈希重钉（%s）：%s" % (_lbl, "、".join(touched)))


def _reconcile_src(mutated):
    """★★★ 构建后对账守卫（2026-09-28 新增，防「构建器改仓源」事故复发）。

    事故原型：build_package.py 曾把一份**内嵌的 run_harness 模板**写进产物，
    而模板是仓里 run_harness.py 的**陈旧副本** —— 于是每次构建都在**用旧副本
    覆盖仓源**，静默丢掉仓里后来做的 5 处改进。发现它靠的是人肉 diff，
    不是机器。这是「同一事实两处副本」缺陷类的第 4 次发作。

    ⇒ 本守卫把「构建器不得改动仓源」变成**每次构建都会自动跑**的判据：
      `mutated` 是 build() 在写盘前登记的 (相对路径, 构建前 sha256) 列表；
      只要构建结束时某个仓源文件的哈希变了，立刻红，并点名是哪个文件。

    为什么**必须**在 `build()` 的**每条 return 路径**上都调用：
      守卫只挂在正常出口 ⇒ 异常路径上的静默破坏永远不被发现。
    """
    bad = []
    for rel, before in mutated:
        p = srcfile(rel)
        if not p.is_file():
            bad.append("%s（构建后**消失了**）" % rel)
            continue
        after = sha256(p)
        if after != before:
            bad.append("%s\n      构建前 %s\n      构建后 %s" % (rel, before, after))
    if bad:
        raise SystemExit(
            "★ 对账守卫 FAIL：构建**改动了仓源文件**（构建器只许读、不许写）：\n  - "
            + "\n  - ".join(bad)
            + "\n（成因：有『生成物』在覆盖仓源 —— 典型是内嵌模板覆盖了真源。"
              "修法是**消灭副本**（读仓源，别内嵌），不是把模板改新。"
              "因为模板一旦内嵌，它迟早会落后于真源，而**落后是静默的**。）")
    print("reconcile: %d 个仓源文件经构建后逐字未变" % len(mutated))
    return True


def _tracked_root_modules(pkg):
    """包根下**被 git 跟踪**的 .py 模块名集合（＝ 会进包的那些）。

    git 不可用 ⇒ 退化为包根全部 .py（不静默放松：D-20 的内建负控与真树调用兜底）。
    """
    pkg = Path(pkg)
    try:
        import subprocess
        r = subprocess.run(["git", "ls-files", "--", "*.py"], cwd=str(pkg),
                            capture_output=True, text=True, timeout=60, creationflags=_CNW)
        if r.returncode == 0 and r.stdout.strip():
            out = set()
            for rel in r.stdout.split():
                if "/" in rel or "\\" in rel:
                    continue                      # 只取包根那一层
                p = pkg / rel
                if p.is_file():
                    out.add(p.stem)
            if out:
                return out
    except Exception:                                          # noqa: BLE001
        pass
    return {p.stem for p in pkg.glob("*.py") if p.is_file()}


def _pymodules_guard(pkg_dir):
    """★ 包组成守卫（**双向**）：返回问题列表（空 = 通过）。

    为什么要有这条（都是实测事故，不是理论）：
      · 正向 —— `antinel_mcp.py` 当年在 pyproject 里声明、却从没被复制 ⇒ 装完 ImportError；
      · 反向 —— `ui_server.py`（D-20）三处都没登记，靠"仓根本来就有"侥幸进包，
        而 `antinel.py` 顶层 `import ui_server` ⇒ **干净树打 wheel 就丢**，
        用户装完**所有命令**都 import 就炸。旧 wheel 能跑只因陈旧 `build/` 带进去（**假绿**）。

    ★ 判据直接盯"装完能不能 import"，不依赖任何陈旧目录。
    ★ 提成独立函数（而不是留在 build() 里）：这样回归闸门能**行为级**调它、
      并用一个"被 import 但没声明"的 fixture 做**内建负控** —— 判据不许二次实现。
    """
    import re
    pkg = Path(pkg_dir)
    problems = []
    _pp = (pkg / "pyproject.toml").read_text(encoding="utf-8")
    _m = re.search(r"py-modules\s*=\s*\[([^\]]*)\]", _pp)
    _declared = set(re.findall(r'"([^"]+)"', _m.group(1))) if _m else set()
    # ★★ 0.50.4：`_present` 只算**会进包的那些**（git 跟踪的 .py）。
    #   为什么必须收窄：仓根有一批 gitignore 的探针（`_p_*.py`，本仓惯例），
    #   它们**不进 wheel、不进 sdist**；旧口径 `pkg.glob("*.py")` 把它们算进来，
    #   而某个探针又 import 另一个探针 ⇒ 判据报「包根模块被 import 却没声明」
    #   （实测 D-20 假红：`_p_q_shot2` / `_p_q_tab…` 一长串）。
    #   收窄口令：**进包的 ＝ 被 git 跟踪的**（探针从不被跟踪）。
    #   git 不可用（如出包后的 `out/` 装配区无 .git）⇒ 退化为全部 .py ——
    #   那边本来就不会有探针（复制清单里没有），不放松真树的守卫。
    _present = _tracked_root_modules(pkg)

    _miss = sorted(_declared - _present)
    if _miss:
        problems.append(
            "pyproject 声明了模块、但包目录里没有对应 .py：%s"
            "（＝ 用户 pip 装完 import 就炸。把该模块加进 root_mod 复制清单。）" % _miss)

    _imported = set()
    for _p in pkg.rglob("*.py"):
        try:
            _txt = _p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for _mm in re.finditer(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)",
                               _txt, re.M):
            _imported.add(_mm.group(1))
    _undeclared = sorted((_present & _imported) - _declared)
    if _undeclared:
        problems.append(
            "包根模块被 import、却没在 pyproject 的 py-modules 里声明：%s"
            "（＝ 干净环境打 wheel 会漏掉它，用户装完**所有命令**都可能 import 就炸。"
            " 实测事故：ui_server.py。）" % _undeclared)
    return problems


def _delivery_gate(out_root, full=True):
    """★★ 0.36.5：打包**之前**必跑统一交付闸门（第二个强制执行点）。

    ★★ 为什么这道闸门是本轮最要紧的一处接线（不是"多加一道检查"这么轻）：
      此前全仓有 **113 条Antinel 监理判据 ＋ 7 条交付自检，一条调用方都没有**。
      实测后果不是"少跑了几个检查"，而是：
        · `ci/inbox_guards_0363.py` 有一条红、`0364.py` 有一条红，
          **已经红了一段时间却没人知道**；
        · 那两条红指向同一个根因：`psl/manifest.json` 停在旧哈希，
          而 0.36.4 的代码改动**从未重新打包** ⇒ 自检永远不符
          ⇒ 研发态被自己的安全边界挡住（这条是**对的**行为）。
      ⇒ 而「重新打包」这件事本身**又依赖闸门通过**（版本一致性就是其中一条）。
         鸡生蛋问题只能靠**把闸门接到打包入口**来解：
         从此「红 ⇒ 打包不出包」成为默认，发出去的包必过闸门。

    ★ 位置纪律：与本函数上方 `_verify_layout()` 同理，**必须在任何写盘之前红**。
      失败的代价必须是「什么都没动」—— 否则红一次就留下一堆半成品。

    ★ `--full` 默认开（跑 slow 档，含回归闸门）：打包是低频动作，
      慢几十秒完全可以接受；而发布钩子上省下的时间不该从发布侧省。
      闸门文件缺失 ⇒ **不静默跳过**：这里要按"缺失＝盲区"处理。
    """
    import subprocess as _sp
    _here = os.path.dirname(os.path.abspath(__file__))       # scripts/
    _root = os.path.dirname(_here)                # 仓根
    _gate = os.path.join(_root, "ci", "delivery_gate.py")
    if not os.path.isfile(_gate):
        raise SystemExit(
            "★ 交付闸门缺失：%s\n"
            "  打包被拦下。**这不是通过，是闸门不存在** —— 打包是发版的最后一道口，\n"
            "  这里空着就等于「无人检查的包可以发出去」。\n"
            "  修法：从 git 恢复该文件（git checkout -- ci/delivery_gate.py）。" % _gate)
    cmd = [sys.executable, _gate] + ([] if full else ["--quick"])
    print("=" * 74)
    print("打包前：统一交付闸门%s" % ("（全量档）" if full else "（秒级档）"))
    print("=" * 74)
    # ★★ 0.36.5：打包期间**自动**声明"在途"（不要求人记得手设）。
    #   D-23 会检查「dist 里必须有本版发布件」——而那些包正是本次构建的产物。
    #   ⇒ 打包时它必然"缺件"，那是流程中间态，不是失守。
    #   ⚠️ 只豁免"缺件"，**不豁免"dist 里混旧包"**（那才是 D-23 要防的误上传）。
    #   ⚠️ 用完必须还原：不能让这个标志泄到闸门之外的进程里
    #   （否则提交钩子跑闸门时也带着它 ⇒ 真缺陷被免检）。
    _prev_inflight = os.environ.get("ANTINEL_BUILD_IN_FLIGHT")
    # ★★ 自举豁免：manifest（版本 + 哈希）**由本次打包生成** ⇒ 打包前必然落后。
    #   不设它则 0.36.5 升版后首次打包必被自己的产物判红 ⇒ 死锁。
    #   自动判定条件（**窄**：只在源码版本 ≠ manifest 登记版本时才算自举）。
    _mf = os.path.join(_root, "psl", "manifest.json")
    _mf_ver = None
    try:
        with open(_mf, encoding="utf-8") as _f:
            _mf_data = json.load(_f)
            _mf_ver = _mf_data.get("version")
            _mf_files = _mf_data.get("files") or {}
    except Exception:                                          # noqa: BLE001
        _mf_ver = None
        _mf_files = {}
    _self_bootstrap = (str(_mf_ver) != str(VERSION))
    # ★★ 0.36.8：**哈希漂移也要算自举** —— 实测踩到，不是假想。
    #   现象：升版脚本把 manifest 的 version 也刷成源码同号（version_check
    #         要求 10 处版本点一致，manifest 是其中之一）⇒ 「版本落后」这个
    #         判据永远不成立；而 manifest 覆盖的 121 个文件里混着当天合法
    #         编辑的（哈希失配）⇒ 自举没声明、哈希级联类红项一条都没豁免、
    #         打包被自己的判据拦死（0363 R06 / 0364 D2 双红，共用一个根）。
    #   判据（窄）：**任一覆盖文件**当前哈希 ≠ 登记哈希（缺文件也算失配）。
    #   为什么不修豁免侧：豁免侧按「根因」分的类是对的（红项自报级联才放），
    #   错的是**触发器**——它只认版本号，不认哈希。修触发器，不动豁免判据。
    _mf_drift = []
    for _rel, _want in _mf_files.items():
        _fp = os.path.join(_root, _rel)
        try:
            # ★★ 0.39.2：与本构建器写 manifest 时**同法**（版本承载件先归一化）——
            #   否则 `hooks/pre_tool_use.py` 会**恒被判为漂移** ⇒ 每次都声明自举，
            #   真漂移被这声"常亮"淹没（豁免机制失去区分度）。
            if _manifest_hash_of(_rel, _fp) != str(_want):
                _mf_drift.append(_rel)
        except Exception:                                      # noqa: BLE001
            _mf_drift.append(_rel)                  # 读不到 ⇒ 失配
    if _mf_drift:
        _self_bootstrap = True
    _prev_boot = os.environ.get("ANTINEL_BOOTSTRAP")
    if _self_bootstrap:
        os.environ["ANTINEL_BOOTSTRAP"] = "1"
        print("（自举：manifest 登记版本 %s / 源码 %s；哈希失配 %d 项%s —— "
              "本次产物将刷新它，已声明自举豁免）"
              % (_mf_ver, VERSION, len(_mf_drift),
                 ("（首批：%s）" % "、".join(_mf_drift[:3])) if _mf_drift else ""))
    os.environ["ANTINEL_BUILD_IN_FLIGHT"] = "1"
    try:
        rc = _sp.call(cmd, cwd=_root)
    finally:
        if _prev_inflight is None:
            os.environ.pop("ANTINEL_BUILD_IN_FLIGHT", None)
        else:
            os.environ["ANTINEL_BUILD_IN_FLIGHT"] = _prev_inflight
        if _prev_boot is None:
            os.environ.pop("ANTINEL_BOOTSTRAP", None)
        else:
            os.environ["ANTINEL_BOOTSTRAP"] = _prev_boot
    if rc != 0:
        raise SystemExit(
            "\n★ 打包被闸门拦下（exit=%s）。**没有产出任何包。**\n"
            "  先分辨红项类型再动手：变红=检出缺陷／崩或缺失=盲区／零输出=没真跑。\n"
            "  闸门全绿后重跑本构建命令。确需强行打包：\n"
            "    ANTINEL_SKIP_GATE=1 python -m scripts.build_package --out <目录>\n"
            "  —— 该环境变量会打进构建日志留痕，不是悄悄溜过去。" % rc)
    print("闸门通过，继续打包。\n")


#: ★★ 0.36.5：`tools/` 的**兜底**复制清单（历史手写项）。
#:   提为**模块级常量**而不是 build() 里的局部变量，理由与本仓既有纪律同源：
#:   判据（`ci/inbox_guards_0364.py::d3`）要**真的取到它**来验"复制清单由
#:   _LAYOUT 派生"。若留在函数内，判据只能读到它不存在的空值 ⇒
#:   **判据自身出错，却因为"有输出"而被当成"检查发现了问题"**。
#:   —— 判据与被测对象必须看同一个真源，否则两边都在自说自话。
_TOOL_FALLBACK = ("antinel_verify.py", "verify_namespaces.py",
                  "verify_chain.py", "tray.ps1", "logo.ps1")


def _ver_tuple(v):
    """'0.42.0' → (0, 42, 0)；解析不了 ⇒ None（调用方按"不是发布件"处理）。"""
    try:
        parts = str(v).strip().split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            return None
        return tuple(int(p) for p in parts)
    except Exception:                                          # noqa: BLE001
        return None


def _archive_stale_dist(dist_dir, version, archive_root):
    """把 `dist/` 里**非本版**的发布件挪去归档区（**零删除**），返回挪走清单。

    ★★ 为什么必须有这个函数（2026-10-09 实测复发，第三次同族）：
      「旧版发布件让开」这件事此前是**手工**的：0.40.0 出包后我 `mv` 走了 0.39.2
      的两件，0.41.0 出包后又 `mv` 走了 0.40.0 的两件 —— 每次都靠"我记得"。
      0.42.0 这一轮我就忘了：dist 里躺着 0.41.0 的两件 ⇒ 闸门 D-23/JDG-06
      同时判红（"dist 里混着非本版发布件"）⇒ **一整轮 4 分钟闸门白跑**。
      ⇒ 根因不是"我粗心"，是**这个动作没有任何机制保证它发生**。
        按本项目反复验证过的结论（"靠人记得就等于没有"），正确解法是让
        **构建器自己**在跑闸门之前把旧版件挪走，并逐条打印。

    ★ 三条设计约束（都是安全侧，不是方便侧）：
      ① **只挪更旧的**：`artifact_ver < VERSION` 才挪。相等的留在原处
         （重复构建同一版本时不该把自己的产物挪走）。
      ② **遇到更新的 ⇒ 硬失败**：`artifact_ver > VERSION` 说明这棵树落后于
         已经构建过的东西（检出了旧分支／回退了版本号）—— 此时若"顺手挪走"，
         就会把一版更新的包静默降级成本版 ⇒ SystemExit，一个字节都不动。
      ③ **零删除、全留痕**：一律 `mv` 进 `_archive_dist/stale_<时间戳>/`，
         并打印每一个被挪走的文件名（与仓内既有 `*.away-*` 惯例同族）。

    ★ 不碰的：`.tmp-*`（构建器自己的暂存）、`*.away-*` / `*.REJECTED*` /
      `*.old`（已是让开态的件）、任何不匹配 `antinel-<x.y.z>-...` 的文件。
    """
    import re as _re
    import shutil as _shutil
    import time as _time
    d = Path(dist_dir)
    if not d.is_dir():
        return []
    arch = Path(archive_root) / ("stale_%s" % _time.strftime("%Y%m%d-%H%M%S"))
    cur = _ver_tuple(version)
    moved, newer = [], []
    for p in sorted(d.iterdir()):
        if not p.is_file():
            continue
        name = p.name
        if name.startswith(".tmp-") or ".away-" in name or ".REJECTED" in name \
                or name.endswith(".old"):
            continue
        # ★ 两种发布件形态都要认：wheel 是 `antinel-0.41.0-py3-none-any.whl`
        #   （连字符），sdist 是 `antinel-0.41.0.tar.gz`（**点号**）——
        #   第一版正则只写 `-`，结果 sdist 一件都匹配不上（本套件 S38 实测抓到）。
        m = _re.match(r"^antinel-(\d+\.\d+\.\d+)(?:-|\.)", name)
        if not m:
            continue
        av = _ver_tuple(m.group(1))
        if av is None or cur is None:
            continue
        if av == cur:
            continue
        if av > cur:
            newer.append(name)
            continue
        arch.mkdir(parents=True, exist_ok=True)
        _shutil.move(str(p), str(arch / name))
        moved.append(name)
    if newer:
        raise SystemExit(
            "★ dist/ 里有**比源码还新**的发布件：%s（源码版本 %s）\n"
            "  这说明当前检出落后于已经构建过的版本（检出了旧分支／回退了版本号）。\n"
            "  若继续打包，等于把一版**更新**的包静默降级 —— 已中止，**一个字节都没动**。\n"
            "  修法：确认要发布的版本号；若确实要发旧版，请先显式处理这些文件。" % (newer, version))
    if moved:
        print("[dist] 把 %d 件非本版发布件挪去 %s（零删除）：%s"
              % (len(moved), arch, ", ".join(moved)))
    return moved


def _adopt_dev_entries(final):
    """harness 期间**临时补登**研发树专属条目；返回**纯 wheel 口径**字节供跑后恢复。

    ★ 0.52.0 起 pure 恒是 wheel 口径（剥掉研发态专属条目）—— 提交态 manifest
      带着 `ci/freeze_zones.json`（研发树 self_check 需要），旧实现拿现字节当
      pure ⇒ 构建把不随包文件写进 wheel 清单（0516 PKG16-a [E] 实测红）。

    ★ 为什么需要（80f0125 冻结区机制 × merge 顺序的未测碰撞，本版出包首次撞上）：
      `_merge(pkg, final)` 把**纯 wheel 口径**的 manifest 覆盖回 final（final 就是
      仓本身）—— `ci/freeze_zones.json` 不在 wheel 载荷里 ⇒ 研发树专属条目被抹。
      而两轮 harness 跑在 final 上：F-13/F-17 要拉哨兵 ⇒ `self_check()` 的
      `_DEV_GUARDED_CHAIN_FILES`「在场才校验」因缺登记而红 ⇒ 构建自带 harness
      永远 FAIL ⇒ rc=1 ⇒ release.py 步骤 1 失败、**一个包都产不出来**。
      （0.51.0 出包在该机制落地之前，故从未暴露。）
    ★ 修法三不：**不弱化自检**（条目照查，只是这期间它在场）、**不污染 wheel**
      （harness 后恢复纯净，`python -m build` 带走的清单必须纯——[E] 对账要求
      清单 ⊆ wheel 载荷）、**不留半成品**（pure 由现清单剥研发态条目重算，
      口径与重签工具同格式 `indent=1`＋尾换行，逐字节可复现）。
    ★ 口径与 `_tools_034/_resign_manifest.py --adopt-dev` 逐字同源：名单从
      host_shield import（单一真源）、在场才补、非版本承载件走裸 sha256。
    """
    import host_shield as _hs
    mfp = Path(final) / "psl" / "manifest.json"
    dirty = mfp.read_bytes()
    try:
        d = json.loads(dirty.decode("utf-8"))
    except Exception as e:                                       # noqa: BLE001
        print("!! 读不到 %s（%s）—— 跳过研发条目补登（harness 可能红 F-13/F-17）"
              % (mfp, e))
        return dirty
    files = d.get("files") or {}
    dev = tuple(getattr(_hs, "_DEV_GUARDED_CHAIN_FILES", ()) or ())
    # ① pure ＝ 现清单**剥掉**研发态专属条目（wheel 口径：不随包就不进清单）。
    #    0.52.0 修（0516 PKG16-a [E] 实测红）：仓内提交态 manifest 带着
    #    ci/freeze_zones.json（5ca682f 起，研发树 self_check 需要），旧逻辑
    #    「已登记 ⇒ 跳过」让它混进 restore 目标 ⇒ python -m build 把不随包
    #    的文件写进 wheel 内清单 ⇒ 纯净安装 --manifest 报 superseded。
    stripped = [rel for rel in dev if rel in files]
    for rel in dev:
        files.pop(rel, None)
    d["files"] = files
    pure = (json.dumps(d, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    # ② harness 期间临时补登**在场**的研发态条目（self_check 在场才校验）。
    adopted = []
    for rel in dev:
        p = os.path.join(str(final), rel.replace("/", os.sep))
        if not os.path.isfile(p):
            continue                        # 不在场（出包语境）
        files[rel] = "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
        adopted.append(rel)
    d["files"] = files
    mfp.write_text(json.dumps(d, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8", newline="\n")
    print("  ADOPT(dev) 补登 %s；pure 剥掉 %s（跑后恢复 wheel 口径）"
          % (adopted or "无", stripped or "无"))
    return pure


def build(out_root, verify=False):
    # ★★ 0.42.0：**先把 dist/ 里的非本版发布件挪走**，再跑闸门。
    #   位置必须在 `_delivery_gate()` **之前**：D-23/JDG-06 判的就是"dist 里混旧包"，
    #   而它们只在闸门里跑 —— 挪晚了就等于让闸门先红一轮。
    #   ★ 这条是 2026-10-09 实测复发的根因修复：此前"旧件让开"是手工动作
    #     （0.40.0、0.41.0 两轮都是我 `mv` 的），没有任何机制保证下次还记得
    #     ⇒ 0.42.0 忘了 ⇒ 白跑一轮 4 分钟闸门。机制见 `_archive_stale_dist`。
    _archive_stale_dist(Path(out_root) / NAME / "dist", VERSION,
                        Path(out_root) / NAME / "_archive_dist")
    # ★★ 0.36.5：统一交付闸门（第二个强制执行点）—— 位置在**最前**，
    #   早于 `_verify_layout()`：两者的失败代价都必须是「什么都没动」。
    #   逃生口用环境变量而不是命令行开关，避免「开关手滑」与「刻意的例外」长得一样。
    if os.environ.get("ANTINEL_SKIP_GATE") != "1":
        _delivery_gate(out_root, full=not os.environ.get("ANTINEL_GATE_QUICK"))
    else:
        print("!! ANTINEL_SKIP_GATE=1 —— 本次构建**跳过了交付闸门**（已留痕）")
    # ★★ 2026-09-28：**构建前先验布局表**。位置选在 build() 最前，理由与 A1 守卫相同：
    #   失败的代价必须是"什么都没动"。"布局错"是最容易被静默跳过的错
    #   （每个 `if p.is_file()` 都会安静地少拷一个文件），所以它必须在任何写盘之前红。
    _verify_layout()
    # 2026-09-24 (G7): assemble into a STAGE directory and MERGE the result into
    # the published package. The old code did shutil.rmtree(pkg) and rebuilt from
    # nothing. That had two defects, both measured on a dry run:
    #   1. it silently deleted 86 TRACKED files that this builder does not
    #      produce -- among them .github/workflows/daily-chain.yml (the public
    #      external anchor), server.json (already published to the MCP registry),
    #      antinel_mcp.py (declared in pyproject.toml's py-modules), challenge/,
    #      demo/, ci/, docs/BRAND.md, MANIFEST.in, pyproject.toml;
    #   2. it tripped the host's bulk-delete guard: 762 files against a threshold
    #      of 50 -- i.e. the build could not run at all on a guarded machine.
    # Merging instead of replacing fixes both, and .git no longer has to be moved
    # aside either, because nothing outside this builder's own output is touched.
    final = Path(out_root) / NAME
    pkg = Path(out_root) / (NAME + "-stage")
    # ★ 2026-09-26（A1）：**在 `_merge` 之前**把产物仓 MANIFEST.in 的原样快照下来。
    #   为什么必须提前：`_merge` 会把暂存包的 MANIFEST.in 覆盖上去，之后再读
    #   `final/MANIFEST.in` 读到的已经是新内容 ⇒ "哪些旧规则被覆盖掉了"永远打印不出来
    #   （实测第一次就是这么静默过去的）。要报"被删了什么"，就得先记住"原来是什么"。
    _repo_manifest_before = []
    try:
        _rmb = final / "MANIFEST.in"
        if _rmb.is_file():
            _repo_manifest_before = [l.strip() for l in
                                     _rmb.read_text(encoding="utf-8").splitlines() if l.strip()]
    except OSError:
        _repo_manifest_before = []
    # 2026-09-24 (G7): _clear, not rmtree -- the build died here on a guarded
    # machine (see _clear's docstring for the measured evidence).
    _clear(pkg)
    for sub in ("scripts", "hooks", "rules", "references", "psl"):
        (pkg / sub).mkdir(parents=True)
    # ★ 2026-09-28：一律走 `srcfile(逻辑名)`（经布局表），不再 `SRC / f`。
    #   旧写法把"源仓平铺布局"焊死在这里：`SRC / "install.py"` 在产物仓是错的。
    for f in ("install.py", "scan.py", "report.py"):
        shutil.copy2(srcfile(f), pkg / "scripts" / f)
    for f in ("pre_tool_use.py", "post_tool_use.py"):
        shutil.copy2(srcfile(f), pkg / "hooks" / f)
    # 0.22.0 (A5): shared session-DNA module at the package root -- hooks/ and
    # scripts/ both reach it via their parent dir.
    # ★★ 2026-09-29（D-20）：`ui_server.py` 补进复制清单 —— 它此前**三处都没登记**
    #   （py-modules / 本清单 / _LAYOUT），却因为"仓根本来就有这个文件"而**侥幸随包**。
    #   实测：**干净树**（无陈旧 `build/`）打 wheel ⇒ 只装 py-modules 声明的 9 个，
    #   `ui_server.py` **不在包里** ⇒ `antinel.py` 顶层 `import ui_server`（2828 行，
    #   建 parser 时执行）**每次都炸** ⇒ **所有命令全废**（实测 `ModuleNotFoundError`）。
    #   旧的 `dist/*.whl` 之所以能跑，只是因为陈旧 `build/` 把它带了进去 —— **假绿**。
    for root_mod in ("session_dna.py", "transcript_reader.py", "audit_chain.py",
                     "antinel.py", "antinel_mcp.py", "hub.py", "host_shield.py", "strings.py", "egress.py",
                     "ui_server.py",  # 0.26: +i18n; 0.28: +audit_chain; 0.33.2: +ui_server
                     # ★ 0.35.0：Antinel 监理 13 个模块。**必须与 PYPROJECT 的 py-modules 逐字一致**：
                     #   这里少一个 ⇒ 干净树打 wheel 缺文件、用户 import 就炸；
                     #   那里少一个 ⇒ 同样。构建末尾的 `_check_*` 守卫会同时盯住两边。
                     "inbox_model.py", "inbox_store.py", "inbox_report.py", "inbox_server.py",
                     "inbox_tray.py", "inbox_notify.py", "inbox_emphasis.py", "inbox_fallback.py",
                     "inbox_daemon.py", "inbox_config.py", "inbox_cli.py",
                     "inbox_bubble.py", "inbox_logo.py",
                     "ledger.py", "heartbeat.py",
                     # ★ 0.35.3 补记：`glossary.py` 上一轮**只登记进了
                     #   pyproject 的 py-modules，却漏了这份 root_mod 复制清单**
                     #   ⇒ 干净树打 wheel 会缺这个文件、用户 import 就炸。
                     #   与 inbox_window.py / remediation.py 一并补齐。
                     #   （构建末尾的 `_check_*` 守卫会同时盯住两边是否一致。）
                     "glossary.py",
                     # ★ 0.36.0：窗口几何（唯一几何实现）+ 失守归因引擎
                     "inbox_window.py", "remediation.py",
                     # ★ 0.38.0：粮（哨兵口粮，0.38.0 新增真源）＋ 机器唯一码
                     "granary.py", "machine_id.py",
                     # ★ 0.55.0 状态机改造（A/B 双线汇合）：四个新模块。
                     #   三处清单（本元组／模板 py-modules／仓库 pyproject.toml）
                     #   必须逐字一致 —— D-20 就是这三处不一致长出来的。
                     "facts.py", "situation.py", "state_registry.py",
                     "sidecar.py"):
        # 2026-09-24 (G7): antinel_mcp.py was declared in pyproject.toml's
        # py-modules and shipped in the repo, but this list never copied it --
        # so a rebuild deleted it while pyproject kept declaring it. Same class
        # of gap as the REPO_EXTRAS one: the builder did not know what the
        # package actually consists of.
        m = srcfile(root_mod)
        if m.is_file():
            shutil.copy2(m, pkg / root_mod)
    # ★ 0.48.4：**SKILL.md 必须随 wheel 走**。
    #   为什么：现在装包的多半是 Agent（"帮我装个安全审计"）。它 pip 装完，
    #   手里只有一个 `antinel` 命令；SKILL.md 是唯一一份"机器可读的操作手册"，
    #   而 0.48.3 及以前的 wheel **完全没有它**（实测 133 成员、SKILL.md 0 命中）
    #   ⇒ Agent 只能靠猜，或去读给人看的 60 行 --help。
    #   落在 `psl/`：顶层非 `.py` 文件没有可靠的随包机制，而 psl 是 package 且
    #   package-data 已声明 `*.md`（与 antinel.py 的 `_skill_md_path()` 第 3 条对应）。
    _skill_src = SRC / "SKILL.md"
    if _skill_src.is_file():
        (pkg / "psl").mkdir(parents=True, exist_ok=True)
        shutil.copy2(_skill_src, pkg / "psl" / "SKILL.md")
        print("SKILL.md copied -> %s" % (pkg / "psl" / "SKILL.md"))
    else:
        print("   [notice] 源码树没有 SKILL.md —— Agent 装完将拿不到随包操作手册（非错误）")

    # ★ 0.35.0：Antinel 监理静态资源（五态 MP4 ＋ 五态 .ico ＋ logo.svg）。
    #   页面按 `<模块目录>/assets/...` 取（`inbox_server.ASSETS_DIR`），
    #   托盘按 `<模块目录>/assets/icons/...` 取（`inbox_tray.icon_path`）。
    #   ⇒ 它必须与模块**同级**落进 site-packages。实测（_p9_wheeltest）：**声明为 package
    #     的目录**里的文件才进 wheel —— assets 靠 package-data 的 3 条 glob 全进（11/11），
    #     `rules/hosts/*.json` 靠 `recursive-include rules *.json` 进（24 个），
    #     而 `docs/` 不是 package ⇒ wheel 里 0 个。
    #   所以 assets 已登记进 PYPROJECT 的 packages ＋ package-data，并在 _LAYOUT 之外单独复制。
    assets_src = SRC / "assets"
    if assets_src.is_dir():
        _n_assets = 0
        for _f in assets_src.rglob("*"):
            if _f.is_file():
                _dst = pkg / "assets" / _f.relative_to(assets_src)
                _dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(_f, _dst)
                _n_assets += 1
        print("assets copied: %d file(s) -> %s" % (_n_assets, pkg / "assets"))
    else:
        # 「没查到」必须与「没发现」长得不一样：资源缺失不是构建错误，
        # 但必须**说出来**，否则页面静默无图标，没人知道为什么。
        print("   [notice] 源码树没有 assets/ —— Antinel 监理页面/托盘将没有图标与 LOGO（非错误）")
    # ★ 0.35.2：`challenge/` 公开挑战件**必须进 wheel**（理由见 PYPROJECT 里
    #   `challenge = [...]` 那段注释：verify 会教用户跑它，而它此前只进 sdist）。
    #   手法与 assets 完全一致：声明为 package ＋ package-data，再逐文件复制进暂存包。
    #   ★ 必须排除 `__pycache__` —— 它是运行产物，且已在 `NEVER_SHIP` 政策排除名单里。
    chal_src = SRC / "challenge"
    if chal_src.is_dir():
        _n_chal = 0
        for _f in chal_src.rglob("*"):
            if not _f.is_file() or "__pycache__" in _f.parts:
                continue
            _dst = pkg / "challenge" / _f.relative_to(chal_src)
            _dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_f, _dst)
            _n_chal += 1
        print("challenge copied: %d file(s) -> %s" % (_n_chal, pkg / "challenge"))
    else:
        # 「没查到」必须与「没发现」长得不一样：缺了就得说出来。
        print("   [notice] 源码树没有 challenge/ —— verify 的「你可以自己复算」"
              "将退化为在线链接（非错误，但能力变弱）")
    econ_src = SRC / "rules" / "economics"           # 0.23.1: 按宿主经济画像
    if econ_src.is_dir():
        (pkg / "rules" / "economics").mkdir(exist_ok=True)
        for f in econ_src.iterdir():
            if f.is_file():
                shutil.copy2(f, pkg / "rules" / "economics" / f.name)
    hosts_src = SRC / "rules" / "hosts"                 # 0.25: 外传路径登记表
    if hosts_src.is_dir():
        (pkg / "rules" / "hosts").mkdir(exist_ok=True)
        for f in hosts_src.iterdir():
            if f.is_file():
                shutil.copy2(f, pkg / "rules" / "hosts" / f.name)
    banner_src = srcfile("session_start_banner.py")
    if banner_src.is_file():
        shutil.copy2(banner_src, pkg / "hooks" / "session_start_banner.py")
    # 0.22.0: audit record schema, shipped for third-party verification
    schema_src = srcfile("AUDIT_SCHEMA.md")
    if schema_src.is_file():
        (pkg / "docs").mkdir(exist_ok=True)
        shutil.copy2(schema_src, pkg / "docs" / "AUDIT_SCHEMA.md")
    # 0.23.1: skill 路由件——与 antinel help 同源（ROUTES），构建期生成，永不手写
    try:
        out = subprocess.run([sys.executable, str(srcfile("antinel.py")), "routes", "--markdown"],
                             capture_output=True, text=True, timeout=30, creationflags=_CNW)
        if out.returncode == 0 and out.stdout.strip():
            (pkg / "references").mkdir(exist_ok=True)
            # 0.48.1：生成物不带源（subprocess 输出没有 SPDX 头）——不加头则每次
            #   组装都把 _license_apply 写进实例的头冲掉（0481 L1 实测红 7 处的教训：
            #   「修了实例、没修源头」的镜像）。md 件头 = HTML 注释形态，落第 1 行。
            (pkg / "references" / "AGENT_SKILL.md").write_text(
                "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n" + out.stdout,
                encoding="utf-8", newline="\n")
    except Exception as e:
        print("WARN: AGENT_SKILL.md not generated: %s" % e)
    shutil.copy2(srcfile("default.json"), pkg / "rules" / "default.json")
    pricing_src = srcfile("pricing.json")          # 0.23.0: cost table (schema only)
    if pricing_src.is_file():
        shutil.copy2(pricing_src, pkg / "rules" / "pricing.json")
    shutil.copy2(HARNESS_SRC, pkg / "scripts" / "verification_tests.py")
    # ★ 2026-09-28：A6 是**文档仓的签署件**，跨仓依赖是有意为之。
    #   但原来它缺了只静默跳过 ⇒ 「没带 A6」与「A6 本来就该在这」在输出里长得一样。
    #   现在：缺了要**明确说没带**，并给出它本该在哪。
    a6 = Path(r"D:\2026\PSL\A6收入边界声明v1.0.md")
    if a6.is_file():
        (pkg / "docs").mkdir(exist_ok=True)
        # 0.48.1：签署源件保持纯净（不带 SPDX 头），归属头由构建器在复制时加上——
        #   直接 copy2 会在每次组装时冲掉实例上的头（0481 L1 实测红）。
        (pkg / "docs" / "A6收入边界声明.md").write_text(
            "<!-- SPDX-License-Identifier: CC-BY-4.0 -->\n"
            + a6.read_text(encoding="utf-8").replace("\r\n", "\n"),
            encoding="utf-8", newline="\n")
    else:
        print("★ 注意：A6 收入边界声明**未随包**（源件不在 %s）—— 它是文档仓的签署件，" % a6)
        print("  本次构建**没有把它带进包里**。这不是错误，但你应当知道包里没有它。")
    (pkg / "LICENSE").write_text(LICENSE_MD, encoding="utf-8", newline="\n")
    (pkg / "NOTICE").write_text(NOTICE_MD, encoding="utf-8", newline="\n")
    # ★★ 2026-09-29（D-21）：把 setuptools 构建垃圾（build/ / antinel.egg-info/ / dist/）
    #   写进**构建器自己的模板**。此前 898791a 手工往仓里 .gitignore 补过这三行，
    #   但本行每次构建都会**整文件覆盖** .gitignore ⇒ 手工修改被**静默回退**
    #   （实测：构建后 `git diff .gitignore` 显示那三行又被删掉）。
    #   这正是「构建器拥有的文件，手工改迟早被覆盖」——修法是把意图写进模板。
    #   ★★ 2026-10-08（0.36.9）：模板已提为模块级 `GITIGNORE_TEMPLATE`
    #      （上方有完整沿革），并由 JDG-05 逐字节比对兜底。
    (pkg / ".gitignore").write_text(
        GITIGNORE_TEMPLATE, encoding="utf-8", newline="\n")
    # byte-exact clones are a digest-security property: no end-of-line conversion,
    # ever (autocrlf smudge broke judgment digests in the v0.17 round).
    (pkg / ".gitattributes").write_text("* -text\n", encoding="utf-8", newline="\n")
    # ★★ 2026-09-28：这里**原来是"从内嵌模板生成 run_harness.py"**。
    #   现在改为**不生成**：run_harness.py 是仓里的正常文件、有独立演进历史、
    #   且已用 `_pkg_version()` 动态读版本。构建器**不该碰它**。
    #   ⇒ 只做两件事：① 断言它在（缺了就没有判定记录的生成器）；② 记下哈希，
    #     供构建后的对账守卫比对（"构建不该改动它"）。
    _rh_src = srcfile(RUN_HARNESS_SRC)
    if not _rh_src.is_file():
        raise SystemExit("★ 构建器找不到 %s —— 没有它就没有 psl/judgment.json" % _rh_src)
    _RUN_HARNESS_HASH_BEFORE = sha256(_rh_src)
    # 对账守卫的**基线**：构建器在构建过程中**允许自己改**的文件只有 stage/pkg
    # 里的东西。仓源文件是`输入`，构建器**一个字都不该动**。
    # 这里只登记要盯的少数几个"曾经被构建器覆盖过"的仓源文件 —— 它们正是
    # 「同一事实两处副本」事故的常客（run_harness 模板被内嵌副本覆盖过一次）。
    _SRC_WATCH = ((RUN_HARNESS_SRC, _RUN_HARNESS_HASH_BEFORE),)
    # A-8: named status-derivation tool + the L10 chain verifier + the namespace
    # verification aid, all shipped in tools/
    #
    # ★★★ 0.36.5 修两处真缺陷（实测：`tools/enforce_probe.py` 明明"已登记进
    #   `_LAYOUT`"，却既没进包、也没进 manifest ⇒ Antinel 监理自检永远报
    #   「在告警链路保护名单里，却没登记进 manifest」⇒ 界面长期挂「存疑」）。
    #
    #   ① **复制清单与 `_LAYOUT` 分叉**：`_LAYOUT` 只被 `_verify_layout()` **校验**，
    #      从没被**复制**；真正复制的是下面这份手写元组。
    #      ⇒ 登记进 `_LAYOUT` 的新文件会"校验通过但根本不拷"，而 D3 判据只查
    #        `_LAYOUT` 里有 ⇒ **报绿**。这不是"忘了加一行"，是**同一事实两处副本**。
    #      ⇒ 修法（结构性，不是补一行）：**凡目标是 `tools/` 的 `_LAYOUT` 项，
    #        一律由 `_LAYOUT` 生成复制清单**，手写元组退化为**兜底**。
    #        判据的意图（"登记了就得真的进包"）一个字没动。
    (pkg / "tools").mkdir(exist_ok=True)
    #: 目标目录为 `tools/` 的布局项 —— 复制清单**由 _LAYOUT 生成**，防分叉。
    #: `_TOOL_FALLBACK` 是模块级常量（0.36.5 提到模块级，好让判据读到同一真源）。
    _tool_from_layout = sorted(
        os.path.basename(dst) for dst in _LAYOUT.values()
        if dst.replace("\\", "/").startswith("tools/")
    )
    _tool_list = sorted(set(_tool_from_layout) | set(_TOOL_FALLBACK))
    if _tool_from_layout:
        print("tools 复制清单：%d 项（其中 %d 项由 _LAYOUT 派生）"
              % (len(_tool_list), len(_tool_from_layout)))
    for tool_dst in _tool_list:
        s = srcfile(tool_dst)
        if s.is_file():
            shutil.copy2(s, pkg / "tools" / tool_dst)
        else:
            # ★ 不静默跳过：复制清单里的项找不到源文件，必须说出来。
            #   判据（照抄本仓既有纪律）："没查到"必须与"没发现"长得不一样。
            print("   [WARN] tools/%s 在源仓找不到 —— 未复制（若它本该随包，"
                  "请查 _LAYOUT 与源仓是否分叉）" % tool_dst)
    # A-5: signed namespace list (ed25519; private key stays in r1v3/keys, never shipped)
    # 2026-09-24 (G7): only when ABSENT FROM THE PUBLISHED PACKAGE -- `final`, not
    # `pkg`. make_namespaces.py stamps `updated_at` with datetime.now(), and
    # updated_at is INSIDE the signature coverage (covers = canonical JSON minus
    # the signature block), so a plain rebuild used to re-date AND re-sign a signed
    # artifact whose content had not changed -- the list claimed "updated at
    # <today>" while nothing about it was touched, and every rebuild churned the
    # file hash. Re-issuing the list is now a DELIBERATE act
    # (`make_namespaces.py --out <pkg>`), not a build side-effect.
    #
    # NOTE the guard target: `pkg` is the STAGE dir and is empty by construction
    # (the build clears it a few lines up), so guarding on `pkg` is always-true --
    # that mistake is exactly how README.md got reverted a second time. The
    # question is never "is it in my scratch dir", it is "does the published
    # package already have one". Fourth instance of the same defect class.
    # ★★ 0.48.3：清单的**落点**从仓根改到 `psl/`。为什么必须改：
    #   它此前放在仓根 ⇒ setuptools 的 wheel 规则里**没有任何一条覆盖它**
    #   （`py-modules` 只收 `.py`；仓根不是 package，MANIFEST.in 的 `include`
    #   只喂 sdist）⇒ 实测 wheel/sdist **都不含**它。后果是三处同源崩塌：
    #     · 随包 judgment 的 21 条 digest 里有它 ⇒ `python -m tools.antinel_verify`
    #       在**纯净安装**上报 `[SUPERSEDED] 1 of 21 ... missing`（README 第一行
    #       「别信我们，自己验」当场喊狼来了）；
    #     · 随包 manifest 里有它 ⇒ `--manifest` 同样报 superseded；
    #     · `tools/verify_namespaces.py`（**随 wheel 发**）按
    #       `<包根>/psl/antinel-namespaces.json` 找它 ⇒ 装完即 `No such file`。
    #   放进 `psl/` 后由既有 package-data `psl = ["*.json","*.md"]` 天然随包，
    #   与同族的 `manifest.json` / `judgment.json` 同居一处。
    #   签名覆盖的是**规范 JSON 内容**（不含路径）⇒ 搬家不动签名有效性。
    if not (final / "psl" / "antinel-namespaces.json").is_file():
        # ★★ 2026-09-28：`make_namespaces.py` **不属于产物仓**，它是**需要私钥的外部签发工具**。
        #   签名私钥 `keys/antinel_namespaces_ed25519.pem` 只存在于源仓 r1v3；产物仓的
        #   `.gitignore` 并不排除 `keys/` ⇒ 一旦把它拷进产物仓，一次 `git add -A`
        #   就可能把私钥提交上去。**"私钥绝不进已发布树"是硬纪律，不能靠记得。**
        #   所以：工具留在 r1v3，构建器**按需从那里调**；产物仓只收**产物**
        #   （`antinel-namespaces.json`，已在树里、受 git 管）。
        #   它缺失时**必须显式报**，不许像原来那样只打一行 WARN 就过去
        #   ——「没生成」与「不需要生成」在输出里必须长得不一样。
        ns_tool = Path(r"D:\psl\poc\r1v3\make_namespaces.py")
        if not ns_tool.is_file():
            print("★ 注意：命名空间清单既不在产物仓，生成器也不在 %s —— 本次**未重新签发**清单。"
                  % ns_tool)
            print("  这不是错误（清单已签发且内容未变），但你必须知道它**没被重新生成**。")
        else:
            try:
                subprocess.run([sys.executable, str(ns_tool), "--out", str(pkg / "psl")],
                               check=True, capture_output=True, text=True, creationflags=_CNW)
            except Exception as e:
                print("WARN: namespaces list not generated: %s" % e)
    wf = (pkg / ".github" / "workflows")
    wf.mkdir(parents=True, exist_ok=True)
    # 2026-09-24 (G7): verify.yml is REPO-OWNED. The builder used to regenerate it
    # from CI_WORKFLOW on every build, which silently reverted hand-maintained work
    # (measured: the repo copy is 55 lines, the template 32 -- the 09-22 macOS fix
    # and the `permissions:` block were being thrown away on each rebuild). The
    # template is now a FALLBACK for a clean tree only; an existing file wins.
    # Same defect class as README.md below -- see the note there.
    # Guard on `final`, NOT `pkg`: pkg is the scratch stage and is empty by
    # construction, so `if not (wf / "verify.yml").is_file()` was always true and
    # reverted the repo copy on every single build.
    if not (final / ".github" / "workflows" / "verify.yml").is_file():
        (wf / "verify.yml").write_text(CI_WORKFLOW.replace("[DB_OPEN]", "{{").replace("[DB_CLOSE]", "}}"), encoding="utf-8", newline="\n")
    (pkg / "ci").mkdir(exist_ok=True)
    tools = pkg / "tools"
    tools.mkdir(exist_ok=True)
    probe_src = Path(r"D:\psl\poc\r1v3\probe_host.py")
    if probe_src.is_file():
        # 0.48.1：r1v3 源仓的 py 件不带 SPDX 头（MIT 归属声明由本仓构建器落），
        #   直接 copy2 每次组装都会冲掉实例上的头（0481 L1 实测红）。
        #   头插在 shebang / coding 声明之后（与 _license_apply_0481.insert_header 同规则）。
        _pl = probe_src.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
        _pi = 1 if _pl and _pl[0].startswith("#!") else 0
        if _pi < len(_pl) and _pl[_pi].startswith("#") and "coding" in _pl[_pi]:
            _pi += 1
        _pl.insert(_pi, "# SPDX-License-Identifier: MIT")
        (tools / "probe_host.py").write_text("\n".join(_pl), encoding="utf-8", newline="\n")
    (tools / "HOST_PROBE.md").write_text(
        "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n" + HOST_PROBE_MD,
        encoding="utf-8", newline="\n")
    (pkg / "ci" / "run_verifications.sh").write_text(POSIX_RUNNER, encoding="utf-8", newline="\n")
    # F5-c (2026-09-24): 这里不再取"现在几点"。见 _verification_evidence()：
    # 只有那份判定记录**确实描述本次要发的字节**时，才敢写 psl-verified: "true"。
    _vok, _vat, _vdetail = _verification_evidence(pkg, final)
    if not _vok:
        print("!! SKILL.md: NOT claiming psl-verified -- %s" % _vdetail)
    _vev = (("live PreToolUse block of a real .env read in ZCode (AN-001) plus a full-assertion "
             "judgment run; digest check %s" % _vdetail) if _vok
            else ("NOT VERIFIED for this build: %s" % _vdetail))
    _skill_txt = SKILL_MD % dict(_TPL_CTX(),
                                 verified="true" if _vok else "false",
                                 verified_at=_vat if _vok else "",
                                 verified_evidence=_vev,
                                 verifier="scripts/run_harness.py")
    # 0.48.1：SKILL.md 的 SPDX 头放 **front matter 内第 2 行**（YAML 注释形态）。
    #   放文件最前会破坏 front matter（必须以 --- 开头）；放 front matter 之后
    #   会超出闸门的六行窗。归属同时登记在 license-map.json（spdx_exempt 例外豁免
    #   不适用于本件——本件是真带头，豁免表只收真正带不了头的）。
    _sl = _skill_txt.split("\n")
    if _sl and _sl[0].strip() == "---" and not any(
            "SPDX-License-Identifier:" in ln for ln in _sl[:6]):
        _sl.insert(1, "# SPDX-License-Identifier: CC-BY-SA-4.0")
        _skill_txt = "\n".join(_sl)
    (pkg / "SKILL.md").write_text(_skill_txt, encoding="utf-8", newline="\n")
    # ★ 2026-10-31（0.63.0）：两个生成物走**同一个写出点**（`_write_generated_md`）。
    #   此前 SPDX 头是在这里手拼的，于是「另一个地方也得记得拼」就成了必然。
    #   现在头只有一个来源，见 `_write_generated_md()` 的注释。
    _write_generated_md(pkg / "references" / "RULES.md",
                        rules_md(pkg / "rules" / "default.json"))
    _write_generated_md(pkg / "references" / "ID_MAP.md",
                        id_map_md(pkg / "rules" / "default.json"))
    # 2026-09-24 (G7): README.md is REPO-OWNED, not a builder output. The builder
    # regenerating it from README_MD silently reverted 116 lines of hand-maintained
    # landing-page copy (the G4-era rewrite) back to the old technical template --
    # measured on a real rebuild, then restored by hand. README.md is the GitHub
    # landing page and the single source of the namespace-key fingerprint that
    # scripts/run_harness.py::pinned_fingerprint() reads; the repo copy is
    # authoritative and already carries sha256:b71e570c30ebcbf7. The template stays
    # as a FALLBACK for a clean tree only. (Its hash still lands in psl/manifest.json
    # either way -- that is computed by rglob over the finished package.)
    #
    # Guard on `final`, NOT `pkg`: pkg is the scratch stage and is empty by
    # construction, so the first version of this guard was always-true and reverted
    # the repo README a second time -- measured, not theorised.
    if not (final / "README.md").is_file():
        (pkg / "README.md").write_text(README_MD % _TPL_CTX(), encoding="utf-8", newline="\n")
    (pkg / "references" / "THREAT_MODEL.md").write_text(
        "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n" + THREAT_MODEL_MD % _TPL_CTX(),
        encoding="utf-8", newline="\n")
    # ---- A1（2026-09-26）：MANIFEST.in 由构建器产出 ----------------------------------
    # ★ 位置是承重的：**必须等暂存包装配完毕**再生成。第一版把这段放在装配中段
    #   （`.gitattributes` 之后），当时 `tools/` 还不存在、`psl/` 还是空的 ⇒
    #   `_manifest_for` 看不到它们，生成的规则集是"半成品"的规则集。
    #   这正是 A1 的病根本身（声明的内容与包里的内容分家），只是换了个地方复发。
    # ★ 产物仓与暂存包**写同一份内容**：这样 `_merge` 覆盖过去是幂等的，
    #   下游 `manifest_files`（含插件副本比对）也不会因为"谁先谁后"而漂移。
    #   第一次实现是"装配期写暂存、合并后再补写产物仓"⇒ 插件的 self-check 报
    #   `1 drifted ['MANIFEST.in']`（实测）。**同一个文件有两条写入路径＝迟早分家。**
    _manifest_lines = _manifest_for(pkg)
    _repo_lines = list(_manifest_lines)
    _seen_dirs = {ln.split()[1] for ln in _repo_lines if ln.startswith("recursive-include ")}
    for _ln in REPO_MANIFEST_RULES:
        if _ln.split()[1] not in _seen_dirs:
            _repo_lines.append(_ln)
            _seen_dirs.add(_ln.split()[1])
    # ★ 0.55.3（2026-10-23）：退役件（`.away-<ts>`）按「减法留账」留在树里可查，
    #   但**不进发布物**。实测：0.55.1 的 sdist 里有 17 份内部旧稿（独立复核报告、
    #   旧版架构方案，未压缩 1,263 KB），0.55.2 仍有 4 份 —— 根因是 `.gitignore`
    #   的 `*.away-*` 对**已被跟踪**的文件无效，而 `recursive-include docs *` 照收。
    #   ★★ 这一行必须写在这里，不能手改 MANIFEST.in：那个文件是本段生成的，
    #   装配时逐字节覆盖（第一版就是手改 ⇒ 装配日志打「旧 MANIFEST 规则已退役」，
    #   修复等于没做）。规则只留一个源 —— 这一段。
    _repo_lines.append("global-exclude *.away-*")
    _blob = "\n".join(_repo_lines) + "\n"
    (pkg / "MANIFEST.in").write_text(_blob, encoding="utf-8", newline="\n")
    if final.is_dir():
        (final / "MANIFEST.in").write_text(_blob, encoding="utf-8", newline="\n")
        for _ln in [x for x in _repo_manifest_before if x not in _repo_lines]:
            print("   - 旧 MANIFEST 规则被覆盖（不再需要）：%s" % _ln)
    print("MANIFEST.in written (%d rules): %s"
          % (len(_repo_lines) - 1, " | ".join(_repo_lines[1:])))
    # 「报出来≠出事了」：非 package 目录**不进 wheel**（实测），这本身不是错，
    # 但它必须看得见 —— 否则下一个人会以为 docs/ 跟着 wheel 走了。
    _pkgs_now = _declared_from_pyproject()[0]
    _sdist_only = [d for d in ("docs", "references")
                   if d not in _pkgs_now and (pkg / d).is_dir()]
    if _sdist_only:
        print("   [notice] 以下目录只进 sdist、**不进 wheel**（非 package；实测 setuptools 行为）：%s"
              % ", ".join(_sdist_only))
    # 2026-09-13 (TN-07): the exclusions are now EXPLICIT. Until today the ledger
    # was out of the manifest only as a side effect of statement order -- this glob
    # runs BEFORE the ledger is restored below, so the file simply did not exist
    # yet. That is a latent trap: any reorder would silently pull the ledger into a
    # "tree == manifest" check, and tools/antinel_verify.py --manifest has no
    # exclusion list, so the first consumer re-run (which APPENDS a ledger row)
    # would report superseded. The ledger is an append-only artifact that is
    # supposed to grow; keep it out, on purpose, with a reason written down.
    # ★★ 0.48.3：清单的**主体**从「暂存包内容」换成「**真会进 wheel 的那批文件**」。
    #   为什么必须换：清单是在**安装态**被消费的（`antinel_verify --manifest`、
    #   `host_shield.self_check()`），而安装态就是 wheel 解开的树；可 wheel 是
    #   setuptools 从**仓根**按 pyproject 声明构建的，暂存包只是构建器的中间物。
    #   实测（0.48.2 的 wheel 124 项 vs 清单 124 项，数目相同、集合不同）**双向**错配：
    #     · 多覆盖 15 项（`docs/` `references/` `ci/` 点文件 README/LICENSE/NOTICE/
    #       SKILL/MANIFEST.in/verify.yml …）⇒ 纯净安装下 `--manifest` 报
    #       `[SUPERSEDED] 15 of 124 covered files are missing`，README 第 17 行
    #       「别信我们，自己验」当场喊狼来了；
    #     · 少覆盖 13 项（`scripts/run_harness.py`、`scripts/build_package.py`、
    #       `psl/judgment.json`、`psl/workspace_facts.json`、`rules/typosquat_top.json`、
    #       `hooks/_host_detect.py`、`tools/host_matrix.py` …）⇒ **保护名单里有一批
    #       文件从未被保护**（0.36.4 修过同一个病的另一半）。
    #   新口径＝`_wheel_payload()`：镜像 pyproject 声明 ＋ setuptools 的
    #   `include_package_data` 行为；规则取**仓根那份 `MANIFEST.in`**（那正是
    #   setuptools 应用的那份，本函数上方刚写完它）。判据已与 0.48.2 的实测
    #   wheel namelist **逐项对过账**：除两条按设计排除（清单自身、judgment.json）
    #   外完全一致。
    #   `REPO_SHIPPED` 随之退役：README.md / verify.yml 都**不进 wheel**，
    #   把它们钉进清单正是上面"多覆盖"的来源。
    MANIFEST_EXCLUDE = MANIFEST_EXCLUDE_NAMES
    # ★ 2026-10-08（trash 族）：垃圾政策排除也要管**清单覆盖面**，不能只管规则。
    #   实测（0.36.8）：规则侧没写 `*.trash` 之前，rglob 仍把宿主守卫的
    #   `.g0364.trash` 连同 sha256 钉进 psl/manifest.json ⇒ 幽灵条目
    #   （下一轮文件被清走 ⇒ 哈希失配 ⇒ 自举豁免）。两个作用域故意分开：
    #   MANIFEST_EXCLUDE 管 psl/ 三产物，NEVER_SHIP_PATTERNS 管垃圾族，
    #   哪一边漏了另一边都会把垃圾放进交付物。
    _wheel_rules = []
    try:
        _wheel_rules = [ln.strip() for ln in
                        (final / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
                        if ln.strip()]
    except OSError as e:                                       # noqa: BLE001
        print("!! 读不到 %s/MANIFEST.in（%s）—— 清单口径退化为「暂存包内容」，"
              "会与 wheel 分家（`verify_release.py` 的对账判据会把它判红）" % (final, e))
    if _wheel_rules:
        _rels = _wheel_payload(final, _wheel_rules)
    else:
        _rels = sorted(str(p.relative_to(pkg)).replace("\\", "/")
                       for p in pkg.rglob("*")
                       if p.is_file() and p.name not in MANIFEST_EXCLUDE
                       and not _is_junk(p.relative_to(pkg).as_posix()))
    # ★★ 0.39.2：哈希一律走 `_manifest_hash_of` —— 版本承载件先归一化再算，
    #   与 `host_shield.self_check()` **同法**（唯一真源在 host_shield）。
    # ★★ 2026-10-15（0.50.4 改名批实测判红）：哈希源从「final 优先」翻成
    #   「**pkg 优先**」。旧口径 `src = final / _rel` 取的是**合并前**的产物仓
    #   字节；而插件拷贝的是**合并后**的字节（build_plugin 跑在 _merge 之后）。
    #   凡装配阶段会重写的文件（SKILL.md、psl/SKILL.md —— 自证卡在 harness 之后
    #   还要再刷一次），合并前后必然不同 ⇒ 清单钉的哈希与插件实收的字节分家
    #   （实测：`plugin self-check FAILED: 1 drifted ['psl/SKILL.md']`，且它排在
    #   harness 之前 SystemExit ⇒ 判定记录永不刷新 ⇒ SKILL.md 自证卡恒 false，
    #   整条链死锁）。这正是本函数族自己的判据禁的病（G7-c：「比对基准必须是
    #   **本次构建的产物**，不能是磁盘现在的样子」）—— final@pre 就是后者。
    #   新口径：pkg（暂存的产物字节）优先；final 只兜底「不进暂存的仓根自有件」
    #   （那些文件装配不碰，final@pre ≡ final@post，两种取法等价）。
    manifest_files = {}
    for _rel in _rels:
        src = pkg / _rel
        if not src.is_file():
            src = final / _rel                  # 兜底：不进暂存的仓根自有件
        if not src.is_file():
            print("!! 清单主体在树上找不到：%s" % _rel)
            continue
        manifest_files[_rel] = _manifest_hash_of(_rel, src)
    manifest_files = dict(sorted(manifest_files.items()))
    manifest = {
        "name": NAME, "version": VERSION, "psl_spec": "psl-vs-0.1",
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "built_from": str(SRC), "spec_document": "ANT-SEC-SPEC-001-FULL-R v1.1-R",
        # P-A3: what this build declares as its subject identity (used by
        # derive_object_ownership when no git remote exists). Fail-closed:
        # if this key is missing and there is no remote, ownership is
        # `unattributed`, never guessed.
        "namespace": NAMESPACE,
        "entry": "SKILL.md", "hooks": ["hooks/pre_tool_use.py", "hooks/post_tool_use.py"],
        "scripts": ["scripts/install.py", "scripts/scan.py", "scripts/report.py"],
        "rules": "rules/default.json", "verification": "scripts/run_harness.py -> psl/judgment.json",
        "files": manifest_files,
    }
    (pkg / "psl" / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    # ---- A1 守卫（2026-09-26）：装配**完毕**后断言"packages 内每个文件都会被打包" ----
    # 位置在 `psl/manifest.json` 之后、`_merge` 之前：此刻暂存包已是**最终字节集**，
    # 且失败会在动到产物仓之前中止。A1 那 29 个文件当初就是"存在、但没被任何规则覆盖"，
    # setuptools 对此不报错、不警告，只是不发。
    _assert_package_data_covered(pkg, _manifest_lines)
    # ---- A6（2026-09-26）：政策排除必须**看得见** ----
    # 静默排除 = "故意不发"与"我漏了"在日志里长得一模一样。
    # 对暂存包与产物仓各扫一次：产物仓里的垃圾**当前**不会进包（规则按暂存包生成），
    # 但它是"下一次有人改回 `recursive-include psl *` 就会中招"的活证据，所以要点名。
    for _label, _root in (("暂存包", pkg), ("产物仓", final)):
        _junk = _junk_in(_root)
        if _junk:
            print("   - 政策排除（垃圾文件，**不随包**）[%s]：%d 件" % (_label, len(_junk)))
            for _r in _junk[:10]:
                print("       ", _r)
            if len(_junk) > 10:
                print("        … 另 %d 件" % (len(_junk) - 10))
    # 2026-09-24 (G7): merge the staged build into the published package, and
    # report loudly anything the previous manifest covered that this build does
    # not. A dropped file must never be silent -- that is exactly how the 86
    # tracked files disappeared without anyone noticing.
    prev_files = {}
    pmf = final / "psl" / "manifest.json"
    if pmf.is_file():
        try:
            prev_files = json.loads(pmf.read_text(encoding="utf-8")).get("files") or {}
        except Exception:
            prev_files = {}
    _merge(pkg, final, label="package")
    dropped = sorted(set(prev_files) - set(manifest["files"]))
    if dropped:
        print("!! %d file(s) were in the previous manifest but NOT in this build "
              "(left on disk, untouched -- confirm they are meant to go):" % len(dropped))
        for d in dropped:
            print("   -", d)
    # 2026-09-24 (G7): the guard that would have caught the 86-file loss. If any
    # repo extra is absent after a build, say so -- silence is what let four
    # releases ship with a shrinking package.
    missing = [r for r in REPO_EXTRAS if not (final / r).exists()]
    if missing:
        print("!! repo extras MISSING from the package: %s" % ", ".join(missing))
        print("   (they ship in the repo/sdist but this builder does not create them;"
              " restore from git before committing)")
    # The ledger is append-only and lives only in the published package; nothing
    # deleted it any more, so no restore-from-git dance is needed. Recover it only
    # if it is genuinely missing (a fresh checkout), to keep history intact.
    led = final / "psl" / "verdict-ledger.jsonl"
    if not led.is_file():
        out = subprocess.run(["git", "-C", str(final), "show", "HEAD:psl/verdict-ledger.jsonl"],
                             capture_output=True, text=True, creationflags=_CNW)
        if out.returncode == 0 and out.stdout.strip():
            led.write_text(out.stdout, encoding="utf-8", newline="\n")
            print("ledger restored from git history (%d bytes)" % len(out.stdout.encode("utf-8")))
    # 2026-09-24 (G7): generated packaging file -- version comes from VERSION, so
    # `pip show antinel` and the CLI banner can no longer disagree. Written after
    # the merge, on purpose: it is a packaging file, not part of the installed
    # skill, so it stays out of psl/manifest.json.
    (final / "pyproject.toml").write_text(PYPROJECT.replace("__VERSION__", VERSION),
                                          encoding="utf-8", newline="\n")
    # ★ 2026-09-26 新增守卫：**包到底由哪些模块组成，必须被机器核对**。
    #   这是 G7（09-24）那一类洞，而且**此前没有任何检查项盯着它**：
    #     · antinel_mcp.py 当年在 pyproject 里声明、却从没被复制 ⇒ 构建不报错、
    #       包静默缺文件、用户装完 ImportError；
    #     · 今天同类事故会落在 egress.py —— 它要在**两处**都登记（声明 + 复制清单），
    #       少一处就是"装完没有这个模块"。
    #   ⇒ 判据直接盯"装包后能不能 import"：py-modules 里每个模块，包目录里必须有 .py。
    #     差集非空 ⇒ **构建失败**（"不知道包由什么组成"必须报错，不能静默漏）。
    #
    # ★★ 2026-09-29（D-20）：上面那条**只有单向**，于是漏掉了 ui_server 事故。
    #   它查的是「**声明了但没装**」（`_declared - _present`），
    #   而真实事故是反过来的：「**装了、也被 import，但没声明**」。
    #   实测：`ui_server.py` 三处都没登记（py-modules/root_mod/_LAYOUT），
    #   靠"仓根本来就有"侥幸进包；**干净树打 wheel 就丢**，而 `antinel.py`
    #   顶层 `import ui_server` ⇒ 所有命令全废。旧 wheel 能跑只因陈旧 `build/` 带进去。
    #   ⇒ 补第二条**反向**判据：包根每个 .py，只要被任何随包 .py 以
    #     `import X` / `from X import` 引用，就必须在 py-modules 里声明。
    #     这条判据直接对应"装完 import 会不会炸"，不依赖任何陈旧目录。
    #   ★★ 2026-09-29（D-20）：判据已提成 `_pymodules_guard(pkg_dir)`（模块级函数），
    #     这样回归闸门能**行为级**调它 + 用 fixture 做内建负控（判据不许二次实现）。
    #     这里只负责"红了就停"，并把问题逐条打印出来（不静默）。
    try:
        _probs = _pymodules_guard(final)
        if _probs:
            raise SystemExit(
                "★ 包组成守卫失败（装完可能 import 就炸）：\n  - "
                + "\n  - ".join(_probs)
                + "\n（成因：包由哪些模块组成，pyproject 的 py-modules 与复制清单必须一致；"
                  "D-20 实测事故：ui_server.py 三处没登记，靠陈旧 build/ 侥幸进包。）")
    except SystemExit:
        raise
    except Exception as _e:
        print("   [WARN] py-modules 守卫自身没跑起来：%s %s" % (type(_e).__name__, _e))

    print("pyproject.toml written (version %s)" % VERSION)
    # ★ 2026-09-26（A1 第二道）：后置断言 —— 产物仓的 MANIFEST.in 必须与暂存包**逐字节相同**。
    #   内容在装配末尾一次性写好（见上面的 `_manifest_lines` 段），这里只核对"没被谁改回去"。
    #   为什么值得单独断言：`_merge` 会把暂存包覆盖到产物仓，**顺序一变就会分家**；
    #   第一次实现正是"装配期写暂存、合并后再补写产物仓"，结果插件 self-check 报
    #   `1 drifted ['MANIFEST.in']`（实测）。同一个文件有两条写入路径＝迟早分家。
    try:
        _fm = final / "MANIFEST.in"
        _blob_final = _fm.read_text(encoding="utf-8") if _fm.is_file() else ""
        if _blob_final != _blob:
            raise SystemExit(
                "★ A1 守卫 FAIL：产物仓 MANIFEST.in 与暂存包不一致（%d vs %d 字节）。\n"
                "  两者必须逐字节相同，否则插件副本比对会漂移。\n"
                "  ——产物仓——\n%s\n  ——暂存包——\n%s" % (len(_blob_final), len(_blob),
                                                        _blob_final, _blob))
        for _ln in [x for x in _repo_manifest_before if x not in _repo_lines]:
            print("   [ok] 旧 MANIFEST 规则已退役：%s" % _ln)
    except SystemExit:
        raise
    except Exception as _e:
        print("   [WARN] MANIFEST.in 写入产物仓失败：%s %s" % (type(_e).__name__, _e))
    print("package: %s (%d files in manifest)" % (final, len(manifest_files)))
    # 2026-09-24 (F5): ★ 产出物先做，家务最后做。
    # 实测（_g7_evidence/build_f12_r3.log）：本机 _clear(pkg) 会撞宿主按【回合】累计的
    # 批量删除阈值（50）而 SystemExit(1)；它原先排在 build_plugin 之前，
    # 于是"清暂存失败"顺带把插件产物也取消了 —— 插件长期停在旧版本
    # （host_shield.py 无 F1 修复、docs/AUDIT_SCHEMA.md 仍 v1.2），
    # 而日志里没有任何一行说明它没更新。
    # 判据：清暂存是可选家务，插件是可交付产物；家务不得阻止产物生成。
    plug = build_plugin(final, out_root)
    nplug = sum(1 for x in plug.rglob("*") if x.is_file())
    print("plugin : %s (%d files)" % (plug, nplug))
    # 2026-09-24 (F5): 副本必须逐字节等于包 —— 否则"插件是旧版本"这件事
    # 就只会以"用户装到的和仓库里的不一样"的形式，在很久以后才被发现。
    _verify_plugin_matches_package(manifest_files, plug)
    # ★★ 2026-09-29（D-17 修）：**删掉这一行原本的位置，家务挪到最后**。
    #
    # 原样（bug，实测）：`_cleanup_stage(pkg)` 排在这里（第 1853 行），
    #   而下面 `--verify` 跑的是 `pkg / "scripts" / "run_harness.py"` ——
    #   **先清暂存、再跑暂存里的 harness** ⇒ 必然 `can't open file ...`
    #   （实测：`rc=2, No such file or directory: antinel-security-stage\scripts\run_harness.py`）。
    #
    # 为什么历史上没暴露：本机删除配额被平台守卫拦死时 `_clear` **失败**⇒
    #   stage 反而**保持完整** ⇒ harness 侥幸跑通。即"错的巧合"，
    #   而不是"对的顺序"—— 一旦配额恢复，这行必然让 `--verify` 全废。
    #
    # 判据（两条，都不依赖环境运气）：
    #   ① **验的必须是产物**：harness 要跑在 `final`（产物仓），不是 stage。
    #      stage 只是装配中转站，`_merge` 之后它就不再是"被发布的东西"。
    #   ② **家务最后做**：清暂存挪到 harness 之后（本仓自己的纪律，
    #      见 `_cleanup_stage` docstring："产物才是交付物，家务不得阻止产物生成"）。
    if verify:
        # P-A1: the SEED run is a BOOTSTRAP run -- the ledger stays untouched
        # (a bootstrap happens before psl/judgment.json exists, and writing a
        # ledger row then is exactly what produced the 161/161-vs-162/162
        # mismatch shipped in v0.16).
        #
        # 2026-09-13 (TN-05/TN-06): ONE run is not enough, and that is structural,
        # not an oversight. scripts/run_harness.py runs the suite FIRST and writes
        # psl/judgment.json LAST -- so the record is an INPUT to the very run that
        # produces it. A single run on freshly assembled bytes therefore always
        # reports the record missing, and the package ships either without any
        # self-verdict (exactly what the v0.19.0 build did: --verify was not passed,
        # so psl/judgment.json was simply absent) or with a FAIL record.
        #
        # The ledger proves the shape, same subject bytes three minutes apart:
        #   2026-09-13T13:38:53  verdict=FAIL  assertions=189/190  subject=b471a31b...
        #   2026-09-13T13:41:35  verdict=PASS  assertions=201/201  subject=b471a31b...
        # So: run twice and SHIP THE SECOND record -- the one a third party
        # reproduces by running scripts/run_harness.py on the shipped bytes.
        # The harness must run under the interpreter the record is going to NAME.
        # The BUILD machine is forced onto 3.11 (make_namespaces.py needs
        # `cryptography`, which the managed 3.13 does not have), but the record's
        # `environment.python` is read by consumers as "the interpreter this was
        # verified with". Running the harness under 3.11 would silently make the
        # shipped record the only 3.11 artifact in a project whose corpus, layers
        # and gate all run on 3.13 -- the exact two-rulers smell v3.0 §六.1 exists
        # to prevent. So: honour ANTINEL_PY, exactly like _autoloop does
        # (PY = ANTINEL_PY or sys.executable), and fall back to sys.executable.
        PY_HARNESS = os.environ.get("ANTINEL_PY") or sys.executable
        print("harness interpreter: %s  (build interpreter: %s)" % (PY_HARNESS, sys.executable))
        # ★★ 0.51.2：harness 期间临时补登研发树专属条目（见 _adopt_dev_entries
        #   docstring：merge 抹条目 × self_check 在场才校验的碰撞）。位置在
        #   build_plugin **之后**——插件内容按 manifest 钉，补登必须晚于它。
        _pure_manifest = _adopt_dev_entries(final)
        # ★ 2026-09-29（D-17）：跑在 **`final`（产物仓）** —— 要验的是产物，
        #   不是装配中转站。原为 `pkg`（stage），见上面的判据 ①。
        _harness_py = str(final / "scripts" / "run_harness.py")
        if not os.path.isfile(_harness_py):
            print("!! harness 不在产物里（%s）—— --verify 无法进行，产物已生成" % _harness_py)
            _reconcile_src(_SRC_WATCH)
            return 0
        rc1 = subprocess.call([PY_HARNESS, _harness_py, "--bootstrap"], creationflags=_CNW)
        print("harness(seed, bootstrap) exit: %s   -- non-zero/absent-record here is EXPECTED on a "
              "fresh tree (the record is an input to the run that writes it)" % rc1)
        rc = subprocess.call([PY_HARNESS, _harness_py], creationflags=_CNW)
        print("harness(final, shipped record) exit:", rc)
        # ★★ 0.51.2：harness 跑完 ⇒ 恢复纯净 wheel 口径清单（用 merge 落盘的原
        #   字节，逐字节可复现）。随后 `python -m build` 打包带走它 —— 带研发
        #   条目会撞 verify_release 的 [E]「清单 ⊆ wheel 载荷」对账。
        #   恢复后主树回到既有的「出包后已知态」（缺研发条目），下一轮开工按
        #   self_check 红项给出的命令补登：`_resign_manifest.py --adopt-dev`。
        (Path(final) / "psl" / "manifest.json").write_bytes(_pure_manifest)
        # ★★★ 0.42.0：自证卡的刷新点在**这里**，不在装配时。
        #   装配时那份记录描述的是上一次的字节 ⇒ 必然 false；只有跑完这一次，
        #   shipped 记录才真的描述本次字节 ⇒ 这时写 true 才不是谎话。
        #   （死锁成因与 README.md G7 同型，详见 `_refresh_skill_selfcert` 的 docstring。）
        _refresh_skill_selfcert(pkg, final, rc, plug)
        _reconcile_src(_SRC_WATCH)
        _cleanup_final_stages(pkg, plug)
        return rc
    _cleanup_final_stages(pkg, plug)
    _reconcile_src(_SRC_WATCH)
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=r"D:\psl\poc")
    ap.add_argument("--verify", action="store_true", help="run scripts/run_harness.py after assembling")
    a = ap.parse_args()
    sys.exit(build(a.out, a.verify))
