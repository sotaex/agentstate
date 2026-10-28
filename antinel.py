#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""antinel v0.34.1 - antinel 单入口（定稿方案 v1.1/v1.2）.

用户面只有这一个名字：配置、账本、报告、校验、中枢，全部在 `antinel` 下。
无参数 = help 清单（命令 + "你可以对 Agent 说的话"，与 skill 路由件由同一份
ROUTES 数据源生成，永不失同步）。

写命令的统一七步（缺一不可，见《用户体验定稿方案》§二）：
  校验前置 → diff 预览 → 影响声明 → 同意（TTY=y/N 记 user；非TTY=宿主批准流，
  记 agent）→ 原子应用 → policy_changed 进链 → 回显 + 撤销提示。

经济画像按宿主加载（rules/economics/<host>.json）：credits 子命令只在
unit=credits 的宿主出现；digest 主视图随画像。不同单位永不加和。

stdlib only；本工具本身允许网络（它是 CLI，不是钩子），但 pricing update
在牌价源实测选定（v0.24）前不联网。Python 3.10+。
"""
import argparse
import glob
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, date

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from strings import detect_lang, get_string

VERSION = "0.60.1"
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ---------------------------------------------------------------- ROUTES ----
# 单一数据源：help 清单与 skill 路由件都从这里生成（定稿方案 §六 纪律）。
# ★ 0.29.0 (F-4)：第三列由「账本/报告/安全」改为 **「审核/防范/账本」**。
#   旧分类按**功能类型**分，用户想问"我电脑有没有中招"得自己在"报告"里翻。
#   现在按**用户要办的事**分：审核＝已经发生了什么；防范＝正在发生时拦不拦。
ROUTES = [
    ("给我一页能交差的纸 / 我要给领导或客户交代这件事",
     "antinel brief（决策层一页纸：有没有外发、比上期、该做什么）", "审核"),
    ("查一查我的电脑 / 我有没有中招（要一个能点的页面）",
     "antinel ui（在你自己电脑的浏览器里点一下就查；结果不会离开你的电脑）", "审核"),
    ("这个会话花了多少", "antinel report --session latest", "账本"),
    ("今天/昨天干了什么，拦了什么", "antinel digest [--days N] [--scope all]", "审核"),
    ("今天这个AI工具有没有胡搞/乱来/出格", "antinel digest --days 1 ＋ antinel host-audit", "审核"),
    ("这台电脑上的 AI 工具在往哪发数据 / 谁在后台发", "antinel egress", "审核"),
    ("这台电脑装了哪些 AI 工具 / 哪个在偷数据",
     "antinel host-scan（你电脑上的全部工具 ＋ 分级 ＋ 证据 ＋ 裁决状态）", "审核"),
    ("帮我放个源码金丝雀 / 埋个外传检测标记", "antinel canary plant（读取会提醒；标记出现在输出即外传证据，report 可见）", "防范"),
    ("今日日报 / 日报 / 昨天干了什么", "antinel digest --days 1（工作区=项目根）", "审核"),
    ("确认放行某个落点 / 不放行就挡下它", "antinel host-shield decide <路径> allow_always｜deny（放行须本人在终端）", "防范"),
    ("把 D:\\xxx 加进项目路径/白名单", "antinel roots add D:\\xxx ｜ antinel paths add <前缀>", "防范"),
    ("xxx 域名放行（装包老报警）", "antinel domains add xxx", "防范"),
    ("预算快超了提醒我 / 给会话设个预算", "antinel settings set budget_tokens_per_session <N>", "账本"),
    ("记一下积分余额", "antinel credits snapshot <余额> [--reward N@到期日] [--cycle 到期日]", "账本"),
    ("积分还够不够 / 什么时候烧完", "antinel credits forecast", "账本"),
    ("订阅和API直付哪个划算（对账）", "antinel credits reconcile", "账本"),
    # ★ 0.38.0：哨兵的口粮 —— 与上面三条 `antinel credits` **是两本账**：
    #   credits 记的是**宿主 AI 工具烧的积分**；粮是**哨兵站岗的口粮**。
    #   两本账分开命名、分开显示（混了会污染两边口径，见 `granary.py` 头部）。
    ("看一下我的粮 / 监理还能站多久", "antinel 粮（余额 / 明细 / 规则）", "账本"),
    ("阻止Agent外传 / 开安全区", "antinel settings set net_mode block ＋ antinel zone add <目录>", "防范"),
    ("证据链有没有被动过", "antinel verify", "账本"),
    ("跨工具汇总（多个AI工具一起看）", "antinel digest --scope all", "审核"),
    # ★ 0.35.0：Antinel 监理 —— 把 15 秒就消失的气泡，变成能翻、能点、能归档的台账。
    #   分类＝审核（"已经发生了什么"），与 digest/ui 同栏。
    ("看 Antinel 监理 / 有什么要处理的", "antinel inbox list", "审核"),
    ("今天日报 / 值守情况", "antinel inbox report", "审核"),
]

SETTINGS_KEYS = {
    "alert_threshold": "warning|critical（低于阈值的提醒静默，记录与拦截不变）",
    "fail_closed_on_audit_loss": "true|false（审计写入失败时是否拦截）",
    "session_banner": "true|false（会话横幅开关）",
    "usage_collect": "true|false（消耗采集总开关——记录越多，越要能一键关）",
    "log_retention_days": "天数（审计归档保留期）",
    "auto_archive": "true|false（report 时自动归档过期审计）",
    "budget_tokens_per_session": "会话 token 预算（50/80/100% 三档提醒；默认只提醒）",
    "budget_tokens_per_day": "项目日 token 预算（跨会话累计，同三档）",
    "budget_block": "true|false（默认 false；true 时 100% 档拦截写通道，只读放行）",
    # 0.29.0（G-4）：默认值从"隐藏默认"改为"显式告知"。
    # ★ 为什么不把默认改成 block：改了会误伤正常装包/拉依赖（一次 pip install 就是
    #   一串非白名单域名），用户第一次用就被拦，产品直接不可用。分寸是"不静默加严"，
    #   但同样不能"静默宽松"—— 所以把默认值**写进 help 与 settings list**，让人知道。
    "net_mode": "warn|block（默认 warn：只提醒不拦；要拦请 set 成 block）。"
                "block 的意思：未白名单域名的网络命令，从提醒升级为拦截。"
                "（依据见对抗分析 v1.0）",
    "notify_owner": "true|false（拦截时实时气泡通知主人，默认 true）",
}

# ---------------------------------------------------------------- basics ----
def detect_host():
    forced = os.environ.get("ANTINEL_FORCE_HOST")
    if forced:
        return forced                       # 显式指定优先（多宿主共存时 Agent 自报）
    home = os.path.expanduser("~")
    for tag, d in (("workbuddy", ".workbuddy"), ("zcode", ".zcode"),
                   ("qoder", ".qoder"), ("claude-code", ".claude")):
        if os.path.isdir(os.path.join(home, d)):
            return tag
    return "generic"


def load_economics(host):
    p = os.path.join(_HERE, "rules", "economics", "%s.json" % host)
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"host": host, "unit": "tokens", "unit_label": "tokens",
                "digest_primary": "tokens", "note": "画像缺失，按默认值计 tokens"}


def find_project_root(start=None):
    d = os.path.abspath(start or os.getcwd())
    while True:
        if os.path.isdir(os.path.join(d, ".psl")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def _audit_dir(root):
    return os.path.join(root, ".psl", "audit")


def _session_dna():
    import session_dna
    return session_dna


def _chain_record(audit_dir, rec):
    """进链并**如实报告落在哪**（2026-10-22 修 BL-03）。

    旧写法 `if not sd.append_chained(...)` 把"落在 sidecar"（记录还在）与
    "一个字节都没落"（记录丢了）判成同一件事；改成四态后必须分开说 ——
    两种降级的动作不同：前者不用管，后者要人去查磁盘/权限。
    """
    sd = _session_dna()
    written = sd.append_chained(audit_dir, rec)
    if written == "none":
        sys.stderr.write("警告：policy_changed 没能落盘（磁盘或权限问题），这条记录已丢\n")
        return False
    if written != "chain":
        sys.stderr.write("警告：policy_changed 未进主链（落在 sidecar，记录还在）\n")
    return True


def _is_tty():
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _confirm(question):
    if not _is_tty():
        return True                     # 非交互 = Agent 代办：同意由宿主批准流承担
    try:
        ans = input("%s [y/N] " % question).strip().lower()
    except Exception:
        return False
    return ans in ("y", "yes")


def _invoked_by():
    return "user" if _is_tty() else "agent"


def _die(msg, rc=2):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(rc)


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_json_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# ------------------------------------------------------------ validation ----
def validate_root(p):
    """workspace_roots 条目：绝对路径、非盘根、无通配、无中段 ..。"""
    s = (p or "").strip().strip('"')
    if not s:
        return None, "路径为空"
    if any(ch in s for ch in "*?["):
        return None, "不允许通配符（%s）" % s
    parts = [x for x in s.replace("\\", "/").split("/") if x not in ("", ".")]
    if ".." in parts:
        return None, "不允许 ..（%s）" % s
    if not (len(s) >= 2 and s[1] == ":") and not s.startswith("/"):
        return None, "需要绝对路径（如 D:\\xxx），收到：%s" % s
    norm = s.replace("\\", "/").rstrip("/")
    if len(norm) <= 3 and norm[1:2] == ":":
        return None, "盘根不放行（%s）——根路径等于关闭边界" % s
    return norm, None


def validate_prefix(p):
    """whitelist.paths 条目：同 _norm_prefix 口径——拒绝根样/通配/中段 ..。"""
    s = (p or "").replace("\\", "/").strip().lower()
    if s in ("", ".", "..", "/"):
        return None, "该条目会匹配所有路径（%r）" % p
    s2 = s.lstrip("./")
    if not s2 or s2.endswith(":") or s2.endswith(":/"):
        return None, "盘根样条目不放行（%r）" % p
    if ".." in s2 or any(ch in s2 for ch in "*?["):
        return None, "不允许 .. 或通配符（%r）" % p
    return s2, None


def validate_domain(d):
    s = (d or "").strip().lower().rstrip("/")
    if not s or "/" in s or "://" in s or " " in s:
        return None, "只要域名本身（如 pypi.org），收到：%r" % d
    return s, None


def validate_command_prefix(c):
    s = (c or "").strip()
    if not s:
        return None, "命令前缀为空"
    return s, None


# ------------------------------------------------- seven-step write flow ----
# 0.28.3（E2）：sensitive=True 的写命令在非 TTY（=Agent 代跑）执行后强制气泡告知
# 主人——宿主批准流是同意，气泡补上"实时可见"，链上 policy_changed 补上"事后可证"。
def seven_step(label, target_file, loader, mutator, impact, undo_hint,
               field, root, sensitive=False):
    """统一的写命令七步。mutator(data) 就地修改并返回变更摘要字符串；
    返回 None 表示无变化（不写盘、不留痕）。

    ★ 0.35.3：返回**结局**而不是 None —— `"written"` / `"nochange"` / `"cancelled"`。
      调用方（如 `zone add`）要据此决定"要不要把这次变更同步进哨兵状态"：
      **用户点了"取消"却照样改了状态**，是比不改更坏的结果。
    """
    old_raw = b""
    if os.path.isfile(target_file):
        old_raw = open(target_file, "rb").read()
    try:
        data = loader()
    except Exception as e:
        _die("配置文件不可读（%s）：%s" % (target_file, e))
    summary = mutator(data)
    if summary is None:
        print("无变化（%s 已是期望状态）" % label)
        return "nochange"
    new_raw = json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8")
    print("变更：%s" % label)
    print("  影响：%s" % impact)
    old_h = hashlib.sha256(old_raw).hexdigest()[:12]
    new_h = hashlib.sha256(new_raw).hexdigest()[:12]
    print("  %s  %s… → %s…" % (target_file, old_h, new_h))
    if not _confirm("应用前确认？"):
        print("已取消（未写盘）")
        return "cancelled"
    _save_json_atomic(target_file, data)
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
           "type": "policy_changed", "tool": "-", "session": "antinel-cli",
           "host": detect_host(), "decision": "allow", "severity": "warning",
           "field": field, "change": summary,
           "old_sha256": "sha256:" + old_h, "new_sha256": "sha256:" + new_h,
           "invoked_by": _invoked_by(),
           "reason": impact}
    _chain_record(_audit_dir(root), rec)
    print("✓ 已应用，写进审计链（policy_changed）")
    print("  撤销：%s" % undo_hint)
    if sensitive and not _is_tty():
        try:
            import host_shield as hs0
            hs0.notify("Antinel 配置已由 Agent 变更",
                       ("%s｜%s" % (label, impact))[:150])
        except Exception:
            pass
    return "written"


# ------------------------------------------------------------ roots ----
def host_config_path(host):
    home = os.path.expanduser("~")
    d = {"workbuddy": ".workbuddy", "zcode": ".zcode", "qoder": ".qoder",
         "claude-code": ".claude"}.get(host)
    if not d:
        _die("宿主 %s 没有已知的配置目录，roots 不可用" % host)
    return os.path.join(home, d, "antinel.json")


def cmd_roots(args):
    host = detect_host()
    cfg = host_config_path(host)
    if not os.path.isfile(cfg):
        _die("宿主配置不存在：%s（先在该宿主下安装 Antinel）" % cfg)
    if args.sub == "list":
        for r in (_load_json(cfg).get("workspace_roots") or []):
            print(" ", r)
        return
    if args.sub == "add":
        norm, err = validate_root(args.path)
        if err:
            _die("校验失败：%s\n  示例：antinel roots add D:\\work\\proj" % err)
        def mut(data):
            wr = data.setdefault("workspace_roots", [])
            if any(x.replace("\\", "/").rstrip("/").lower() == norm.lower()
                   for x in wr):
                return None
            wr.append(norm.replace("/", "\\"))
            return "workspace_roots + %s" % norm
        seven_step("roots add %s" % norm, cfg,
                   lambda: _load_json(cfg), mut,
                   "信任边界扩大：该目录内的写入将不再被 DST-02 拦截",
                   "antinel roots remove %s" % norm, "workspace_roots",
                   find_project_root() or os.getcwd(), sensitive=(args.sub == "add"))
    elif args.sub == "remove":
        norm, err = validate_root(args.path)
        if err:
            _die("校验失败：%s" % err)
        def mut(data):
            wr = data.get("workspace_roots") or []
            keep = [x for x in wr if x.replace("\\", "/").rstrip("/").lower() != norm.lower()]
            if len(keep) == len(wr):
                return None
            data["workspace_roots"] = keep
            return "workspace_roots - %s" % norm
        seven_step("roots remove %s" % norm, cfg,
                   lambda: _load_json(cfg), mut,
                   "信任边界收紧：该目录内的项目外写入将重新被拦截",
                   "antinel roots add %s" % norm, "workspace_roots",
                   find_project_root() or os.getcwd())


# --------------------------------------- paths / domains / commands ----
def _policy_loader(pol_path):
    """首次配置引导：项目还没有 policy.json 时，从最小骨架开始（用户全程
    不需要手工创建/编辑 JSON）。"""
    def loader():
        if os.path.isfile(pol_path):
            return _load_json(pol_path)
        return {"$schema": "antinel-policy-v1", "version": "1.0",
                "global_settings": {},
                "whitelist": {"domains": [], "paths": [], "commands": []}}
    return loader


def _wl(kind, sub, args):
    root = find_project_root()
    if root is None:
        _die("未找到项目（向上没有 .psl 目录）——在项目内运行，或先安装")
    pol_path = os.path.join(root, ".psl", "policy.json")
    key = {"paths": "paths", "domains": "domains", "commands": "commands"}[kind]
    vfn = {"paths": validate_prefix, "domains": validate_domain,
           "commands": validate_command_prefix}[kind]
    undo = {"paths": "antinel paths remove", "domains": "antinel domains remove",
            "commands": "antinel commands remove"}[kind]
    if sub == "list":
        try:
            wl = (_load_json(pol_path).get("whitelist") or {}).get(key) or []
        except Exception:
            wl = []
        for x in wl:
            print(" ", x)
        if not wl:
            print("（空）")
        return
    val, err = vfn(args.value)
    if err:
        _die("校验失败：%s\n  示例：%s %s <值>" % (err, kind, sub))

    def mut(data):
        wl = data.setdefault("whitelist", {}).setdefault(key, [])
        if sub == "add":
            if val in wl:
                return None
            wl.append(val)
            return "whitelist.%s + %s" % (key, val)
        keep = [x for x in wl if x != val]
        if len(keep) == len(wl):
            return None
        data["whitelist"][key] = keep
        return "whitelist.%s - %s" % (key, val)

    impact = {"paths": "该前缀下的写入将不再被 DST-02 拦截（每次放行都留审计痕）",
              "domains": "该域名的网络请求不再触发 NET 提醒/拦截",
              "commands": "该前缀命令不再触发 warning 级提醒（critical 规则不受影响）"}[kind]
    seven_step("%s %s %s" % (kind, sub, val), pol_path,
               _policy_loader(pol_path), mut, impact,
               "%s %s" % (undo, val), "whitelist.%s" % key, root, sensitive=(sub == "add"))


# ------------------------------------------------------------ settings ----
def cmd_settings(args):
    root = find_project_root()
    if root is None:
        _die("未找到项目（向上没有 .psl 目录）")
    pol_path = os.path.join(root, ".psl", "policy.json")
    if args.sub == "list":
        data = _load_json(pol_path) if os.path.isfile(pol_path) else {}
        gs = data.get("global_settings") or {}
        for k, desc in SETTINGS_KEYS.items():
            print("  %-26s = %-10s # %s" % (k, gs.get(k, "<默认>"), desc))
        return
    if args.sub == "get":
        data = _load_json(pol_path) if os.path.isfile(pol_path) else {}
        print((data.get("global_settings") or {}).get(args.key, "<默认>"))
        return
    key = args.key
    if key not in SETTINGS_KEYS:
        _die("未知设置键：%s\n可用：%s" % (key, ", ".join(SETTINGS_KEYS)))
    val = args.value.strip()
    if key in ("fail_closed_on_audit_loss", "session_banner", "usage_collect", "auto_archive"):
        if val.lower() not in ("true", "false"):
            _die("%s 取 true|false" % key)
        val = val.lower()
    if key == "alert_threshold" and val.lower() not in ("warning", "critical"):
        _die("alert_threshold 取 warning|critical")
    if key == "log_retention_days":
        try:
            val = int(val)
        except Exception:
            _die("log_retention_days 取整数")

    def mut(data):
        gs = data.setdefault("global_settings", {})
        old = gs.get(key)
        if str(old).lower() == str(val).lower():
            return None
        gs[key] = val
        return "global_settings.%s: %s → %s" % (key, old, val)

    seven_step("settings set %s=%s" % (key, val), pol_path,
               _policy_loader(pol_path), mut,
               SETTINGS_KEYS[key], "antinel settings set %s <旧值>" % key,
               "global_settings." + key, root,
               sensitive=(key in ("net_mode", "fail_closed_on_audit_loss", "alert_threshold")))


# ------------------------------------------------------------ credits ----
def _snapshots(audit_dir):
    sd = _session_dna()
    out = []
    for _d, rec in sd._rows(sd._iter_day_files(audit_dir), float("inf"), [False]):
        if rec.get("type") == "credits_snapshot":
            out.append(rec)
    out.sort(key=lambda r: r.get("ts") or "")
    return out


def _tokens_between(audit_dir, ts0, ts1):
    sd = _session_dna()
    total = 0
    for _d, rec in sd._rows(sd._iter_day_files(audit_dir), float("inf"), [False]):
        if rec.get("type") != "usage_delta":
            continue
        for e in (rec.get("entries") or []):
            t = str(e.get("ts") or "")
            if not t:
                continue
            # transcript ts 可能是 epoch 毫秒或 ISO——两种都兼容到可比较的序
            try:
                key = t if not t.isdigit() else datetime.fromtimestamp(
                    int(t) / 1000).isoformat(timespec="seconds")
            except Exception:
                key = t
            if ts0 < key < ts1:
                total += (e.get("input_tokens") or 0) + (e.get("output_tokens") or 0)
    return total


def cmd_credits(args, prof):
    root = find_project_root()
    if root is None:
        _die("未找到项目")
    if prof.get("unit") != "credits":
        _die("当前宿主（%s）经济画像为 %s——没有积分换算依据，credits 不可用"
             % (prof.get("host"), prof.get("unit")))
    audit = _audit_dir(root)
    if args.sub == "plan":
        uep = os.path.join(os.path.expanduser("~"), ".antinel", "user_economics.json")
        os.makedirs(os.path.dirname(uep), exist_ok=True)
        try:
            yuan, credits = float(args.yuan), float(args.credits)
        except Exception:
            _die("用法：antinel credits plan <月费元> <每月积分>，例：antinel credits plan 99 4000")
        data = {"plan_yuan_per_month": yuan, "plan_credits_per_month": credits,
                "yuan_per_credit": round(yuan / credits, 6),
                "updated_at": datetime.now().isoformat(timespec="seconds")}
        _save_json_atomic(uep, data)
        print("✓ 套餐设置已存（你报的）：%.2f 元 / %s 积分 = %.4f 元/积分"
              % (yuan, format(int(credits), ","), data["yuan_per_credit"]))
        return
    if args.sub == "reconcile":
        snaps = _snapshots(audit)
        if len(snaps) < 2:
            _die("比对需要 ≥2 次快照")
        a, b = snaps[-2], snaps[-1]
        cdelta = float(b["balance"]) - float(a["balance"])
        toks = _tokens_between(audit, a.get("ts", ""), b.get("ts", ""))
        observed = (-cdelta / toks * 1000.0) if (toks > 0 and abs(cdelta) > 0) else None
        print("【observed】", end="")
        if observed is not None:
            print("%.4f 积分/千token（快照差分，%d tokens / Δ%s 积分）" % (observed, toks, cdelta))
        else:
            print("不可得（两次快照间无 token 记录或无差额）")
        uep = os.path.join(os.path.expanduser("~"), ".antinel", "user_economics.json")
        ppc = None
        try:
            ue = _load_json(uep)
            ppc = ue.get("yuan_per_credit")
            print("【套餐】%.4f 元/积分（你报：%.2f 元 / %s 积分）"
                  % (ppc, ue["plan_yuan_per_month"], format(int(ue["plan_credits_per_month"]), ",")))
            if observed is not None:
                print("  → %.4f 积分/千token ≈ %.5f 元/千token（换算值）" % (observed, observed * ppc))
        except Exception:
            print("【套餐】未登记——antinel credits plan <月费元> <每月积分>")
        cache_p = os.path.join(root, ".psl", "state", "pricing_cache.json")
        try:
            cache = _load_json(cache_p)
            print("【牌价参照】来源 %s @ %s（对公开价，非你的账单）"
                  % (cache.get("source"), str(cache.get("fetched_at"))[:16]))
        except Exception:
            print("【牌价参照】无缓存。要拉取：antinel pricing update"
                  "（可选，仅作参考位）")
        print("  差异来源：缓存计价／模型组合变化／时间窗；两次的统计范围不同，不能相加。")
        return
    if args.sub == "snapshot":
        try:
            balance = float(args.balance)
        except Exception:
            _die("余额需为数字，收到：%r" % args.balance)

        def bucket(name):
            v = getattr(args, name, None)
            if not v:
                return None
            if "@" in v:
                n, exp = v.split("@", 1)
                return {"value": float(n), "expires": exp}
            return {"value": float(v)}

        rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
               "type": "credits_snapshot", "tool": "-", "session": "antinel-cli",
               "host": detect_host(), "decision": "allow", "severity": "none",
               "balance": balance, "user_reported": True,
               "buckets": {k: bucket(k) for k in ("base", "gift", "reward")
                           if bucket(k)},
               "cycle_end": args.cycle,
               "reason": "用户口报积分余额（引导式快照）"}
        _chain_record(audit, rec)
        print("✓ 快照已进链：余额 %s（你报于 %s）" % (balance, rec["ts"][:16]))
        snaps = _snapshots(audit)
        if len(snaps) < 2:
            print("  再记一次余额，就能学出你的燃烧速度并做周期预测")
        return
    snaps = _snapshots(audit)
    if args.sub == "list":
        if not snaps:
            print("（还没有快照——antinel credits snapshot <余额>）")
        for s in snaps:
            print(" ", s["ts"][:16], "余额", s.get("balance"),
                  ("周期至 %s" % s.get("cycle_end")) if s.get("cycle_end") else "")
        return
    # forecast
    if len(snaps) < 2:
        _die("预测需要 ≥2 次快照（现在 %d 次）——隔一天再记一次余额即可" % len(snaps))
    a, b = snaps[-2], snaps[-1]
    cdelta = float(b["balance"]) - float(a["balance"])
    toks = _tokens_between(audit, a.get("ts", ""), b.get("ts", ""))
    rate = None
    if toks > 0 and abs(cdelta) > 0:
        rate = -cdelta / toks * 1000.0
    print("【一句话】余额 %s 积分（你报于 %s）%s。"
          % (b["balance"], b["ts"][:16],
             ("，观察速度 ≈%.4f 积分/千token（估）" % rate) if rate is not None
             else "，速度未知（两次快照间无 token 记录）"))
    lines = []
    if b.get("cycle_end"):
        try:
            days_left = (date.fromisoformat(b["cycle_end"]) - date.today()).days
            lines.append("周期至 %s（剩 %d 天）" % (b["cycle_end"], days_left))
            if rate is not None:
                recent = _tokens_between(audit, b.get("ts", ""),
                                         datetime.now().astimezone().isoformat(timespec="seconds"))
                lines.append("自上次快照已耗 %d tokens（估）——按此速度请隔一天再快照一次以细化预测" % recent)
            rb = (b.get("buckets") or {}).get("reward") or {}
            if rb.get("expires"):
                lines.append("⚠ 奖励积分 %s 将于 %s 过期（平台通常先扣先过期的桶）"
                             % (rb.get("value"), rb.get("expires")))
        except Exception:
            lines.append("周期日期无法解析：%s" % b.get("cycle_end"))
    else:
        lines.append("未登记周期。示例：antinel credits snapshot <余额> --cycle 2026-09-30")
    print("\n".join(lines))


# ------------------------------------------------------------ digest ----
def _agg_audit(audit_dir, days):
    sd = _session_dna()
    from datetime import timedelta
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    acts = blocks = warns = 0
    by_rule = {}
    toks = 0
    gaps = probe_ok = probe_fail = 0
    fail_open = 0
    host_changes = 0
    untrusted_host = low_conf_host = 0        # 0.33.1 (P4-1)
    canary_leak = 0                           # 0.34.0 (E2)：蜜饵标记出现在工具输出里
    sens_out = 0                              # 0.34.0 (E2)：输出命中敏感模式
    canary_marks = {}                         # marker -> 首次 ts
    pre_ts = {}
    post_ts = {}
    probe_last = None
    for day, rec in sd._rows(sd._iter_day_files(audit_dir), float("inf"), [False]):
        if day[:10] < since:
            continue
        t = rec.get("type")
        # 0.33.1 (P4-1)：宿主归因可信度可见化。
        # 旧记录（0.33.0 及更早）没有 host_confidence 字段 ⇒ 其宿主标签**不可信**
        # （实测：本项目的 WorkBuddy 流量被标成 qoder）。链不可变，所以不改链、
        # 改读法：把"这段时间的宿主标签不可信"做成报告里的一个显式数字，
        # 而不是让读者以为每个 host 字段都是事实。
        if t in ("pre_tool_use", "post_tool_use"):
            _hc = rec.get("host_confidence")
            if _hc is None:
                untrusted_host += 1
            elif _hc == "low":
                low_conf_host += 1
        if t == "pre_tool_use":
            acts += 1
            if rec.get("decision") == "block":
                blocks += 1
                for rid in (rec.get("rules_hit") or []):
                    by_rule[rid] = by_rule.get(rid, 0) + 1
            elif rec.get("decision") == "alert":
                warns += 1
        elif t == "usage_delta":
            for e in (rec.get("entries") or []):
                toks += (e.get("input_tokens") or 0) + (e.get("output_tokens") or 0)
        # 0.30.0 (E-3): enforcement facts join the same daily aggregation --
        # the morning report must be able to say "the gate is not signaling".
        elif t == "enforcement_gap":
            gaps += 1
        elif t == "enforcement_probe":
            if rec.get("ok") is True:
                probe_ok += 1
            elif rec.get("ok") is False:
                probe_fail += 1
            _ts = rec.get("ts") or ""
            if probe_last is None or _ts > probe_last:
                probe_last = _ts
        # 0.32.0 (F5): fail-open visibility -- every hook_error is a call the
        # hook could not judge (allowed by the host, A-08). "持续安心" requires
        # this number to be visible in the morning report, not buried in stderr.
        elif t == "hook_error":
            fail_open += 1
        # 0.32.2 (A1): 宿主版本变化——W2 对冲的可见性。
        elif t == "host_changed":
            host_changes += 1
        elif t == "pre_tool_use":
            _dg = rec.get("content_digest")
            if _dg:
                pre_ts[_dg] = rec.get("ts")
        elif t == "post_tool_use":
            _dg = rec.get("content_digest")
            if _dg:
                post_ts[_dg] = rec.get("ts")
            # ★★ 0.34.0（E2）：**数据外发**进日常视图。
            #   为什么加：canary 是本产品唯一能给出"内容真的出去了"的**主动证据**
            #   （SEC-11 埋的蜜饵标记一旦出现在工具输出里 ⇒ 读过 ＋ 带出去过）。
            #   而它此前**只**在 `report` 的 canaries 统计里，`digest`/`morning`
            #   这两个用户最常看的视图**完全没有这个数字** ——
            #   也就是"最该被看到的风险"在"最常被看到的界面"上缺席。
            #   口径（与 report.py 一致，不二次实现判据）：
            #     · canaries_observed 非空 ⇒ 蜜饵标记出现在输出里 ⇒ 强证据
            #     · sensitive_output 非空  ⇒ 输出里命中了敏感模式
            for _c in (rec.get("canaries_observed") or []):
                canary_leak += 1
                _mk = _c if isinstance(_c, str) else (_c.get("marker") or "")
                if _mk and _mk not in canary_marks:
                    canary_marks[_mk] = rec.get("ts")
            for _s in (rec.get("sensitive_output") or []):
                sens_out += 1
    return {"actions": acts, "blocks": blocks, "warnings": warns,
            "by_rule": by_rule, "tokens": toks,
            "gaps": gaps, "probe_ok": probe_ok, "probe_fail": probe_fail,
            "fail_open": fail_open, "host_changes": host_changes,
            "untrusted_host": untrusted_host, "low_conf_host": low_conf_host,
            "canary_leak": canary_leak, "canary_marks": canary_marks,
            "sensitive_output": sens_out,
            "pre_ts": pre_ts, "post_ts": post_ts,
            "probe_last": probe_last}


def canary_summary():
    """诱饵文件状态（**唯一实现**：体检页 ③ 组与任何调用方都读它，不各写一份）。

    数据源＝hub 登记的各项目 `.psl/audit/` 链（与 `_agg_audit` 同一个读取器
    `session_dna._rows/_iter_day_files`，禁第二份链读法），聚合三件**已经
    发生**的事：
      · planted  —— 链上 `canary_planted` 按 marker 去重 ⇒ 放了几枚
      · read     —— SEC-11 提醒次数（工具**读过**诱饵文件；规则故意只 alert
                    不拦——拦下就观察不到外传链路，见 rules/default.json SEC-11 note）
      · observed —— `canaries_observed` 次数＋涉及哪些 marker（标记出现在工具
                    **输出里**＝读过**且**带出去过，唯一强证据）

    ★ 三态不许混（页面文案的地基）：没登记项目 ≠ 没放诱饵 ≠ 放了没被读 ≠
      被读过 ≠ 带出去过。调用方必须分别措辞，**不许**把"被读"渲染成"出事"。
    ★ 读不出/没登记项目 ⇒ `projects: 0` 且三个计数给 0 —— 调用方据此说
      「还没登记过项目」，**绝不**渲染成「一个诱饵文件都没有」（没查过与
      查过没有是两件事，本仓铁律）。
    """
    sd = _session_dna()
    import hub as _hub
    reg = _hub.load_registry()
    planted, read, observed, marks = {}, 0, 0, {}
    projects = 0
    for p in (reg.get("projects") or []):
        root = str(p.get("root") or "")
        if not root or not os.path.isdir(root):
            continue
        projects += 1
        try:
            for _day, rec in sd._rows(sd._iter_day_files(_audit_dir(root)),
                                      float("inf"), [False]):
                t = rec.get("type")
                if t == "canary_planted":
                    mk = str(rec.get("marker") or "")
                    if mk and mk not in planted:
                        planted[mk] = rec.get("ts") or ""
                elif t == "pre_tool_use":
                    if "SEC-11" in (rec.get("rules_hit") or []):
                        read += 1
                elif t == "post_tool_use":
                    for c in (rec.get("canaries_observed") or []):
                        observed += 1
                        mk = c if isinstance(c, str) else (c.get("marker") or "")
                        if mk and mk not in marks:
                            marks[mk] = rec.get("ts") or ""
        except Exception:                                     # noqa: BLE001
            continue        # 单个项目的链读不出不影响别的项目（家务事不搞崩正经事）
    return {"projects": projects,
            "planted": sorted(planted), "planted_at": planted,
            "read": read, "observed": observed, "observed_marks": marks}


def cmd_canary(args):
    """0.31.0 (F3)：源码金丝雀。plant = 在 <root>/.canary/ 放一个含
    CANARY-<slug>-<8hex> 标记的蜜饵文件并上链 canary_planted；list = 列出
    现存金丝雀与链上登记。观察半边（输出中出现标记）由 post_tool_use 的
    既有 canaries_observed 机制接管——本命令只负责"放"与"登记"。"""
    root = find_project_root()
    if root is None:
        _die("未找到项目（金丝雀挂在项目上）")
    sub = getattr(args, "sub", "")
    cdir = os.path.join(root, ".canary")
    ad = os.path.join(root, ".psl", "audit")
    slug = re.sub(r"[^\w-]", "-", os.path.basename(root)).strip("-")[:24] or "proj"
    host = detect_host()

    def _chain(rec):
        try:
            import audit_chain as _acm
        except ImportError:
            _die("audit_chain 不可用（包不完整）")
        os.makedirs(ad, exist_ok=True)
        fn = os.path.join(ad, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
        _rec, _ok = _acm.append_chained(fn, rec)
        # 2026-10-22 修 BL-03：旧代码把返回值丢掉 ⇒ 记录彻底没落盘也没人知道。
        if _rec.get("written") == "none":
            sys.stderr.write("警告：这条记录没能落盘（%s）\n"
                             % (_rec.get("write_error") or "原因未知"))
        _acm.touch_day_manifest(fn)
        mad = os.path.join(os.path.expanduser(
            os.environ.get("WORKBUDDY_CONFIG_DIR") or "~/.workbuddy"), "antinel-audit")
        try:
            os.makedirs(mad, exist_ok=True)
            mfn = os.path.join(mad, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
            _acm.append_locked(mfn, json.dumps(rec, ensure_ascii=False) + "\n")
            _acm.touch_day_manifest(mfn)
        except Exception:
            pass

    if sub == "plant":
        marker = None
        if os.path.isdir(cdir):
            for fn in sorted(os.listdir(cdir)):
                if fn.startswith("CANARY-%s-" % slug):
                    marker = fn
                    break
        note = "already" if marker else "planted"
        if not marker:
            import secrets as _secrets
            marker = "CANARY-%s-%s" % (slug, _secrets.token_hex(4))
            os.makedirs(cdir, exist_ok=True)
            cpath = os.path.join(cdir, marker)
            with open(cpath, "w", encoding="utf-8") as f:
                f.write("%s\nAntinel canary：本文件是蜜饵。"
                        "若这个标记出现在任何工具输出或外部通道，"
                        "说明项目内容被读走并带了出去。"
                        "在 antinel report 的 canaries 统计里能看到。\nplanted: %s\n"
                        % (marker, datetime.now().isoformat(timespec="seconds")))
        _chain({"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
                "type": "canary_planted", "tool": "-", "session": "antinel-cli",
                "host": host, "marker": marker,
                "path": os.path.join(".canary", marker), "note": note,
                "decision": "allow", "severity": "none",
                "reason": "canary %s（读取 → SEC-11 提醒；标记出现在输出 → report canaries 统计）"
                          % ("已存在，复用" if note == "already" else "已布置")})
        print("✓ 金丝雀在岗：%s（读取 → SEC-11 提醒；标记出现在输出即外传证据）"
              % os.path.join(".canary", marker))
        return
    if sub == "list":
        planted = []
        if os.path.isdir(cdir):
            planted = [fn for fn in sorted(os.listdir(cdir))
                       if fn.startswith("CANARY-%s-" % slug)]
        seen = []
        try:
            for day in sorted(os.listdir(ad)):
                if not day.endswith(".jsonl"):
                    continue
                for ln in io.open(os.path.join(ad, day), encoding="utf-8", errors="replace"):
                    if '"canary_planted"' in ln:
                        try:
                            r = json.loads(ln)
                            seen.append((r.get("ts", "")[:16], r.get("marker"), r.get("note")))
                        except Exception:
                            pass
        except Exception:
            pass
        print("【金丝雀】在岗 %d 个：%s" % (len(planted), ", ".join(planted) or "（无）"))
        for ts, marker, note in seen[-8:]:
            print("  %s  %s（%s）" % (ts, marker, note))
        print("  读取 → SEC-11 提醒；标记出现在工具输出 → report 的 canaries 统计。")
        return
    _die("未知子命令")


def cmd_digest(args):
    prof = load_economics(detect_host())
    days = args.days or 1
    scope = args.scope or "project"
    primary = prof.get("digest_primary") or "tokens"
    root = find_project_root()
    if root is None and scope == "project":
        _die("未找到项目")
    projects = []
    if scope == "all":
        import hub as hubmod
        reg = hubmod.load_registry()
        projects = [(p["root"], h, p) for p in reg["projects"] for h in p.get("hosts") or ["?"]]
        if not projects:
            _die("登记表为空——antinel hub register <项目路径>")
    else:
        projects = [(root, detect_host(), {"root": root})]

    per = []
    total = {"actions": 0, "blocks": 0, "warnings": 0, "tokens": 0,
             "gaps": 0, "probe_ok": 0, "probe_fail": 0, "fail_open": 0,
             "host_changes": 0, "untrusted_host": 0, "low_conf_host": 0,
             # ★ 0.34.0（E2）：与 _agg_audit 的返回键**一一对应**。
             #   漏一个就会在这一行 KeyError —— `for k in total: total[k] += a[k]`
             #   是按 total 的键去 a 里取值，两边必须同集合。
             "canary_leak": 0, "sensitive_output": 0}
    # ★ 0.34.0（E2）：canary_marks 是 **dict**（marker→首次 ts），
    #   不能进 `for k in total: total[k] += a[k]` 那个加法循环（dict += dict 会炸），
    #   所以它不进 total，单独维护并在合并时 update。
    heads = {}
    total_marks = {}                          # ★ 0.34.0 (E2)
    for proot, host, _meta in projects:
        ad = _audit_dir(proot)
        if not os.path.isdir(ad):
            continue
        a = _agg_audit(ad, days)
        a.update({"root": proot, "host": host})
        per.append(a)
        for k in total:
            total[k] += a[k]
        # ★ 0.34.0（E2）：marker→首次 ts 跨项目合并（dict 单独 update，不进上面的加法）
        for _mk, _ts in (a.get("canary_marks") or {}).items():
            if _mk not in total_marks or (total_marks[_mk] and _ts < total_marks[_mk]):
                total_marks[_mk] = _ts
        try:
            man = _load_json(os.path.join(ad, "day_manifest.json"))
            today = datetime.now().strftime("%Y-%m-%d.jsonl")
            if today in man:
                heads[proot] = man[today].get("last_hash", "")
        except Exception:
            pass

    unit = prof.get("unit_label") or prof.get("unit") or "tokens"
    econ = ""
    if primary == "credits" and days == 1:
        econ = "；积分消耗请看 credits forecast（快照驱动）"
        # v0.24: 有观察换算率时直接给估算积分（派生，标估）
        try:
            _ad = _audit_dir(root)
            snaps0 = _snapshots(_ad)
            if len(snaps0) >= 2:
                a0, b0 = snaps0[-2], snaps0[-1]
                cd0 = float(b0["balance"]) - float(a0["balance"])
                tk0 = _tokens_between(_ad, a0.get("ts", ""), b0.get("ts", ""))
                if tk0 > 0 and abs(cd0) > 0:
                    rate0 = -cd0 / tk0 * 1000.0
                    est = total["tokens"] / 1000.0 * rate0
                    econ = "；估算消耗 ≈%s 积分（估，据观察换算率 %.4f/千tok）" % (format(round(est, 1), ","), rate0)
        except Exception:
            pass
    print("【一句话】近 %d 天：%d 个项目/宿主组合，%d 次操作、拦截 %d 次、"
          "token 进出 %s（事实）；记账方式 %s=%s%s。"
          % (days, len(per), total["actions"], total["blocks"],
             format(total["tokens"], ","), detect_host(), unit, econ))
    # ★★ 0.34.0（E2）：**「数据有没有出去」提到首屏**。
    #   为什么放在【一句话】之后、其它段之前：用户装这个工具，问的第一个问题是
    #   "我的东西有没有被传出去"，而这个答案此前**只**在 `report` 里 ——
    #   `digest`/`morning` 这两个最常被看的视图**没有它**。
    #   口径诚实（与 report.py /canary plant 同一套判据，不二次实现）：
    #     · 有 canary 命中 ⇒ 蜜饵标记出现在工具输出里 ⇒ 强证据（有东西被带出去过）
    #     · 无命中     ⇒ **只说明"没见到"，不是"没有"** —— 会偷的工具不写记录
    _ck = total.get("canary_leak", 0)
    _so = total.get("sensitive_output", 0)
    if _ck:
        _first = min([v for v in total_marks.values() if v] or [""])
        print("【数据外发】🔴 检出 %d 次蜜饵标记出现在工具输出里。"
              "（内容被读，且带出项目外）%s"
              % (_ck, ("；首次 %s" % _first[:19]) if _first else ""))
        print("            用 python -m antinel report --days %d 看是哪条工具、哪个文件" % days)
    elif _so:
        print("【数据外发】🟠 未见蜜饵命中，但 %d 次输出命中敏感模式 —— 查 python -m antinel report" % _so)
    else:
        print("【数据外发】未见蜜饵命中（只说明没见到，不等于没有——"
              "会偷的工具不会写记录）。要更强的证据：python -m antinel canary plant")
    for a in sorted(per, key=lambda x: -x["actions"]):
        print("  %-9s %s" % (a["host"], a["root"]))
        print("    操作 %d｜拦截 %d %s｜提醒 %d｜tokens %s"
              % (a["actions"], a["blocks"],
                 ("（%s）" % ",".join("%s×%d" % kv for kv in sorted(a["by_rule"].items()))) if a["by_rule"] else "",
                 a["warnings"], format(a["tokens"], ",")))
    # 0.30.0 (E-3): 执法状态进晨报——"闸门还在不在"必须能大声说出来。
    if total.get("gaps") or total.get("probe_fail"):
        print("【执法】⚠ 缺口 %d 次（被拦的调用仍被执行）｜自检失败 %d/%d。"
              "拦截信号可能未生效。"
              "运行 python -m tools.enforce_probe 复检，并核对宿主钩子协议"
              % (total.get("gaps", 0), total.get("probe_fail", 0),
                 total.get("probe_ok", 0) + total.get("probe_fail", 0)))
    elif total.get("probe_ok"):
        print("【执法】自检 %d/%d 通过；缺口 0（被拦的调用没有再执行）"
              % (total.get("probe_ok", 0), total.get("probe_ok", 0)))
    # 0.32.0 (F5): fail-open 可见性——每次钩子异常都是一次"没判就放"。
    if total.get("fail_open"):
        print("【护栏】⚠ fail-open %d 次（钩子异常时放行，A-08）。"
              "当时闸门不在岗，详见 report" % total.get("fail_open", 0))
    if total.get("host_changes"):
        print("【宿主】⚠ 版本变化 %d 次，钩子协议可能与预期不符。"
              % total.get("host_changes", 0))
        print("请重跑 probe_host.py 与 enforce_probe.py 各一次。")
    # 0.33.0 (B5): 钩子延迟可见性——pre/post 配对的时长中位数。
    _durs = []
    for a in per:
        _pre = a.get("pre_ts") or {}
        _post = a.get("post_ts") or {}
        for dg in _post:
            if dg in _pre:
                try:
                    d = (datetime.fromisoformat(_post[dg])
                         - datetime.fromisoformat(_pre[dg])).total_seconds() * 1000
                    if 0 <= d < 60000:
                        _durs.append(d)
                except Exception:
                    pass
    if _durs:
        _durs.sort()
        print("【延迟】钩子耗时中位数 %.0f ms（%d 对 pre/post 配对）" % (_durs[len(_durs) // 2], len(_durs)))
    # 0.32.2 (A4): 探针陈旧/从未运行——拦截自证停摆必须可见。
    # ★★ 2026-09-30 修（假警）：此前用**展示窗口内**的 probe_last 判陈旧，
    #   而默认窗口 days=1 ⇒ since＝今天；陈旧阈值却是 2×probe_interval_hours＝48h。
    #   **窗口(≤24h) < 阈值(48h) ⇒ 判据结构性不可满足**：探针昨天跑过、今天还没跑，
    #   上午的晨报就必报「陈旧/从未运行（last: never）」——这是**假警**，
    #   而且把「本窗口内没有」说成了「从未运行」（`没查到` ≠ `没发现`）。
    #   实测对照（同机器同账本同秒）：--days 3 →「探针 3/3 通过」；--days 1 →「last: never」。
    #   修法两条：①陈旧判定与展示窗口**解耦**（回看窗口 ≥ 陈旧阈值）；
    #            ②措辞区分「本窗口内没有」与「从未运行」。
    #   ★ 真源仍是**账本本身**（复用 _agg_audit，不二次实现、不引入第二份副本）。
    try:
        _pol = {}
        if root:
            _pol = json.load(open(os.path.join(str(root), ".psl", "policy.json"),
                                  encoding="utf-8"))
        _iv = float((_pol.get("global_settings") or {}).get("probe_interval_hours", 24) or 24)
        _last = None
        for a in per:
            if a.get("probe_last"):
                _last = a["probe_last"] if _last is None else max(_last, a["probe_last"])
        # 窗口内没有 ⇒ 按"与窗口无关的回看"再算一次（回看 ≥ 陈旧阈值 ⇒ 判据可满足）
        if _last is None and root:
            try:
                _look = max(int(days), int(_iv / 24.0 * 2) + 1)
                _last = _agg_audit(_audit_dir(str(root)), _look).get("probe_last")
            except Exception:
                _last = None
        _stale = True
        if _last:
            _dt = datetime.fromisoformat(_last)
            if _dt.tzinfo is None:                 # 状态文件里写的是本地时间（naive）
                _dt = _dt.astimezone()
            _stale = (datetime.now().astimezone() - _dt).total_seconds() > _iv * 3600 * 2
        if _stale and root:
            if _last:
                print("【执法】⚠ 自检陈旧（上一次 %s，已超过 %d 小时）——拦截自证停摆，"
                      "运行 python -m tools.enforce_probe" % (_last, int(_iv * 2)))
            else:
                print("【执法】⚠ 自检从未运行——拦截自证停摆，"
                      "运行 python -m tools.enforce_probe")
        elif _last and not total.get("probe_ok"):
            # 窗口内已经报过「探针 N/N 通过」时不再重复；只在"窗口内没有、但也没陈旧"时报一句。
            print("【执法】自检上一次 %s（不在本次展示窗口内，未陈旧）" % _last)
    except Exception:
        pass
    # 0.33.1 (P4-1)：不可信日期段显式化——分母是"这段时间内的工具调用记录数"。
    if total["untrusted_host"] or total["low_conf_host"]:
        print("【宿主标签】⚠ %d 条记录的宿主标签不可信（旧格式，无归因证据）；"
              "%d 条为低可信（仅目录标记）——这两个 host 字段不能当事实引用。"
              % (total["untrusted_host"], total["low_conf_host"]))
    else:
        print("【宿主标签】全部记录带归因证据（每条都记了它是怎么认出来的）")
    print("【覆盖】%d 个登记项目 / %d 个宿主；未接入工具不在此列（分母显式）"
          % (len({p for p, _h, _m in projects}), len({h for _p, h, _m in projects})))

    if scope == "all":
        rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
               "type": "digest_rollup", "tool": "-", "session": "antinel-cli",
               "host": detect_host(), "decision": "allow", "severity": "none",
               "days": days, "total": total,
               "per_project": [{k: v for k, v in a.items() if k != "by_rule"} for a in per],
               "coverage": {"projects": len({p for p, _h, _m in projects}),
                            "hosts": len({h for _p, h, _m in projects})},
               "chain_heads": heads,
               "derived": True,
               "reason": "跨项目聚合快照（按各项目链汇总；各项目链仍是唯一的事实来源）"}
        import hub as hubmod
        _w = _session_dna().append_chained(hubmod.rollup_dir(), rec)
        # 2026-10-22 修 BL-03：旧代码**无条件**打印"已进中枢链"——而那一行可能是
        # 一句谎（磁盘满时它什么都没写）。凡是要打印"已经落盘"的地方，必须回读结果。
        if _w == "chain":
            print("（汇总快照已进中枢链：~/.antinel/rollup/）")
        elif _w == "none":
            print("（汇总快照没能落盘：磁盘或权限有问题，这份快照已丢）")
        else:
            print("（汇总快照落在 sidecar，未进主链；记录还在，稍后可追）")


# ------------------------------------------------------------ 粮 ----
# ★ 0.38.0：粮（哨兵的口粮）。**与 `credits` 是两本账** —— 见 `granary.py` 头部。
#   判据 `ci/guard_granary.py` 会验：本条命令能用，且与 credits 不混。
def cmd_granary(args, prof):                       # noqa: ARG001 (prof 仅保签名一致)
    """antinel 粮 [余额|明细|规则]。真源在 granary；本函数只排版，不自己算账。"""
    import granary as G
    sub = getattr(args, "sub", None) or "余额"
    if sub == "规则":
        r = G.rules()
        print("粮的获得（单位：粮）")
        for grp, rows in r["grant"].items():
            print("  ◇ %s" % grp)
            for name, amt, freq in rows:
                print("    %-14s %+4d   %s" % (name, amt, freq))
        print("粮的消耗（监理在岗时慢慢走）")
        for name, amt, note in r["spend"]:
            print("    %-8s %-12s %s" % (name, amt, note))
        print("缺粮阈值：余额低于 %d 粮（约一周口粮）时亮「缺粮」。" % r["low_threshold"])
        print("充值：%s" % ("已开放" if r["recharge"].get("enabled")
                            else "尚未开放（开放注册后提供充值渠道）"))
        return
    if sub == "明细":
        rows = G.recent(getattr(args, "n", 20) or 20)
        if not rows:
            print("（还没有粮的流水 —— 监理开始站岗后才有消耗）")
            return
        print("%-20s %-14s %6s  %s" % ("时间", "事由", "增减", "机器"))
        for e in rows:
            sign = e["amount"] if e["kind"] == "grant" else -e["amount"]
            print("%-20s %-14s %+6d  %s" % (e.get("ts", "")[:19], e.get("reason", ""),
                                            sign, e.get("machine") or ""))
        return
    s = G.summary()
    if not s["has_ledger"]:
        print("还没有粮账：监理还没开始站岗（没在消耗，也就不缺粮）。")
        return
    print("粮：%d（还够 %s 天，状态 %s）" % (s["balance"], s["days_left"], s["tier"]))
    print("缺粮阈值：%d 粮；流水 %d 笔。" % (s["threshold"], s["entries"]))
    if s["state"] == "low":
        print("★ 缺粮灯亮：%s" % s["why"])
    print("（这是监理的口粮，不是宿主 AI 工具的积分 —— 后者看 antinel credits。）")


# ------------------------------------------------- verify / report / hub ----
def cmd_morning(args):
    """0.29.0：一屏晨报——昨晚（今日）动作/拦截/提醒/tokens + 昨日对比 + 最重一条。
    单遍扫描账本；生成耗时上屏（承诺 ≤1s）。只聚合事实，不评分、不排名。"""
    import time as _t
    from datetime import timedelta
    t0 = _t.time()
    root = find_project_root()
    if root is None:
        _die("未找到项目根（请在项目内运行晨报；跨项目见 digest --scope all）")
    ad = _audit_dir(root)
    if not os.path.isdir(ad):
        _die("本项目还没有账本（.psl/audit 不存在）。"
             "先接入宿主，跑一次 Agent 会话。")
    sd = _session_dna()
    today = datetime.now().strftime("%Y-%m-%d")
    yest = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    cur = {"a": 0, "b": 0, "w": 0, "t": 0, "by": {}}
    prev = {"a": 0, "b": 0, "w": 0, "t": 0}
    worst = None                                # (sev_rank, rec)
    sev_rank = {"critical": 0, "warning": 1}
    for day, rec in sd._rows(sd._iter_day_files(ad), float("inf"), [False]):
        d = day[:10]
        if d == today:
            t = rec.get("type")
            if t == "pre_tool_use":
                cur["a"] += 1
                if rec.get("decision") == "block":
                    cur["b"] += 1
                    for rid in (rec.get("rules_hit") or []):
                        cur["by"][rid] = cur["by"].get(rid, 0) + 1
                    sr = sev_rank.get(rec.get("severity"), 9)
                    if worst is None or sr < worst[0]:
                        worst = (sr, rec)
                elif rec.get("decision") == "alert":
                    cur["w"] += 1
            elif t == "usage_delta":
                for e in (rec.get("entries") or []):
                    cur["t"] += (e.get("input_tokens") or 0) + (e.get("output_tokens") or 0)
        elif d == yest:
            t = rec.get("type")
            if t == "pre_tool_use":
                prev["a"] += 1
                if rec.get("decision") == "block":
                    prev["b"] += 1
                elif rec.get("decision") == "alert":
                    prev["w"] += 1
            elif t == "usage_delta":
                for e in (rec.get("entries") or []):
                    prev["t"] += (e.get("input_tokens") or 0) + (e.get("output_tokens") or 0)

    def _diff(now, before):
        if now == 0 and before == 0:
            return "—"
        if before == 0:
            return "新增 " + format(now, ",")
        d = now - before
        return "持平" if d == 0 else "%+d" % d

    wk = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"][datetime.now().weekday()]
    print("───────── Antinel 晨报 · %s（%s）─────────" % (today, wk))
    print("  动作 %s ｜拦截 %s ｜提醒 %s ｜tokens %s"
          % (format(cur["a"], ","), cur["b"], cur["w"], format(cur["t"], ",")))
    if cur["by"]:
        print("  拦截构成：" + " · ".join("%s×%d" % kv for kv in sorted(cur["by"].items())))
    if worst:
        wrec = worst[1]
        rid = ",".join(wrec.get("rules_hit") or ["-"])
        inp = wrec.get("input") or {}
        detail = (wrec.get("match_snippet")
                  or inp.get("command") or inp.get("file_path") or "")[:56]
        print("  最重一条：[%s] %s（已挡下）" % (rid, detail))
    print("  对比昨日：动作 %s ｜拦截 %s ｜tokens %s"
          % (_diff(cur["a"], prev["a"]), _diff(cur["b"], prev["b"]),
             _diff(cur["t"], prev["t"])))
    unit = (load_economics(detect_host()).get("unit_label") or "tokens")
    print("  覆盖：本项目 / 宿主 %s（未接入工具不在此列）；记账方式 %s"
          % (detect_host(), unit))
    # 0.28.1（哨兵存活性 v1）：门闸布防时把哨兵在岗状态说出口——dead-man 的消费端。
    # 此前心跳断档没有任何主动呈现，哨兵死了 5 天无人知晓（2026-09-24 死因取证）。
    try:
        import host_shield as _hs
        _st = _hs.load_state()
        if _st.get("enabled"):
            if _hs.sentinel_alive(_st):
                print("  监理：在岗（pid %s）" % _st.get("sentinel_pid"))
            else:
                _age, _ = _hs.sentinel_heartbeat_age()
                print("  ⚠ 监理：不在岗%s——下次 Agent 活动自动复活；手动：antinel host-shield enable"
                      % ("" if _age is None else "，最后心跳 %.0f 分钟前" % (_age / 60.0)))
    except Exception:
        pass
    print("  生成 %.2fs · 数据源=本地审计链（逐条可复算）" % (_t.time() - t0))



def _sibling(name):
    """包内寻址：源码树（同级）与安装布局（scripts/hooks/tools 子目录）都成立。"""
    for d in (_HERE, os.path.join(_HERE, "scripts"), os.path.join(_HERE, "hooks"),
              os.path.join(_HERE, "tools")):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return os.path.join(_HERE, name)


# ★ 0.35.2：verify 之后要摆出来的「你可以自己复算」入口 —— **单一真源**。
#   为什么要有这张表（2026-10-06 真实用户验收实测的缺陷）：
#     `verify` 在链干净时打印 `python <site-packages>/challenge/verify.py`，
#     ★ 而 `challenge/` **根本没进 wheel**（只进了 sdist）⇒ pip 装到的用户
#     照着敲，得到 `Errno 2 No such file or directory`。
#     撞本项目自订规矩：「**页面上不许教跑不通的命令**」。
#   ⇒ 两条修法同时上：
#     ① 让 `challenge/` 真进 wheel（`scripts/build_package.py`）——承诺要兑现；
#     ② 打印前**逐条检查存在**，不在就退回**真的**在线入口（下面 link 字段）——
#        这样即便哪天打包又回归，也**不可能**再打印出一条跑不通的命令。
#   ★ 这张表是打印逻辑与守卫（`ci/verify_promises_guard.py`）**共同的**数据源，
#     不各抄一份 —— 「判据不许二次实现」。
_GH = "https://github.com/sotaex/agentstate/blob/main/"
_VERIFY_RECOMPUTE = (
    ("challenge/verify.py",
     "换一个工具算（不依赖本包，独立实现）",
     _GH + "challenge/verify.py"),
    ("challenge/tamper.py",
     "亲眼看它怎么被改坏（改一条 → 复算 → 报 tamper）",
     _GH + "challenge/tamper.py"),
    ("challenge/tamper-lab.html",
     "浏览器里手动试（不用装任何东西）",
     _GH + "challenge/tamper-lab.html"),
)
# 纯在线入口（本地没有对应文件，天然不会"跑不通"）。
_VERIFY_LINKS = (
    ("看别人的链每天被验一次（公开可查，可交叉核对）",
     "https://github.com/sotaex/agentstate/tree/main/challenge/chain"),
)


def _chain_record_count(adir):
    """这条链里有多少条**带 hash 的记录**（与 tools/verify_chain.py 同口径）。

    为什么要它：`verify` 报 `0 anomalies / rc=0 (clean)` 时，一条**空链**与一条
    **真干净的链**长得一模一样 —— 而含义天差地别。★ 规矩：
    「**『没查到』必须与『没发现』长得不一样**」。
    """
    import json as _json
    n = 0
    try:
        names = os.listdir(adir)
    except OSError:
        return 0
    for fn in names:
        if not fn.endswith(".jsonl"):
            continue
        try:
            with open(os.path.join(adir, fn), encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        if "hash" in _json.loads(line):
                            n += 1
                    except Exception:                             # noqa: BLE001
                        continue
        except OSError:
            continue
    return n


def cmd_verify(args):
    # ★ 0.35.2 修复（2026-10-07）：本函数下方用到 `hs._CREATE_NO_WINDOW`，
    #   但此前 `hs` 只在别的函数里 import ⇒ verify 一跑就 NameError 崩掉，
    #   判定根本没执行（2026-10-07 日报自动化实测，rc=3）。
    import host_shield as hs
    root = find_project_root()
    if root is None:
        _die("未找到项目")
    # ★ 0.57.0（第 32 条）：先报规则快照落差。否则「链上 0 条异常 / 干净」
    #   会被读成「保护到位」——而实际跑的可能是几十个版本之前的规则。
    #   文案与 report 同源（`host_shield.rules_drift_lines`），不另写一份。
    _drift = hs.rules_drift_lines(root)
    if _drift:
        for _ln in _drift:
            print(_ln)
        print("")
    adir = _audit_dir(root)
    n_rec = _chain_record_count(adir)
    # ★ 0.35.2：**先说出我验的是哪条链、有多少条记录**。
    #   为什么（2026-10-06 真实用户验收实测）：同一个目录下 `inbox report` 读的是
    #   registry 里**所有**登记项目根的链（20 文件 / 42065 条），而 `verify` 只读
    #   **当前目录**向上找到的那条链（1 文件 / 0 条）—— 却照样报 `0 anomalies / clean`。
    #   一条空链于是长得和一条真干净的链一模一样 ⇒ **假绿**。
    print("验证目标：%s" % adir)
    print("记录条数：%d" % n_rec)
    cands = (_sibling(os.path.join("tools", "verify_chain.py")),
             os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "tools", "verify_chain.py"))
    for cand in cands:
        if os.path.isfile(cand):
            # ★ 0.35.3 修复（2026-10-08 日报自动化实测）：CREATE_NO_WINDOW 在
            #   MSYS/bash 管道环境下会吞掉子进程 stdout（rc 码照传、明细全丢），
            #   ⇒ verify 表面只剩两行头信息、判异明细不可见。
            #   修法＝capture 后由父进程回放：防闪窗 flag 保留，输出任何宿主都可见。
            _v = subprocess.run([sys.executable, cand, adir],
                                capture_output=True, text=True,
                                encoding="utf-8", errors="replace",
                                creationflags=hs._CREATE_NO_WINDOW)
            rc = _v.returncode
            sys.stdout.write(_v.stdout or "")
            sys.stderr.write(_v.stderr or "")
            if n_rec == 0:
                # ★ 空链不许报"干净"。这与 verify_chain 的 rc=4 是**两处独立的**保险：
                #   即便哪天 verify_chain 的判定被改回去，这里也照样说实话。
                print("")
                print("─" * 60)
                print(" ⚠ 这条链里 0 条记录 —— 这不是「没问题」，是「这里没有东西可查」。")
                print("   · verify 只验当前目录向上找到的那条链；")
                print("   · antinel inbox report 验的是登记过的所有项目的链。")
                print("   若你在别的目录跑过 antinel，请在那个目录下再跑一次 verify。")
                print("─" * 60)
                sys.exit(rc if rc else 4)
            # ★ 0.34.0（E6）：验完之后**把"如何独立复算"摆出来**。
            #   为什么加：复核报告实测到的一条死结 ——
            #     `challenge/` 公开挑战件（attack.py / tamper.py / tamper-lab.html
            #     ／每日公开链 ／五级复算器）是本产品**唯一能满足企业采购理由**
            #     （"给我一份能独立复算的证据"）的能力，
            #     ★ 而 8 份用户文档里**一个字都没提**。
            #   ⇒ **能力最强、叙述为零。** 一句话的"你可以自己验"是最低成本的补救。
            if rc == 0:
                print("")
                print("─" * 60)
                print(" 这条链你可以自己复算，不需要相信监理：")
                for i, (rel, desc, link) in enumerate(_VERIFY_RECOMPUTE, 1):
                    local = _sibling(rel)
                    print("   %d) %s：" % (i, desc))
                    # ★ 0.35.2：**存在才打印本地命令**，否则退回真的在线入口。
                    #   这条 isfile 就是「不许教跑不通的命令」的**执行点**。
                    if os.path.isfile(local):
                        print("        python %s" % local)
                    else:
                        print("        （本机这份没随包，用在线版）")
                        print("        %s" % link)
                n = len(_VERIFY_RECOMPUTE)
                for j, (desc, url) in enumerate(_VERIFY_LINKS, n + 1):
                    print("   %d) %s：" % (j, desc))
                    print("        %s" % url)
                print("")
                print("   ★ 复算规则。每条的 hash 这样算：")
                print("   sha256(上一条的 hash ＋ 本条规范化后的 JSON)")
                print("     改一个字节就能被指出；删掉中间任何一条，链就接不上。")
                print("─" * 60)
            sys.exit(rc)
    _die("verify_chain.py 不存在")


def _sibling_dir(sub):
    return os.path.join(_HERE, sub)


def cmd_ledger_top(args):
    """★ 0.53.0（T4.1）`antinel ledger [--days N] [--json]`：按天账的机器出口。

    ★ 数据只走 `inbox_model.ledger_rows`（**唯一实现**，内部就是账本页用的
      `day_counts`）—— 本函数只取数＋排版，不另算一份（同源纪律）。
    ★★ 无记录的天在 JSON 里是 `null`、在文本里是「—（当天无记录）」，
      **不给 0**：那台机器那天可能没开机，「没查」与「查过没事」必须可区分。
    """
    import json as _json
    import inbox_model as _M
    import inbox_store as _ST
    days = getattr(args, "days", None) or 7
    # ★★ 0.53.2：`--days N` 只决定**输出几行**，记录本身必须**全量**取。
    #   旧版 `_ST.load_items()` 默认 7 天窗口 ⇒ `--days 30` 打印 30 行、其中
    #   22 行是「当天无记录」—— 那是**没读到**，不是那天没开机（与"无记录给
    #   null 不给 0"的护栏意图正好相反：护栏是为了区分"没查"与"查过没事"，
    #   而窗口把"没查"伪装成"没开机"）。
    rows = _M.ledger_rows(_ST.load_items_all(), days=days)
    if getattr(args, "json_out", False):
        print(_json.dumps(rows, ensure_ascii=False, indent=1))
        return 0
    if not any(r.get("events") is not None for r in rows):
        print("账本尚无可核对记录；这表示还没有能统计的内容，"
              "不是确认累计为零。")
        return 0
    for r in rows:
        if r.get("events") is None:
            print("%s  —（当天无记录）" % r["date"])
        else:
            print("%s  记录 %d 条 ｜ 已处理 %d ｜ 未处理 %d"
                  % (r["date"], r["events"], r["acked"], r["pending"]))
    print("只统计本机审计记录；不代表全天在线，也不是 AI 工具积分余额。")
    return 0


def cmd_brief(args):
    """★ 0.34.0（E1）**决策层一页纸**。

    为什么要有这条命令（实测出来的缺口，不是设想的）：
      `antinel report` 的 19 行正文里，有 8 行是给**安全工程师**看的
      （config health / hook health / host attribution / enforcement probe /
       gate alive days / rules fallback / trust-boundary edits /
       whitelist-released secrets reads）。这些是真价值。
      ★ 但**决策层要的三个数字一个都没有**：
         ① 我的 AI 工具有没有把数据传出去？
         ② 这期比上期是升了还是降了？
         ③ 我现在该做什么、谁来做？
      一个 CTO 看到 `host attribution: 0/3 records UNVERIFIED` 不会有任何动作。

    ⇒ 所以**不是**把 report 做"更强"，而是**按人分层**。
      本命令给决策层：`report` 继续给工程师（默认行为不变，向后兼容）。

    ★ 口径纪律（与 report.py / digest 同一套判据，**不二次实现**）：
      · 外发结论只认 canary（内容被读 ＋ 带出去过）与 sensitive_output；
        两者都没命中时**明说"没见到 ≠ 没有"**。
      · 所有数字都带分母或有"未覆盖"说明，异单位永不加和。
      · 本命令**只读**，不写任何文件、不改任何状态。
    """
    days = getattr(args, "days", None) or 7
    root = find_project_root()
    if root is None:
        _die("未找到项目（在项目根目录运行，或用 --scope all 看已登记的全部项目）")
    ad = _audit_dir(root)
    if not os.path.isdir(ad):
        _die("这个项目还没有账本 —— 先装一次：python -m scripts.install --root .")

    now = _agg_audit(ad, days)                     # 本期

    # ★ 上期单独算（见 `_period_delta`），**不用"本期减上期"**：
    #   减法在计数上会出负数，在异单位（积分/token）上会直接失真 ——
    #   那正是本项目反复记为「异单位永不加和」的那类错。

    print("=" * 68)
    print(" Antinel 决策层一页纸｜%s" % datetime.now().strftime("%Y-%m-%d %H:%M"))
    print(" 统计范围：近 %d 天 ｜ 项目：%s" % (days, root))
    print("=" * 68)

    # ── ① 有没有把数据传出去 ────────────────────────────────────────
    print("")
    print("【一】数据有没有被 AI 工具带出去")
    if now.get("canary_leak"):
        print("  🔴 有确凿证据：%d 次蜜饵标记出现在工具输出里" % now["canary_leak"])
        print("        （内容被读过 ＋ 带出项目外。命令：antinel report --days %d 看是哪条工具）" % days)
    elif now.get("sensitive_output"):
        print("  🟠 未见蜜饵命中，但 %d 次输出命中敏感模式 —— 需要看一眼" % now["sensitive_output"])
        print("        （命令：antinel report --days %d）" % days)
    else:
        print("  ⚪ 这一期没见到外传证据")
        print("        ★ 请读作『没查到』，不是『没有』——会偷的工具不会写记录。")
        print("        想换更强的证据：antinel canary plant（埋标记，"
              "标记出现在输出里才会被记下）")
    _zero = now.get("untrusted_host", 0) + now.get("low_conf_host", 0)
    if _zero:
        print("        ⚠ 另有 %d 条记录的宿主标签不可信（旧格式，无归因证据）"
              % _zero)
        print("          —— 这部分连『哪个工具做的』都说不准，antinel report 会单列。")

    # ── ② 比上期升了还是降了 ────────────────────────────────────────
    print("")
    print("【二】和上一期比")
    _d = _period_delta(ad, days)
    if _d is None:
        print("  （上一期没有可比数据 —— 本机是新装的，或账本还没攒够 %d 天）" % (days * 2))
    else:
        print("  拦截次数   %d → %d  %s" % (_d["blocks"], now["blocks"], _arrow(now["blocks"], _d["blocks"])))
        print("  操作次数   %d → %d  %s" % (_d["actions"], now["actions"], _arrow(now["actions"], _d["actions"])))
        if now.get("canary_leak") or _d.get("canary_leak"):
            print("  外传证据   %d → %d  %s" % (_d.get("canary_leak", 0), now.get("canary_leak", 0),
                                                _arrow(now.get("canary_leak", 0), _d.get("canary_leak", 0))))
        if now.get("fail_open") or _d.get("fail_open"):
            print("  ⚠ 放行次数 %d → %d  %s（钩子异常放行＝当时闸门不在岗）"
                  % (_d.get("fail_open", 0), now.get("fail_open", 0),
                     _arrow(now.get("fail_open", 0), _d.get("fail_open", 0))))
        print("  ★ 「操作变多」本身不是坏事（用得多）；要盯的是拦截与放行。")

    # ── ③ 我现在该做什么 ────────────────────────────────────────────
    print("")
    print("【三】你现在要做的")
    import host_shield as hs
    try:
        pend = hs.load_pending()
    except Exception:
        pend = []
    todo = []
    if pend:
        todo.append(("🔴 %d 个落点等你表态（不表态就一直拦着）" % len(pend),
                     'antinel host-shield queue   # 看清单\n'
                     '        antinel host-shield decide "<路径>" allow_always｜deny'))
    if now.get("fail_open"):
        todo.append(("⚠ %d 次钩子异常导致放行 —— 闸门当时不在岗"
                     % now["fail_open"],
                     "python -m tools.enforce_probe   # 复检拦截信号是否真的生效"))
    if now.get("gaps"):
        todo.append(("🔴 %d 次「已判拦截但仍被执行」—— 宿主没尊重 deny 信号"
                     % now["gaps"],
                     "看 report 的【执法】段 ＋ 核对宿主钩子协议"))
    if now.get("untrusted_host"):
        todo.append(("⚠ %d 条记录的宿主标签不可信 —— 归因证据缺失"
                     % now["untrusted_host"],
                     "换宿主或宿主大版本更新后跑一次：python -m tools.probe_host"))
    if not now.get("canary_leak") and not now.get("sensitive_output"):
        todo.append(("○ 想把『没见到』变成『有证据』",
                     "antinel canary plant   # 埋蜜饵，之后正常使用 AI 工具"))
    if not todo:
        print("  ✓ 这一期没有需要你动手的事。")
    for i, (what, how) in enumerate(todo, 1):
        print("  %d) %s" % (i, what))
        print("     %s" % how)

    # ── 覆盖声明（永远在最后，分母显式）────────────────────────────────
    print("")
    print("-" * 68)
    print(" 覆盖：1 个项目 ｜ 本页只看【汇总计数】，逐条明细在 "
          "antinel report --days %d" % days)
    print(" 边界：规则只匹配工具调用的文本，不解析脚本内容。"
          "写进 .py/.sh 再执行，就不会被拦。")
    print("       护栏不是隔离层。antinel verify 可独立复算本机账本。")
    print("=" * 68)
    return 0


def _arrow(cur, prev):
    """涨跌标记。只标方向不标好坏——拦截变多是正常的。"""
    if cur == prev:
        return "（持平）"
    d = cur - prev
    return "（%s%d）" % ("↑" if d > 0 else "↓", abs(d))


def _period_delta(audit_dir, days):
    """上期（再往前的 days 天）的聚合计数。

    ★ 为什么不去 `_agg_audit` 里加一个 since 参数（那才是干净做法）：
      本函数是 0.34.0 的临时实现，**宁可多写一行也不改被审计的判据** ——
      `_agg_audit` 同时被 digest / morning 用着，改它的签名会牵动两个已发布命令。
      TODO: 若这条命令活下来，把 since 参数做进 `_agg_audit`，本函数退化为调用它。
    """
    try:
        from datetime import timedelta
        # 取"days+1 .. days*2"这一段：先扫全量，再按 ts 的日期分段。
        cur_lo = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        hi = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        lo = (datetime.now() - timedelta(days=days * 2 - 1)).strftime("%Y-%m-%d")
        acts = blocks = warns = toks = fail_open = gaps = canary = 0
        untrusted = 0
        sd = _session_dna()
        for day, rec in sd._rows(sd._iter_day_files(audit_dir), float("inf"), [False]):
            d10 = day[:10]
            if d10 > hi or d10 < lo:
                continue
            t = rec.get("type")
            if t in ("pre_tool_use", "post_tool_use") and rec.get("host_confidence") is None:
                untrusted += 1
            if t == "pre_tool_use":
                acts += 1
                if rec.get("decision") == "block":
                    blocks += 1
                elif rec.get("decision") == "alert":
                    warns += 1
            elif t == "usage_delta":
                for e in (rec.get("entries") or []):
                    toks += (e.get("input_tokens") or 0) + (e.get("output_tokens") or 0)
            elif t == "hook_error":
                fail_open += 1
            elif t == "enforcement_gap":
                gaps += 1
            elif t == "post_tool_use":
                canary += len(rec.get("canaries_observed") or [])
        return {"actions": acts, "blocks": blocks, "warnings": warns,
                "tokens": toks, "fail_open": fail_open, "gaps": gaps,
                "canary_leak": canary, "untrusted_host": untrusted}
    except Exception:
        return None


def cmd_report(args):
    # ★ 0.35.2 修复（2026-10-07）：同 cmd_verify——函数内用到 `hs._CREATE_NO_WINDOW`
    #   但缺局部 import ⇒ report 一跑就 NameError。
    import host_shield as hs
    root = find_project_root()
    if root is None:
        _die("未找到项目")
    argv = [sys.executable, _sibling("report.py"), "--root", root]
    # ★ 0.53.0 修复（2026-10-17）：`scripts/report.py` 里 `if args.session:
    #   return _session_dna_main(...)` 排在 days 处理**之前** ⇒ 只要传了
    #   --session，--days 就被静默吞掉。而本函数此前无条件传 --session latest
    #   （default 值），于是「按天看明细」这个语义永远到不了底层。
    #   ⇒ 用户没点名会话（仍是默认 latest）时不传 --session，让它走按天路径；
    #     显式点名会话时两样都传（report.py 的既有优先序：会话优先）。
    _days = getattr(args, "days", None)
    if _days is None or args.session != "latest":
        argv += ["--session", args.session]
    if _days is not None:
        argv += ["--days", str(_days)]
    if getattr(args, "write", False):
        argv.append("--write")
    if args.write:
        argv.append("--write-dna")
    # ★ 0.35.3 修复（2026-10-08）：同 cmd_verify——CREATE_NO_WINDOW 在 bash 管道下
    #   吞子进程 stdout ⇒ report 明细不可见。capture 后回放。
    _r = subprocess.run(argv, capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        creationflags=hs._CREATE_NO_WINDOW)
    sys.stdout.write(_r.stdout or "")
    sys.stderr.write(_r.stderr or "")
    sys.exit(_r.returncode)


def cmd_hub(args):
    import hub as hubmod
    if args.sub == "register":
        if not os.path.isdir(os.path.join(args.path, ".psl")):
            _die("该目录没有 .psl（未安装 Antinel？）：%s" % args.path)
        hubmod.register(args.path, args.host or detect_host(),
                        registered_by=_invoked_by())
        print("✓ 已登记：", os.path.abspath(args.path))
    elif args.sub == "unregister":
        n = hubmod.unregister(args.path)
        print("移除 %d 条" % n)
    elif args.sub == "tools":
        hubmod.set_tools_declared(args.tools)
        print("✓ 在用工具清单：", ", ".join(hubmod.load_registry()["tools_declared"]))
    else:
        reg = hubmod.load_registry()
        for p in reg["projects"]:
            print(" ", p["root"], "（%s）" % ",".join(p["hosts"]))
        if reg.get("tools_declared"):
            declared = set(reg["tools_declared"])
            covered = {h for p in reg["projects"] for h in p.get("hosts") or []}
            miss = sorted(declared - covered)
            if miss:
                print("  未接入：", ", ".join(miss))


# ------------------------------------------------------------ help ----
# ★ 0.55.3（2026-10-23）：这里原来是一个 `HELP_HOSTLINE` 常量，而 strings.py 的
#   `help_header` 里存着同一条文案的 11 个语言版本、却**没有任何使用点** ——
#   改 strings 那边等于没改（实测：11 语言全改成 Antinel 之后，`antinel help`
#   首行仍打 AgentState；切 `ANTINEL_LANG=en` 也仍打中文）。
#   品牌名只留一个源：strings.help_header。
def _help_hostline(version, host, unit):
    try:
        import strings as _st
        return _st.get_string(_st.detect_lang(), "help_header",
                              V=version, H=host, U=unit)
    except Exception:
        return "Antinel 监理 v%s ｜ 宿主: %s（记账方式: %s）" % (version, host, unit)


def cmd_help(_args=None):
    host = detect_host()
    prof = load_economics(host)
    _unit = prof.get("unit", "?")
    print(_help_hostline(VERSION, host, _unit))
    # 0.29.0（C-5/D3）：credits 子命令只在 unit=credits 的宿主存在（见本文件抬头 §经济画像）。
    # 此前 help 无条件把三条 `antinel credits …` 印出来，而 zcode/qoder/generic 的 unit 是
    # tokens、claude-code 是 USD ⇒ 印出来的命令一跑就 _die（cmd_credits 会拒绝）。
    # help 是"本宿主"的交互面，按画像过滤；判据取"命令是否以 antinel credits 开头"，
    # 这样 `antinel report --session latest` 这类跨单位命令仍保留。
    # ★ cmd_routes **不过滤**：那是宿主无关的路由契约，会被烘进随包 references/AGENT_SKILL.md，
    #   在那里藏掉 credits 反而会让 workbuddy 宿主的 Agent 不知道有这条命令。
    _routes = [r for r in ROUTES
               if _unit == "credits" or not r[1].strip().startswith("antinel credits")]
    print("── 你可以对 Agent 说 ───────────────────────")
    for u, _c, _cat in _routes:
        print("  「%s」" % u)
    print("── 命令（Agent 替你跑，也可以自己跑）─────────")
    for cat in ("审核", "防范", "账本"):
        rows = [(u, c) for (u, c, k) in _routes if k == cat]
        if rows:
            print("  ◇ %s" % cat)
            for _u, c in rows:
                print("    %s" % c)
    print("    antinel settings list ｜ hub list ｜ routes --markdown")
    # ★ 0.48.4：给 Agent 的极简路口。上面 60 行是**给人看的**（"你可以对 Agent 说"
    #   那一段对 Agent 本身毫无意义——它不需要被教用户会怎么说）。Agent 只需要三行。
    print("── 如果你是 Agent ─────────────────────────")
    print("  antinel agent --json    一个 JSON 拿到：装没装、什么宿主、下一步敲什么")
    print("  antinel install         装钩子（等价 python -m scripts.install）")
    print("  antinel skill           随包操作手册（--path 只给路径，省 token）")
    print("  包名是 antinel（pip install antinel）—— 不是 antinel-security")
    print("── 提示 ───────────────────────────────────")
    print("  拦截消息里给出的命令可直接执行；所有配置变更均进审计链。")
    print("  多宿主共存机器：Agent 自报宿主。写法 antinel --host zcode …，"
          "记在它报的那家名下。")
    print("  分寸：记录 Agent 的行为与消耗；不做人的效率排名。")
    # 0.29.0（G-4）：网络外传的默认档位**显式说出来**。
    # 实测：hooks/pre_tool_use.py 里 `.get("net_mode","warn")` —— 默认只提醒不拦；
    # 且两个真实 .psl/policy.json 里都**没有**这个键 ⇒ 生效的就是隐藏默认。
    # 不说出来，用户会以为"网络外传已被拦"，那是自我安慰；说出来，选择权才在人手里。
    # ★ 读不到就**如实说读不到**，不假装是 warn（假方案比没方案更坏）。
    _nm, _nm_note = None, ""
    _root = find_project_root()
    if _root is None:
        _nm_note = "未找到项目 .psl，按内置默认"
    else:
        try:
            _gs = (_load_json(os.path.join(_root, ".psl", "policy.json")) or {}).get(
                "global_settings") or {}
            if "net_mode" in _gs:
                _nm, _nm_note = str(_gs["net_mode"]).lower(), "策略文件已显式设置"
            else:
                _nm_note = "策略文件未设置该键，按内置默认"
        except Exception as _e:
            _nm_note = "策略文件读取失败（%s），按内置默认" % type(_e).__name__
    if _nm is None:
        _nm = "warn"
    print("  ⚠ 网络外传当前设置：net_mode=%s  [%s]" % (_nm, _nm_note))
    if _nm != "block":
        print("     ★ 即：未白名单域名的网络命令只提醒、不拦截。"
              "要拦：antinel settings set net_mode block")
    else:
        print("     ★ 未白名单域名的网络命令会被挡下。")


def cmd_routes(args):
    if args.markdown:
        print("<!-- 由 `antinel routes --markdown` 生成；与 help 同源（ROUTES） -->")
        print("当用户表达下列意图时，运行对应命令（命令幂等；配置变更自动进审计链）。")
        print()
        print("★ 语义匹配，不是词表匹配：下面的用户话语只是示例，不是触发条件。")
        print("用户用任何说法表达同类意图。下面这些只是例子："
              "「胡搞/乱来/越界/偷传/不乖/瞎动」，将来出现新说法也一样。")
        print("都应执行对应命令。语义对上就执行，不要等词对上。")
        print()
        for u, c, _cat in ROUTES:
            print("- 「%s」→ %s" % (u, c.replace("\\", "\\\\")))
        print("- 「antinel / 帮助 / 你能做什么」→ antinel（help 清单）")
        print("- 多宿主共存的机器上，Agent 应自报所在宿主：antinel --host zcode …"
              "（workbuddy|zcode|qoder|claude-code）。"
              "不报的话，记账方式按这台电脑探测到的显示。")
        return
    for u, c, _cat in ROUTES:
        print("%s\t%s" % (u, c))


# ------------------------------------------------------------ main ----
# ------------------------------------------------------ host-shield/audit ----
def _shield_chain_dir():
    """门闸哨兵**真正在读**的那条链的目录（＝包根下的 `.psl/audit`，没有则个人中枢）。

    ★★ 为什么必须有这个函数（0.35.3，盘上证据）：
      门闸相关的记录此前**散在三个地方** ——
        · 哨兵自己写的（心跳/篡改/breach）→ `<包根>/.psl/audit/`
        · CLI 写的（unlock/decide）→ `~/.antinel/rollup/`
        · 策略改写（`policy_changed`）→ `<项目根>/.psl/audit/`
      而哨兵的链背书判定**只读自己那一条** ⇒ 另外两条里的"授权记录"它**一条也看不见**
      ⇒ 每一次改哨兵状态都会被判成"无链背书被修改"并回滚。
      修法：**改哨兵状态的地方，就在哨兵自己那条链上留一条授权记录**。
    """
    import host_shield as _hs
    # ★★★ 0.40.0（A4，堵源①）：**沙箱里跑的命令，授权也必须落在沙箱里**。
    #   设了 `ANTINEL_HUB_DIR`（测试/套件沙箱）时，旧实现的硬绑定会返回
    #   "包根下的 `.psl/audit`" —— 也就是**真项目的链**。于是
    #   `antinel zone add <临时目录>` 的授权记录被写进真链 ⇒ 真哨兵读到这条"背书"、
    #   把早已改名的临时目录纳入执法、去加锁 ⇒ 锁不上 ⇒ 每跑一次测试刷一批
    #   R0「安全区加锁失败」（盘上实测 93 条，路径全部是
    #   `C:\Temp\...\antinel_harness_*` / `antinel_verify_work`，**0 条真实目录**）。
    #   ⇒ 跟随中枢：沙箱下与哨兵在沙箱里的 rollup 同处一地。
    #   ★ 生产不受影响：未设 `ANTINEL_HUB_DIR` 时展开结果与旧写法**逐字相同**。
    if os.environ.get("ANTINEL_HUB_DIR"):
        return _hs._hub_rollup_dir()
    return _hs._shield_audit_dir(os.path.dirname(_sibling("antinel.py")))


def _sync_zone_state(norm, adding=True):
    """把 zone 变更同步进哨兵状态（**幂等**），并在哨兵自己的链上留一条授权记录。

    ★★ 修的是什么（0.35.3，两条真缺陷）：
      ① 旧版 `st.setdefault("zones", []).append(norm)` —— **无条件追加**：
         重复执行 `zone add` 造重复项；而且**每一次都改 state 指纹** ⇒
         哨兵判一次"无链背书被修改" ⇒ `save_state(last_good)` **把用户刚设的安全区回滚**。
         （盘上证据：全链 12 条 `host_shield_tamper` + `field="state"`，全部紧跟
          「哨兵被重新拉起」、全部带"已回写恢复"＝防线自己扛住了却记成失守。）
      ② 这一改**没有任何哨兵能看见的链记录** ⇒ 无论幂等与否都会被判篡改。
         `seven_step` 写的 `policy_changed` 落在**项目链**，而哨兵读的是**包链** ——
         两处副本，哨兵永远看不到。
      ⇒ 现在：改了才写、幂等、并且**把授权记录写到哨兵自己那条链上**。

    ★ 不弹气泡（`notify=False`）：创始人 2026-10-06 明确说右下冒泡有问题；
      安全区变更由Antinel 监理收件箱呈现，不再走弹窗。
    返回 True 表示哨兵状态**真的变了**。
    """
    try:
        import host_shield as hs
    except Exception as e:                                   # noqa: BLE001
        print("（监理未运行；防篡改锁将在监理启动时生效）")
        return False
    try:
        st = hs.load_state()
        zs = list(st.get("zones") or [])
        key = norm.replace("/", "\\").lower()
        keys = [str(z).replace("/", "\\").lower() for z in zs]
        if adding and key in keys:
            print("· 监理状态里已有该目录（未重复写入）")
            return False
        if (not adding) and key not in keys:
            print("· 监理状态里没有该目录（无需移除）")
            return False
        if adding:
            zs.append(norm)
        else:
            zs = [z for z, k in zip(zs, keys) if k != key]
        st["zones"] = zs
        hs.save_state(st)
        # ★ 授权记录：写在**哨兵自己那条链**上（`_ChainTail` 与 `chain_backing_fields`
        #   都从那儿读）—— 先改状态、后留痕，哨兵下一拍就能看到背书。
        hs.record(_shield_chain_dir(), "host_shield_changed", decision="allow",
                  severity="warning", field="zones",
                  change="zones %s %s" % ("+" if adding else "-", norm),
                  invoked_by=_invoked_by(),
                  reason=("安全区%s：%s（监理执法状态已同步）"
                          % ("生效" if adding else "解除", norm)),
                  notify=False)
        print("✓ 监理已纳入执法（防篡改锁即时生效）" if adding
              else "✓ 监理已解除该安全区")
        return True
    except Exception as e:                                   # noqa: BLE001
        print("（监理状态同步失败：%r）" % (e,))
        return False


def cmd_zone(args):
    """0.26.0 安全区：目录进保险库——防篡改（deny 写）+ 出网被闸（net_mode=block）。
    数据经用户同意放入，之后区内不可变；出口在 NET block。

    ★★ 0.35.3 修（第三条真缺陷，读码发现）：**`zone remove` 从来就是 `zone add` 的副本**。
      子命令解析器里明明有 `remove`，函数体却只有 `list` 分支，其余一律走 add 的 mut
      ⇒ `zone add` 打印的撤销提示「antinel zone remove <路径>」**照着跑等于再加一次**
      （或 no-op）—— 用户按提示撤销，**撤不掉**，而且看不出哪里不对。
      ⇒ 现在 add / remove 各走各的。
    """
    root = find_project_root()
    if root is None:
        _die("未找到项目")
    pol_path = os.path.join(root, ".psl", "policy.json")
    if args.sub == "list":
        try:
            for z in (_load_json(pol_path).get("zones") or []):
                print(" ", z)
        except Exception:
            pass
        return
    norm, err = validate_root(args.dir)
    if err:
        _die("校验失败：%s\n  示例：antinel zone add D:\\archive\\重要资料" % err)
    if not os.path.isfile(pol_path):
        _die("项目策略不存在（先执行任一 antinel 写命令自动创建）")

    adding = (args.sub == "add")
    key = norm.replace("/", "\\").lower()

    def mut(data):
        zs = data.setdefault("zones", [])
        keys = [z.replace("/", "\\").lower() for z in zs]
        if adding:
            if key in keys:
                return None
            zs.append(norm)
            return "zones + %s" % norm
        keep = [z for z, k in zip(zs, keys) if k != key]
        if len(keep) == len(zs):
            return None
        data["zones"] = keep
        return "zones - %s" % norm

    label = "zone %s %s" % ("add" if adding else "remove", norm)
    impact = ("安全区生效：该目录对 Agent/宿主进程 只读（防篡改）。"
              "配合 net_mode=block，出网被闸" if adding else
              "安全区解除：该目录恢复可写（出网闸由 net_mode 单独决定）")
    undo = ("antinel zone remove %s" % norm if adding
            else "antinel zone add %s" % norm)
    outcome = seven_step(label, pol_path, _policy_loader(pol_path), mut, impact,
                         undo, "zones", root)
    if outcome == "cancelled":
        return                       # ★ 用户没点头 ⇒ 哨兵状态一个字节都不动
    _sync_zone_state(norm, adding=adding)


def _startup_folder_cmd():
    """启动文件夹里的自启 shim 路径（schtasks 被宿主 Program Blacklist 拦时的回退位）。

    ★ 0.51.2：本条**降为兜底**（PowerShell 不可用时才用）—— 首选见
      `_startup_folder_lnk()`：`.cmd` 必然带一个控制台窗口，见那边的说明。
    """
    appdata = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(appdata, "Microsoft", "Windows", "Start Menu",
                        "Programs", "Startup", "antinel-shield.cmd")


def _startup_folder_lnk():
    """启动文件夹里的无窗口自启快捷方式（.lnk → pythonw.exe）。"""
    appdata = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(appdata, "Microsoft", "Windows", "Start Menu",
                        "Programs", "Startup", "antinel-shield.lnk")


def _pythonw_exe():
    """sys.executable 的 pythonw 变体（GUI 子系统，不建控制台）；没有则退回本尊。"""
    exe = sys.executable or ""
    d, _b = os.path.split(exe)
    w = os.path.join(d, "pythonw.exe")
    return w if os.path.isfile(w) else exe


def _create_startup_lnk(lnk_path):
    """建 `.lnk`（PowerShell + WScript.Shell COM，Windows 自带，不装依赖）。成功返回 True。

    ★★ 为什么自启**必须**是 .lnk 而不是 .cmd（创始人 2026-10-17：
      「重启时弹出的大黑窗口……这种能否不显示，甚至不一闪而过？
        让用户感觉不到存在是最好的」）：
      `.cmd` 由 cmd.exe/conhost 执行 ⇒ **必然**有一个控制台窗口 —— 前台跑
      常驻哨兵时它会**一直开着**；改成 `start /b` 只能消掉"常驻"，消不掉
      启动那一闪。唯一**真无窗口**的入口是 `.lnk` → `pythonw.exe`
      （GUI 子系统，不创建控制台）：explorer 直接 CreateProcess，全程无 conhost。
    ★ 代价与兜底：pythonw 下 `sys.stdout`/`sys.stderr` 是 `None` ⇒
      `host_shield._no_console_streams()` 先把流接到
      `~/.antinel/logs/sentinel.log`，否则那些 `print(flush=True)` 会把哨兵打崩
      （那比看得见窗口严重得多：用户以为有保护，实际没有）。
      PowerShell 不可用时**如实退回 .cmd**（有窗口，但哨兵照跑）——
      宁可看得见，不可没有保护。
    """
    import host_shield as _hs                 # 与文件内其他处一致：延迟导入
    # ★ 0.60.0：**薄委托** —— 实现在 `host_shield.create_autostart_lnk`。
    #   为什么不能各留一份：哨兵（升级后自动修老任务）也要建同一个 `.lnk`，
    #   两份实现必然漂（本仓第一顽症），而这次漂的代价是"一处改好、另一处照旧闪窗"。
    return _hs.create_autostart_lnk(
        lnk_path, script=_sibling("host_shield.py"),
        root=os.path.dirname(_sibling("antinel.py")), icon=_brand_icon())


def _neutral_lnk():
    """自启 `.lnk` 的**中立落点**（不在启动文件夹里）：`~/.antinel/antinel-shield.lnk`。

    ★ 0.60.0：为什么要有中立落点 —— `schtasks /TR` 与「启动文件夹」两条注册路径
      必须指向**同一件东西**（一个 `.lnk`），否则又是"同一事实两处副本"。放在
      启动文件夹里当 schtasks 成功时会**双份拉起**，所以落点必须在中立目录，
      需要启动文件夹时再**复制**过去。
    """
    import host_shield as _hs
    return _hs.neutral_autostart_lnk()


def _archive_legacy_startup():
    """把启动文件夹里所有**会闪窗的旧自启件**移出（改名不删，零删除纪律）。

    要移的三类（全部是 0.60.0 之前留下的）：
      · `antinel-shield.cmd`         —— 活的 `.cmd`：登录必闪一个控制台
      · `antinel-shield.cmd.away-*`  —— 已归档但仍躺在启动文件夹里（真源不清）
      · `antinel-shield.lnk.away-*`  —— 同上（不闪，但属于"退役件没搬走"）
    ★ 为什么不只是改名：`.away-` 后缀不参与启动，**不闪**；但它留在用户的启动
      文件夹里，等于把退役件堆在人家门口 —— 换个名字回去就复原了。搬到
      `~/.antinel/archive/` 才是"退役件离开现场"，且证据仍在、随时可恢复。
    返回被搬走的路径列表。
    """
    import host_shield as _hs
    return _hs.archive_legacy_startup()


# ------------------------------------------------- 0.52.0：桌面入口 ----
# ★ 为什么要有桌面入口（创始人 2026-10-17：「用户下载安装之后，是否也默认在
#   用户桌面放上呢，用户体验一定要照顾周全」）：pip 装完只有 `antinel` 命令，
#   普通用户找不到入口 ⇒ 装了却用不上。enable 一键布防时**默认放**桌面
#   （`--no-desktop` 可关），与自启同形态（pythonw 无窗口＋品牌图标）。
# ★ 对称卸载（UX 周全的另一半）：disable 撤防时一并**归档**桌面入口（改名
#   不删）—— pip uninstall 删不到包外文件，不处理的话卸载后桌面留个点开
#   报错的死图标，那是"卸载不干净"差评最常见的来源。完整卸载＝disable ＋
#   pip uninstall（文档里写清）。

def _desktop_dir():
    """桌面目录（Known Folder，尊重 OneDrive 重定向）；取不到退回 ~/Desktop。"""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        # CSIDL_DESKTOP = 0（每用户桌面，不含公用）；S_OK = 0
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0, None, 0, buf) == 0:
            return buf.value
    except Exception:
        pass
    return os.path.join(os.path.expanduser("~"), "Desktop")


def _desktop_entry_path():
    """桌面入口路径：Antinel 监理.lnk（与 Toast AUMID 快捷方式同名不同目录）。"""
    return os.path.join(_desktop_dir(), "Antinel 监理.lnk")


def _brand_icon():
    """品牌图标绝对路径（单一真源 inbox_window.brand_icon_path）；缺失 None。"""
    try:
        import inbox_window as _iw
        return _iw.brand_icon_path()
    except Exception:
        return None


def _spawn_mode_text(mode, ok):
    """把 `spawn_sentinel` 的模式翻译成用户读得懂的一句话（★ 唯一实现）。

    ★ 40 格 · 时间·挡：时钟被改过时模式是 `clock-skew` —— 它既不是"已在岗"，
      也不是"拉起失败"。以前两种情形共用一句"拉起失败，由它自动复活"，
      于是用户看到的是"失败了但会自己好"，而事实是"**没人动过它，先校准时钟**"。
    """
    if mode == "clock-skew":
        return "系统时钟被改过，这次没动它（先校准时钟再看）"
    if ok:
        return {"already-running": "已在岗（心跳新鲜）", "detached": "已拉起（独立进程）",
                "detached-breakaway": "已拉起（脱离会话）"}.get(mode) or str(mode)
    return "拉起失败，由它自动复活"


def _create_desktop_lnk(lnk_path=None):
    """建桌面入口 `.lnk`（pythonw 无窗口＋品牌图标）。成功返回路径，失败返回 None。

    ★ 目标：`pythonw.exe -I -S inbox_cli.py window`（与启动文件夹自启同一手法：
      PowerShell＋WScript.Shell COM，Windows 自带，零依赖）。`-I -S` 与哨兵
      一致（隔离 PYTHONPATH 等环境投毒；本机实测不清 PYTHONPATH 会站点初始化卡死）。
    ★ 开窗是**短命进程**（窗口归长命服务所有，关掉入口不影响服务）；
      pythonw 下 print 落 `~/.antinel/logs/console.log`（`_no_console_streams`），
      失败不静默。
    ★ 失败不假装：任何一步不成立就返回 None，由调用方如实告知＋给补建命令。
    """
    import host_shield as _hs                 # 与文件内其他处一致：延迟导入
    pyw = _pythonw_exe()
    icli = _sibling("inbox_cli.py")
    root = os.path.dirname(_sibling("antinel.py"))
    if not (pyw and icli and os.path.isfile(icli)):
        return None
    path = lnk_path or _desktop_entry_path()
    args = '-I -S "%s" window' % icli
    icon = _brand_icon()
    ps = ("$w=New-Object -ComObject WScript.Shell;"
          "$s=$w.CreateShortcut('%s');"
          "$s.TargetPath='%s';$s.Arguments='%s';$s.WorkingDirectory='%s';"
          "$s.Description='Antinel 监理';"
          % (path, pyw, args, root))
    if icon:
        ps += "$s.IconLocation='%s';" % icon
    ps += "$s.Save()"
    try:
        r = subprocess.run([_hs._POWERSHELL, "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-Command", ps],
                           capture_output=True, timeout=30,
                           creationflags=_hs._CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return None
    return path if (r.returncode == 0 and os.path.isfile(path)) else None


def _archive_desktop_entry(lnk_path=None):
    """桌面入口改名归档（零删除）。返回归档路径；不在则 None（不谎报归档）。"""
    path = lnk_path or _desktop_entry_path()
    if not os.path.isfile(path):
        return None
    away = path + ".away-" + datetime.now().strftime("%Y%m%d%H%M%S")
    try:
        os.replace(path, away)
        return away
    except OSError:
        return None


# ★ 单一真源（2026-09-26 B3）：护盾"开着"时**到底拦不拦**。
#   实测矛盾：`enable` 打印"登记路径的外传落点默认拒绝"，而 `status` 打印
#   "未裁决落点默认只报不拦" —— 同一次操作，前后自相矛盾。
#   H-1（0.29.0）已认定旧文案不再成立，但当时只改了 status。
#   危害是实质的：用户开完护盾会以为**已经在拦**，其实一条都没拦
#   （"记录 ≠ 实际"的对外版本）。⇒ 两处共用这一句，不许各写一份。
SHIELD_STATE_ON = "开着（未裁决落点默认只报不拦；要拦须 decide deny）"


def cmd_host_shield(args):
    import host_shield as hs
    st = hs.load_state()
    if args.sub == "status":
        # 0.29.0 (H-1)：原文案写"宿主外传路径**默认拒绝**"——这句话在 H-1 之后已经不成立
        # （未裁决 ⇒ 只报不拦），留着就是「记录 ≠ 实际」，会让人以为拦着其实没拦。
        print("护盾：", SHIELD_STATE_ON if st.get("enabled")
              else "关着（默认。开启：antinel host-shield enable）")
        # 0.28.1：哨兵存活性 + 心跳断档——"配置开着"不等于"哨兵在岗"，把两者分开说
        alive = hs.sentinel_alive(st)
        # ★ 0.35.3 修（真缺陷）：无参 `heartbeat_age()` 走**中枢 rollup**，
        #   而哨兵（包根带 .psl）写的是**包审计** ⇒ 把活哨兵报成"断档 693 分钟"。
        age, _last = hs.sentinel_heartbeat_age()
        if st.get("enabled"):
            if alive:
                print("  监理进程：在岗（pid %s，自 %s）"
                      % (st.get("sentinel_pid"), str(st.get("sentinel_started_at"))[:16]))
            else:
                print("  ⚠ 监理进程：不在岗——每次 Agent 活动会自动尝试复活（paramedic）；"
                      "手动：antinel host-shield enable")
            print("  最后心跳：%s" % ("%.0f 分钟前（应 ≤10 分钟）" % (age / 60.0)
                                      if age is not None else
                                      "无记录——监理还没成功写下记录，"
                                      "或者刚开始布防"))
            print("  自启方式：%s" % (st.get("autostart") or "<未登记（旧版布防）>"))
        for k, v in (st.get("workspaces") or {}).items():
            print("  %s → %s" % (k, v))
        for k, v in (st.get("windows") or {}).items():
            print("  [放行窗] %s 至 %s" % (k, datetime.fromtimestamp(v)))
        # 0.29.0 (H-4)：**列出当前真正锁着的目录**。这是用户此前完全没有的出口。
        _root = os.path.dirname(_sibling("antinel.py"))
        try:
            _locks = hs.list_locks(_root)
        except Exception as _e:
            _locks = []
            print("  ⚠ 已上锁目录列举失败：%s" % _e)
        if _locks:
            print("  ⚠ 当前 %d 个目录处于上锁状态。" % len(_locks))
            print("     解除：antinel host-shield unlock <路径>")
            for _l in _locks:
                print("     · %s  [gate=%s / 来源=%s]" % (_l.get("path"), _l.get("gate"),
                                                          _l.get("source")))
        # 0.29.0 (H-2)：待裁决队列的**呈现端**。此前只有记录端（审计链里躺着），
        # 用户从不看 ⇒ "报告必须要用户确认"这条要求落空一半。
        _pend = [r for r in hs.load_pending() if (r.get("status") or "unjudged") == "unjudged"]
        if _pend:
            print("  ⚠ %d 个落点待你裁决（host-shield queue 看全部）：" % len(_pend))
            for r in _pend[:5]:
                print("     · %s  [%s] %s" % (r.get("path"), r.get("gate"),
                                              (r.get("why") or "")[:48]))
            print("     裁决：antinel host-shield decide \"<路径>\" allow_always｜deny")
        return
    if args.sub == "locks":
        _root = os.path.dirname(_sibling("antinel.py"))
        _locks = hs.list_locks(_root)
        if not _locks:
            print("当前没有处于上锁状态的目录。")
            return
        print("当前上锁 %d 个目录：" % len(_locks))
        for _l in _locks:
            print("  %s\n     gate=%s 来源=%s\n     解锁：antinel host-shield unlock \"%s\""
                  % (_l.get("path"), _l.get("gate"), _l.get("source"), _l.get("path")))
        return
    if args.sub == "unlock":
        # 0.28.3（E1 自签字堵死）同一条纪律：解锁＝放行，必须人本人在终端跑。
        if not _is_tty():
            _die("unlock 是放行决定，必须在交互终端由你本人执行（防 Agent 自签字）")
        import host_shield as _hu
        _tgt = os.path.abspath(args.path)
        if not os.path.isdir(_tgt):
            _die("目录不存在：%s" % _tgt)
        _before = _hu.is_denied(_tgt)
        _hu.acl_allow(_tgt)                     # ★ 必须走 acl_allow（/reset），
        _after = _hu.is_denied(_tgt)            #   另写的 /remove:d 实测不解（见 host_shield 注释）
        _st = _hu.load_state()
        _st.setdefault("workspaces", {})[_tgt.lower()] = "allow_always"
        _hu.save_state(_st)
        _hu.record(None, "host_shield_changed", decision="allow", severity="warning",
                   field="workspace:" + _tgt, change="unlock", invoked_by=_invoked_by(),
                   reason="用户解锁：%s（解锁前 is_denied=%s，解锁后 %s）"
                          % (_tgt, _before, _after))
        print("✓ %s" % ("已解锁" if not _after else
                        "【解锁未生效】——ACL 未能恢复，仍为上锁状态，须人工排查：%s" % _tgt))
        return
    if args.sub == "queue":
        _pend = hs.load_pending()
        if not _pend:
            print("待裁决队列为空（门闸未发现需要你表态的落点）。")
            return
        print("待裁决 %d 个落点：" % len(_pend))
        for r in _pend:
            print("  %s\n     gate=%s 来源=%s 状态=%s\n     理由：%s\n     首见 %s / 末见 %s"
                  % (r.get("path"), r.get("gate"), r.get("source"),
                     r.get("status") or "unjudged", r.get("why"),
                     r.get("first_seen"), r.get("last_seen")))
        print("\n裁决：antinel host-shield decide \"<路径>\" allow_always｜deny"
              "（放行须本人在终端）")
        return
    if args.sub == "enable":
        st["enabled"] = True
        hs.save_state(st)
        # 0.31.0 (F4): 布防时登记钩子注册（settings 文件 + 哈希）——哨兵从此
        # 有基线可查："闸门被拔线"从无声变成 breach 子类⑤（见 host_shield.scan_once）。
        try:
            _reg_file = None
            try:
                _mf = json.load(open(os.path.join(os.getcwd(), ".psl", "manifest.json"),
                                     encoding="utf-8"))
                _reg_file = _mf.get("settings_file") or None
            except Exception:
                _reg_file = None
            if _reg_file and os.path.isfile(_reg_file):
                # ★★ 0.35.3 修（**真缺陷**，本机实测 2026-10-06）：
                #   旧版存的是**裸 hexdigest**，而哨兵比对用的是 `_file_sha256()`
                #   —— 那个返回 **`sha256:<hex>`**。两者**永不相等** ⇒ 哨兵每 5 分钟
                #   记一条 `hook_registration_changed`（"钩子注册文件被改"）
                #   ⇒ 一天 288 条 ＋ 每 30 分钟一次弹窗，**永远不停**；
                #   而文件其实一字未动（实测 mtime 停在 10-03）。
                #   ⇒ 修法＝**消灭副本**：写与比用**同一个函数**（`_file_sha256`）。
                #   ★ 为什么测试没抓到：`scripts/verification_tests.py` 的 U1-2
                #     自己造 state 时写的是 `'sha256:'+hexdigest()`（带前缀，对的），
                #     而产品 `enable` 写的是裸 hex —— **测试覆盖的是"我以为的写入"，
                #     不是"产品真的写出来的"**（与 0.35.2 那个 403 是同一形状）。
                st["hook_registration"] = {
                    "settings_file": _reg_file,
                    "sha256": hs._file_sha256(_reg_file)}
            else:
                st["hook_registration"] = {"settings_file": None, "sha256": None}
            hs.save_state(st)
        except Exception:
            pass
        # ★★ 0.60.0：自启**不再经 `.cmd`**（创始人 2026-10-27：「对于用户来说，
        #   任何类型的闪出黑窗都是不可接受的」）。
        #   机制：`.cmd` 只能由 cmd.exe 执行，而 cmd.exe 是**控制台子系统**程序；
        #   计划任务/启动文件夹的父进程都**没有控制台** ⇒ Windows 给 cmd.exe 新建
        #   一个控制台 ⇒ 用户看到黑窗闪一下。这与钩子用 python.exe 是**同一个根因**
        #   的另一个出口：**谁来执行它**决定了会不会闪。
        #   0.51.2 只堵了「启动文件夹」那条（改 .lnk）；`schtasks` 那条一直指着
        #   `~/.antinel/antinel-shield.cmd` ⇒ 每次登录闪一次，没人发现。
        #   ⇒ 一条 `.lnk`（pythonw.exe、无窗口）同时服务两条注册路径（**同源**），
        #     `.cmd` 降级为「PowerShell 完全不可用」时的最后兜底，并如实告知有窗。
        lnk = _neutral_lnk()
        os.makedirs(os.path.dirname(lnk), exist_ok=True)
        has_lnk = _create_startup_lnk(lnk)
        shim = None
        if not has_lnk:
            shim = os.path.join(os.path.expanduser("~"), ".antinel", "antinel-shield.cmd")
            # 0.28.1：编码必须容纳用户名里的非 ASCII 字符（本机 ~ = C:\Users\大马\...）。
            # 旧版 encoding="ascii" 在这台机器上必抛 UnicodeEncodeError——enable 在
            # save_state 之后、schtasks 之前死掉，留下 enabled=true 而什么都没做
            # （这正是 09-19 那次"开了护盾却没有 shim、没有哨兵"的死因之一）。
            # cmd 按 ANSI 代码页解析批处理（zh-CN = GBK/936），mbcs 恰好正确。
            with open(shim, "w", encoding="mbcs", newline="\r\n") as f:
                f.write('@echo off\r\n"%s" -I -S "%s" sentinel "%s"\r\n'
                        % (_pythonw_exe(), _sibling("host_shield.py"),
                           os.path.dirname(_sibling("antinel.py"))))
        target = lnk if has_lnk else shim
        # 0.28.1（死因 RC2）：schtasks /Create 的返回码必须查，失败要换道，不许假成功。
        # 0.28.3（B4i）：schtasks 走 System32 绝对路径（防应用目录/PATH 投毒）。
        # ★ 2026-09-26（A2）：**"返回码" ≠ "能启动"**。本机实测：schtasks.exe 被程序
        #   黑名单禁止启动时，subprocess.run 在 CreateProcess 阶段就抛 PermissionError，
        #   异常直接穿透到顶层 —— 而 `save_state(enabled=True)` 与写 shim 都在它**之前**，
        #   于是留下"状态说开着、实际没有哨兵、没有自启"（＝ 09-19 那个死因换了触发条件）。
        #   ⇒ 除了查 rc，还必须接住"根本起不来"。
        autostart = "schtasks"
        try:
            r1 = subprocess.run([hs._SCHTASKS, "/Create", "/TN", "AntinelHostShield",
                                 "/TR", '"%s"' % target, "/SC", "ONLOGON", "/F"],
                                capture_output=True, timeout=30,
                                creationflags=hs._CREATE_NO_WINDOW)
            _rc1 = r1.returncode
        except (OSError, subprocess.SubprocessError) as _e:
            _rc1 = -1
            print("  ⚠ 计划任务工具无法启动（%s）——改走启动文件夹" % type(_e).__name__)
        if _rc1 != 0:
            # ★ 0.51.2：回退位**优先 `.lnk`（无窗口）**，`.cmd` 只作 PowerShell
            #   不可用时的兜底 —— 见 `_create_startup_lnk` 的说明（创始人
            #   2026-10-17「重启时弹出的大黑窗口」）。
            # ★ 0.60.0：`.lnk` 已在上方**无条件先建好**（schtasks 也要用它），
            #   这里只需把它**复制**进启动文件夹；不再重复调用 PowerShell 建一遍。
            _copied = False
            if has_lnk:
                try:
                    shutil.copyfile(lnk, _startup_folder_lnk())
                    _copied = True
                except OSError:
                    _copied = False
            if _copied:
                autostart = "startup-lnk"
                _archive_legacy_startup()   # 旧 `.cmd` 归档（并存会多闪一次窗）
            elif shim:
                try:
                    shutil.copyfile(shim, _startup_folder_cmd())
                    autostart = "startup-folder"
                except OSError:
                    autostart = "none"
            else:
                autostart = "none"
        # 0.28.1（死因 RC3）：哨兵由 spawn_sentinel 拉起——脱离会话/作业对象，
        # 会话结束不再连带被杀；失败也如实上报（不再无条件宣布成功）。
        # 幂等：哨兵已在岗则不重复拉起（重复拉起会立刻被唯一性守卫退出，
        # 却把 state 的 pid 改写成这个短命进程，造成记账抖动）。
        # ★★ 2026-10-22（40 格 · 时间·挡）：**删掉这道捷径**。
        #   0.35.3 已把 `spawn_sentinel` 的幂等收紧成「进程活 **且** 心跳新鲜」
        #   （进程活但心跳断了 ⇒ 杀掉重拉）。而这里先判 `sentinel_alive(st)`
        #   就直接宣布成功 ⇒ 那条收紧**在这条路径上从来没生效过**：
        #   一个僵死的哨兵占着 pid，用户点「布防」得到的是"已在跑"。
        #   `spawn_sentinel` 本身就是幂等的（already-running），不必在外面先拦一遍。
        #   ★ 顺带修掉时钟坏时的 fail-open：模式可能是 `clock-skew`（算不出在不在岗），
        #     由 `spawn_sentinel` 统一给出，不再在这里被"进程在"覆盖成成功。
        ok, pid, mode = hs.spawn_sentinel(os.path.dirname(_sibling("antinel.py")))
        # ★ 0.52.0：桌面入口 —— 默认放（创始人 2026-10-17「用户下载安装之后，
        #   是否也默认在用户桌面放上呢，用户体验一定要照顾周全」）。与自启同形态
        #   （pythonw 无窗口＋品牌图标）；`--no-desktop` 可关；建不成就地如实说，
        #   不假装成功（补建：antinel host-shield desktop）。
        _desk = None
        if not getattr(args, "no_desktop", False):
            _desk = _create_desktop_lnk()
        st = hs.load_state()
        st["autostart"] = autostart
        hs.save_state(st)
        hs.record(None, "host_shield_changed", decision="allow", severity="warning",
                  field="enabled", change="false → true", armed=True,
                  autostart=autostart, spawn=("ok" if ok else "failed"),
                  invoked_by=_invoked_by(),
                  reason="宿主审计门闸已布防（自启=%s；监理=%s）"
                         % (autostart, ("pid %s %s" % (pid, _spawn_mode_text(mode, ok)))
                            if ok else _spawn_mode_text(mode, ok)))
        print("✓ 护盾已布防：%s" % SHIELD_STATE_ON)
        if autostart == "schtasks":
            print("  自启：计划任务 AntinelHostShield（登录触发）")
        elif autostart == "startup-lnk":
            print("  自启：启动文件夹快捷方式（无窗口，计划任务被本机策略拦截已回退）")
        elif autostart == "startup-folder":
            print("  自启：启动文件夹（计划任务命令被这台电脑上的策略拦截，已回退）")
        else:
            print("  ⚠ 自启未能注册（计划任务命令与启动文件夹都失败）。"
                  "保险起见：每次 Agent 活动时钩子会自动复活监理。")
        if getattr(args, "no_desktop", False):
            print("  桌面入口：未创建（--no-desktop；补建：antinel host-shield desktop）")
        elif _desk:
            print("  桌面入口：%s（双击开监理窗口，无黑窗）" % _desk)
        else:
            print("  ⚠ 桌面入口未能创建——补建：antinel host-shield desktop")
        if ok:
            print("  监理：%s（pid %s）" % (_spawn_mode_text(mode, ok), pid))
        elif mode == "clock-skew":
            print("  ⚠ 监理：%s" % _spawn_mode_text(mode, ok))
        else:
            print("  ⚠ 监理本次未能拉起——下次 Agent 活动时 paramedic 会自动重试；"
                  "antinel host-shield status 查看在岗状态")
        print("  代价：被拦工作区的 ZCode 检查点回滚不可用。撤销：antinel host-shield disable")
        return
    if args.sub == "disable":
        # ★★ 2026-09-29（D-18 修）：**先干活，最后宣告**。
        #
        # 原顺序（bug，实测）：`st["enabled"]=False` 写在**最前**，然后才去删自启项。
        #   本机实测：宿主 safe-delete 会在 `os.remove(启动文件夹 shim)` 处
        #   **硬杀进程**（`SAFE_DELETE_BULK_CONFIRM_REQUIRED` 是平台层杀的，
        #   Python 的 `except OSError` **接不住**）⇒ `disable` rc=1 当场中断。
        #   结果：state 已写 enabled=false，而自启 shim **还在启动文件夹里**
        #   ⇒ 下次登录仍会拉起哨兵，可 `status` 读 state 说"关着"
        #   ⇒ **机器状态与账本不一致，且没有任何安置**。
        #
        # 判据：**状态位是"结果"、不是"意图"**。清理会被外部杀掉，
        #   所以"宣告已撤防"必须排在清理**之后**：要么真撤干净了才写 false，
        #   要么半途被杀时 state 仍是 true（status 会如实说"开着"，并列出不在岗的哨兵）。
        # ★ 与 0.28.1 的原意图不矛盾：那条要的是"撤防不能一步都不走"，
        #   本条要的是"不能把没走完说成走完了" —— 两者靠"先干活后宣告"同时满足。
        # 0.28.1：撤防同时停掉在岗哨兵（旧版留着空转）——先查存活再清 pid
        _alive_pid = st.get("sentinel_pid") if hs.sentinel_alive(st) else None
        # 0.28.3（B4i）：schtasks/taskkill 绝对路径
        # ★ 2026-09-26（A2）：**撤防必须走完**。原代码裸调 schtasks，本机实测直接抛
        #   PermissionError ⇒ 后面"杀哨兵、还原 ACL、写留痕"三步**一步都没执行**，
        #   而 state 已经写了 enabled=false —— 机器上留下"已撤防"的假象。
        #   （审计链 2026-09-26T08:26:03 那条"disable 在写本条留痕之前中断"就是这次。）
        _auto_removed = True
        try:
            subprocess.run([hs._SCHTASKS, "/Delete", "/TN", "AntinelHostShield", "/F"],
                           capture_output=True, timeout=30,
                           creationflags=hs._CREATE_NO_WINDOW)
        except (OSError, subprocess.SubprocessError) as _e:
            _auto_removed = False
            print("  ⚠ 计划任务未能删除（%s）——继续撤防其余部分" % type(_e).__name__)
        try:
            os.remove(_startup_folder_cmd())
        except OSError as _e:
            # ★★ 2026-09-29（D-18 修）：**不许静默吞**。
            #
            # 原来这里是 `except OSError: pass` —— 而 `_auto_removed` 只反映 schtasks
            # 那一路。于是「schtasks 成功 + 启动文件夹删除失败」这一格会：
            #   · `_auto_removed` 仍为 True ⇒ 不打印任何警告；
            #   · 但启动文件夹里的 shim **还在** ⇒ 下次登录仍会拉起哨兵，
            #     而 `host-shield status` 读的正是这个自启位 ⇒ 用户看到"护盾：开着"。
            # 实测（隔离 HOME，schtasks 被 Program Blacklist 拦）：
            #   `disable` 之后 `status` 仍报「护盾：开着」。
            #
            # 判据：**自启位有两个来源（schtasks ／ 启动文件夹），
            #   "撤销成功"必须同时覆盖两者** —— 只报其中一个，就是把
            #   "同一事实两处副本"重新引进来（本仓反复踩过的那一类）。
            # ⇒ 删失败必须并入同一个标志，让上面那段统一报告。
            if os.path.exists(_startup_folder_cmd()):
                _auto_removed = False
                print("  ⚠ 启动文件夹自启项未能删除（%s）——下次登录可能仍会拉起监理"
                      % type(_e).__name__)
        # ★ 0.52.0：自启 `.lnk` 也要撤（**0.51.2 漏洞**：disable 只删 `.cmd`。
        #   0.51.2 起自启首选形态就是 `.lnk` ⇒ 撤防后启动文件夹里还躺着它 ⇒
        #   下次登录仍拉起哨兵，而 status 读 state 说"关着" —— 机器状态与账实
        #   不一致，与 D-18 修的是同一类病换了张脸）。零删除：改名归档。
        try:
            _lnk = _startup_folder_lnk()
            if os.path.exists(_lnk):
                os.replace(_lnk, _lnk + ".away-" + datetime.now().strftime("%Y%m%d%H%M%S"))
        except OSError as _e:
            if os.path.exists(_startup_folder_lnk()):
                _auto_removed = False
                print("  ⚠ 启动文件夹无窗口自启项未能撤除（%s）——下次登录可能仍会拉起监理"
                      % type(_e).__name__)
        # ★ 0.52.0：桌面入口**对称归档**（改名不删）—— pip uninstall 删不到包外
        #   文件，不处理的话卸载后桌面留个点开报错的死图标（"卸载不干净"差评最
        #   常见的来源）。完整卸载＝disable ＋ pip uninstall（文档里写清）。
        _desk_away = _archive_desktop_entry()
        if _alive_pid:
            try:
                subprocess.run([hs._TASKKILL, "/F", "/PID", str(_alive_pid)],
                               capture_output=True, timeout=30,
                               creationflags=hs._CREATE_NO_WINDOW)
            except (OSError, subprocess.SubprocessError) as _e:
                print("  ⚠ 监理进程未能结束（%s）——下次登录可能仍被拉起，请手工检查"
                      % type(_e).__name__)
        for reg in hs.load_watch_registry(os.path.dirname(_sibling("antinel.py"))):
            for w in reg.get("watch", []):
                base = hs.expand(w.get("path", ""))
                if not os.path.isdir(base):
                    continue
                for dirpath, dirnames, _f in os.walk(base):
                    for dn in dirnames:
                        if hs.is_denied(os.path.join(dirpath, dn)):
                            hs.acl_allow(os.path.join(dirpath, dn))
        hs.record(None, "host_shield_changed", decision="allow", severity="warning",
                  field="enabled", change="true → false", armed=False, invoked_by=_invoked_by(),
                  reason="宿主审计门闸已撤防（ACL 已还原%s）"
                         % ("" if _auto_removed else "；★ 自启项删除失败，下次登录可能仍被拉起"))
        # ★ 2026-09-29（D-18）：**状态位最后写** —— 前面每一步都可能被外部杀掉
        #   （宿主硬杀不抛 Python 异常，`except` 接不住）。写在最后才能保证：
        #   "state 说已撤防" ⇔ "真的撤完了"。半途被杀时 state 仍是 true ⇒ status 如实说"开着"。
        st["enabled"] = False
        st["sentinel_pid"] = None
        # ★ 0.40.0：**显式声明这是有链背书的撤防** —— 上面那条
        #   `record(None, "host_shield_changed", field="enabled", armed=False, …)`
        #   就是背书（写在哨兵链上）。`save_state` 的默认闸会**挡住无背书的撤防**，
        #   所以合法撤防必须在这里显式放行，否则 `disable` 会静默失效。
        hs.save_state(st, allow_disarm=True)
        print("✓ 护盾已撤防，ACL 已还原")
        if _desk_away:
            print("  桌面入口已归档：%s（要恢复改回来即可）" % _desk_away)
        if not _auto_removed:
            print("  ⚠ 但自启项未能删除——下次登录可能仍会拉起监理。请手工检查："
                  "计划任务 AntinelHostShield ／ %s" % _startup_folder_cmd())
        return
    if args.sub == "desktop":
        # ★ 0.52.0：桌面入口**补建/刷新**（当时 enable 带了 --no-desktop，后来
        #   改主意；或品牌图标/入口形态升级后要刷新）。幂等：重复建＝覆盖。
        _desk = _create_desktop_lnk()
        if _desk:
            print("✓ 桌面入口已就位：%s" % _desk)
            print("  双击打开 Antinel 监理窗口（pythonw 启动，无黑窗）")
            return
        _die("桌面入口未能创建——请确认桌面目录可写；手工建法见设计文档"
             "《Antinel·文案派生与无窗口自启 v1.0（2026-10-17）》")
    if args.sub == "decide":
        ws = os.path.abspath(args.workspace).lower()
        dec = args.decision
        if dec not in ("allow_once", "allow_always", "deny"):
            _die("决定取 allow_once|allow_always|deny")
        # 0.28.3（E1 自签字堵死）：放行类决定必须人本人在终端跑——Agent 非 TTY
        # 调用一律拒绝。deny 是收紧方向，不拦。
        if dec in ("allow_once", "allow_always") and not _is_tty():
            _die("allow_once/allow_always 是放行决定。"
                 "要你本人在交互终端里执行，防止 Agent 自签字。"
                 "deny 可以由 Agent 代跑。")
        import host_shield as hs2
        import time as _t
        resolved = None
        for reg in hs2.load_watch_registry(os.path.dirname(_sibling("antinel.py"))):
            for w in reg.get("watch", []):
                base = hs2.expand(w.get("path", ""))
                if not os.path.isdir(base):
                    continue
                for dirpath, dirnames, _f in os.walk(base):
                    for dn in dirnames:
                        full = os.path.join(dirpath, dn)
                        if ws in full.lower() or full.lower() in ws:
                            resolved = full
        # 0.29.0 (F-3)：**host-scan 登记的落点同样可被裁决**。
        # 此前只在 rules/hosts/*.json 的 watch 表里找 ⇒ host-scan 判 T2（本机实证、
        # 但没登记 watch）的落点**根本裁决不到** ⇒ 只能"只报不拦"。现在两边都能裁决。
        if not resolved:
            for fd in hs2.load_findings():
                fp = os.path.abspath(hs2.expand(fd.get("path", "")))
                if not fp or not os.path.isdir(fp):
                    continue
                if fp.lower() in ws or ws in fp.lower():
                    resolved = fp
                    break
        if not resolved:
            _die("未找到匹配的外传落盘点（antinel host-scan 查看你电脑上的落点）")
        st = hs2.load_state()
        st.setdefault("workspaces", {})[resolved.lower()] = (
            "allow_always" if dec == "allow_always" else "deny")
        if dec == "allow_once":
            st.setdefault("windows", {})[resolved.lower()] = _t.time() + 120
        hs2.save_state(st)
        hs2.record(None, "host_shield_changed", decision="allow" if dec.startswith("allow") else "deny",
                   severity="warning", field="workspace:" + resolved,
                   change=dec, invoked_by=_invoked_by(),
                   reason="用户决定：%s" % dec)
        print("✓ 已记录决定：%s → %s" % (resolved, dec))
        return


def _save_health_report(doc):
    """把这次体检的结论存到本机（`~/.antinel/health/audit-<时间>.json`）。

    ★ 为什么落盘（方案 v1.7 §28.4「桥一」）：网站上的体检**没有服务端** ——
      它给的是提示词，让用户在自己机器上跑**同一个包**。所以「装前体检过」这件事
      只能由本机留下证据；不落盘就必然在装完监理之后再催一次（创始人明确不接受）。
    ★ 边界：只写自家目录、只增不改、只含**路径与计数**、留最近 12 份。
      落盘实现放在 `host_shield`（那里是中枢目录的唯一真源）。
    ★ 目录不可写时**抛异常**，由调用方如实说「没存下来」——
      绝不把「没存下来」渲染成「存下来了」。
    """
    import host_shield as _hs
    return _hs.save_health_report(doc)


def cmd_host_audit(args):
    import host_shield as hs
    root = os.path.dirname(_sibling("antinel.py"))
    if not os.path.isdir(os.path.join(root, "rules", "hosts")):
        root = os.path.dirname(root)            # pkg 布局：从 hooks/ 上浮到包根
    regs = hs.load_watch_registry(root)
    if getattr(args, "host", None):
        regs = [r for r in regs if r.get("host") == args.host]
    if not regs:
        _die("登记表为空（rules/hosts/）")
    # 0.28.4：登记表已扩到本机全部 AI 工具（24 个），但**只有已取证的才布门闸**。
    # 本表只列【已布门闸】的宿主；其余在 `host-scan` 里分级列出 —— 避免"列了一堆
    # 却什么都没拦"的假安全感（那正是「查不出来 ≠ 查出来是好的」）。
    armed = [r for r in regs if r.get("watch")]
    if not armed:
        _die("登记表里没有任何【已布门闸】的宿主（watch 全为空）")
    # ★ 0.53.0（P6 第一步）：这次体检的结论**同时**收成一份机读档案 ——
    #   屏幕上的字是给人看的，存档是给「装完监理之后还认不认这次体检」用的。
    #   只收路径与计数，不收任何文件内容（键白名单见 0353 H9）。
    _rep = {"schema": "antinel.health/1",
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source": "host-audit",
            "hosts": [], "workspaces": []}
    for reg in armed:
        print("== 宿主:", reg.get("host"))
        for w in reg.get("watch", []):
            base = hs.expand(w.get("path", ""))
            print("  路径:", base, "存在" if os.path.isdir(base) else "不存在")
            if not os.path.isdir(base):
                _rep["hosts"].append({"host": reg.get("host"), "root": base,
                                      "present": False, "bytes": 0, "workspaces": 0})
                continue
            # 0.29.0：此处原有一行死代码（`sum(...) if False else None`），从不被使用，
            # 且会在每次调用时构造生成器 —— 已删。
            size = 0
            for dp, _dn, fs in os.walk(base):
                for x in fs:
                    try:
                        size += os.path.getsize(os.path.join(dp, x))
                    except OSError:
                        pass
            print("  体量: %.1f MB" % (size / 1048576))
            _ws_n = 0
            for ws in sorted(os.listdir(base)):
                wd = os.path.join(base, ws)
                if not os.path.isdir(wd):
                    continue
                accepted = pending_n = 0
                git_n = sens_n = entries = 0
                ws_path = ""
                for f2 in glob.glob(wd + r"\\*.json", recursive=True):
                    try:
                        s = io.open(f2, encoding="utf-8", errors="replace").read()
                    except Exception:
                        continue
                    if "lastAccepted" in s:
                        accepted += 1
                    if "workspacePath" in s:
                        # 0.28.4：原实现按固定偏移 `i+17` 切片，但 json.dump 写的是
                        # `"workspacePath": "..."`（冒号后带空格）⇒ 值其实从 i+18 起，
                        # 于是**一直解析成空串**，工作区路径恒显示 "?"（静默、无报错）。
                        # 改用正则，两种分隔写法都对。
                        m = re.search(r'"workspacePath"\s*:\s*"((?:[^"\\]|\\.)*)"', s)
                        if m:
                            try:      # 反转义：json 里是 "D:\\psl\\poc"
                                ws_path = json.loads('"%s"' % m.group(1))
                            except Exception:
                                ws_path = m.group(1)
                    try:
                        d = json.loads(s)
                    except Exception:
                        continue
                    items = d if isinstance(d, list) else d.get("files") or []
                    for it in items:
                        p = it if isinstance(it, str) else (it.get("path") or "")
                        if not p:
                            continue
                        entries += 1
                        if ".git" in p.lower():
                            git_n += 1
                        if p.lower().endswith((".pem", ".key", ".p12", ".pfx", ".asc", ".kdbx")):
                            sens_n += 1
                for f2 in glob.glob(wd + r"\\pending\*", recursive=True):
                    pending_n += 1
                line = "  工作区 %s: %s | 条目 %d | .git %d | 敏感 %d | pending %d" % (
                    ws[:12], (ws_path or "?")[:46], entries, git_n, sens_n, pending_n)
                if accepted:
                    line += " | ⚠ 已上传接受"
                print(line)
                if sens_n:
                    print("    ⚠ 敏感扩展命中——核对凭据轮换")
                # ★ 存档用：与屏幕上这一行**同一批数**（`entries` / `git_n` / `sens_n` /
                #   `pending_n` / `accepted`），不许另算一遍 —— 同一次体检两处数分叉
                #   正是本仓反复吃亏的形状（0353 H9 会当场判红）。
                _ws_n += 1
                _rep["workspaces"].append({
                    "host": reg.get("host"), "checkpoint": ws,
                    "path": ws_path or "", "entries": entries,
                    "git_entries": git_n, "sensitive_entries": sens_n,
                    "pending": pending_n, "accepted": bool(accepted)})
            _rep["hosts"].append({"host": reg.get("host"), "root": base,
                                  "present": True, "bytes": size,
                                  "workspaces": _ws_n})
    print("（覆盖声明：登记表共 %d 个宿主，其中【已布门闸】%d 个（即上表）。）"
          % (len(regs), len(armed)))
    print("  ⚠ 未被列出的工具 ≠ 安全：'本次取证未发现外传证据' 只说明【没查出来】，"
          "不代表【没有外传】。")
    # ★ 0.29.0.r1：这里原本写「本机所有 AI 工具」。「本机」是**开发团队视角**的词，
    #   用户读到的是"那台机器"，不是"我的电脑"（创始人点名过这个错位）。
    #   ⇒ 改产品，不改网页：网页贴的是**逐字真实输出**，为了过检查器去改贴出来的字，
    #     就等于重新制造 P0-2（页面 ≠ 产品）。
    print("  全量清单（你电脑上的所有 AI 工具 ＋ 分级 ＋ 证据）：antinel host-scan）")
    # ★ 0.34.0（E4）：给「没查到」配一个**能做的下一步**。
    #   改之前的实况：这条命令以"没查出来 ≠ 没有"收尾——**诚实，但把用户放在原地**。
    #   读到这里的人心里是"那我下一步该干什么"，而原文没回答。
    #   ⇒ 补两句，且**不给虚假承诺**（不暗示 host-scan 能查出外传）。
    #   ★ 措辞纪律：只说"能列清单"和"能埋蜜饵"，不承诺任何检测能力。
    print("")
    print("  你能接着做的两件事：")
    print("    1) 看清你机器上到底装了哪些 AI 工具、哪些还没被纳管：")
    print("         python -m antinel host-scan        # 只读，扫全盘约 1–2 分钟")
    print("    2) 想知道『有没有东西真的被带出去过』，用蜜饵换主动证据：")
    print("         python -m antinel canary plant     # 放一个标记文件，")
    print("         然后正常使用 AI 工具；标记出现在输出里就会被记下")
    print("    （两者都只读你的机器，不联网、不上传。）")
    # ★ 0.53.0（P6 第一步）：存档 —— 「网站体检过 ⇒ 装完监理不再催」的唯一本机证据。
    #   只多这一行（人读文本一字不动，方案 §28.7 写死）。
    try:
        _hp = _save_health_report(_rep)
        # ★ 2026-10-22：**「已存档」是一句关于世界的话，必须先回读**
        #   （与 BL-03 同一纪律：凡是要打印"已经落盘"，就去盘上看一眼）。
        #   怎么发现的：0353 的 P16 负控把保存函数打桩成"返回路径但不写盘"，
        #   旧代码照样打印"已存档：<路径>" —— 而那个路径根本不存在。
        #   一声 stat 就能拦住，成本可以忽略。
        if os.path.exists(_hp):
            print("这次体检已存档：%s" % _hp)
        else:
            print("这次体检没存下来（写盘没有发生）")
    except Exception:                                        # noqa: BLE001
        # 存不下来要**如实说**（不能沉默），但也不许把异常栈倒给用户。
        # 唯一一处这么宽的捕获，理由：它是本次体检的收尾动作，
        # 失败不该让已经打完的体检结论作废。
        print("这次体检没存下来（目录不可写）")


# ------------------------------------------------------------ host-scan ----
# 0.28.4（C3）：本机 AI 工具「外传落盘点」发现（只读）。
# 设计：《Antinel 全工具覆盖设计 v1.0》§4「证据驱动的三级判定」。
# ★ 为什么不靠目录名：本机实测（2026-09-25），纯目录名启发式命中 24 个"疑似外传暂存区"，
#   逐个人工取证后 23 个是误报（Crashpad/reports、*-updater/pending、Chrome 内置、
#   技能包名里含 upload/report…）—— 误报率约 85%。
#   所以本命令的判据是【工具自己写下的外传自认】，不是【目录叫什么】。

# ★ 2026-09-26：厂商词表搬到 `egress.py`（`VENDOR_KW`）作为**唯一真源**，这里改为导入。
#   理由（仓库自己的纪律「共用同一实现，禁重写判据」）：复制一份必然漂移 ——
#   本仓已为「两处同一判据」付过四次学费（放行判据≠留痕判据、allow_always 不解锁、
#   文档区间腐烂、ROUTES 落后于实现）；不共用就是第五次。
#   ★ 不给退路：`egress.py` 缺失会立刻 ImportError，不是静默降级 ——
#     「缺东西就让功能悄悄消失」正是我们要防的病。构建链有检查项保证它被打包。
from egress import VENDOR_KW as _SCAN_VENDOR_KW

# 排除表：命中即 T4，不进正文。★ 必须显式维护 —— 无排除表的启发式 ＝ 会误报的检查器。
# ★ 0.29.0（G-9）：**移除崩溃类条目**（原为 crashpad / \crash\ / /crash/ / crashinfo / sentry）。
#   移除理由不是"它们会误报"，而是它们**让表说谎**：把崩溃上报写进"已排除"，
#   读表的人会以为崩溃目录已经被处理过了 —— 而实际上 `.dmp`（整进程内存镜像）
#   在 0.28.4 里**任何地方都不出现**。现在崩溃类由 `_crash_dump_obs` +
#   `_RESIDUE_SUBDIRS` 的观察项接管，**有名字、有体积、有进程名**。
#   判据：把"没查"写成"已排除"，就是自我安慰。
_SCAN_EXCLUDE_PAT = (
    "-updater", "updater\\", "updater/",
    "node_modules", "\\.git\\", "/.git/",
    "user data", "wechat", "qqlive", "wemeet", "sogouime", "weixin",
)

# 「外传自认」证据：工具自己写下的、证明它把东西发出去过的字段/后缀。
_SCAN_EVIDENCE_KW = (
    "lastAccepted", "lastUploaded", "uploadedAt", "syncedAt", "pushedAt",
    "manifestHash", "encryptedSize", "lastCompressedSize",
)
_SCAN_EVIDENCE_SUFFIX = (".reported", ".sent", ".uploaded")

# 目录遍历优先级提示：名字里带这些词的先走（见 _scan_evidence 注释 2）。
_SCAN_HINT = ("pending", "upload", "outbox", "staging", "sync", "report",
              "telemetry", "queue", "checkpoint", "snapshot", "manifest",
              "residue", "spool", "batch")

_SCAN_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "Cache", "GPUCache", "Code Cache",
    "Crashpad", "DawnGraphiteCache", "DawnWebGPUCache", "CachedData",
    "CachedExtensionVSIXs", "CachedProfilesData", "CachedConfigurations",
    "IndexedDB", "Local Storage", "Session Storage", "blob_storage",
    "Service Worker", "Partitions", "File System", "Network", "binaries",
    "extensions", "builtin", "languagepacks", "resources", "app", "Apps",
    ".cache", "cache", "Cache_Data", "CodeCache", "Crash-Log", "Diagnostics",
    "image-cache", "image_cache", "node_compile_cache", "logs",
    "artifacts", "sessions", "transcript", "transcripts",
    "conversation-history", "shell-snapshots", "file-history",
}

# ---- G-6／G-8／G-9 观察项配置 ------------------------------------------------
# ★ 0.33.1（夜间补齐）：这三个常量此前**从未定义**，却已被 2100／2111／2123 引用，
#   于是 `antinel host-scan` 的整个"观察项家族"自 0.29.0 引入起一跑就崩，
#   且 `verification_tests.py` 里 0 覆盖 ⇒ 死了 5 个版本没人发现。
#
# ★★ 内容不是"挑"出来的，是**量**出来的（判据三条）：
#   1) 名字一律取**本机实测存在**的：`_night_20260928\probe_residue_measured.py`
#      遍历 56 个 AI 数据根（home／APPDATA／LOCALAPPDATA）后列出的真实子目录名。
#   2) 语义猜测已被实测**否决**：`Crash-Log`／`Diagnostics`／`transcript`／`transcripts`／
#      `conversation-history` 本机**全不存在**；而真实存在、确实在装数据却被漏掉的有一整类
#      —— `Local Storage`(10 个工具)／`Network`(10)／`blob_storage`(10)／
#      `Session Storage`(9)／`IndexedDB`(4)／`Service Worker`(3)／`File System`(1)。
#      ⇒ 照猜测填，INV-2 会变绿（"配对通过"）而 Chromium 那一整类无人盯 ——
#      那正是 INV-2 要防的"报告说通过、实际看不见"。**所以宁可先量再填。**
#   3) 标签措辞是唯一自由项。硬约束：**至少一条含"崩溃上报"** —— 2489 行用
#      `"崩溃上报" in lbl` 把崩溃目录筛给 G-10（`_crash_dump_obs`），改措辞会切断它。
_RESIDUE_SUBDIRS = (
    ("Crashpad",        "崩溃上报目录"),
    ("logs",            "日志目录"),
    ("sessions",        "会话历史"),
    ("shell-snapshots", "会话历史"),
    ("file-history",    "会话历史"),
    ("IndexedDB",       "站点数据（会话可能在此）"),
    ("Local Storage",   "站点数据（会话可能在此）"),
    ("Session Storage", "站点数据（会话可能在此）"),
    ("Service Worker",  "站点数据（会话可能在此）"),
    ("blob_storage",    "站点数据（会话可能在此）"),
    ("Network",         "网络缓存（响应体可能在此）"),
    ("File System",     "文件系统沙箱"),
)
# INV-2（tools/antinel_verify.py）要求：`_SCAN_SKIP_DIRS` 里每一条"数据类跳过"
# 都要有一个观察项当着。这张配对表就是它读取的对象。
_RESIDUE_GUARD_PAIRS = tuple((k, k) for k, _lbl in _RESIDUE_SUBDIRS)

# G-8：云盘同步根（写进去＝客户端自动上传）。
# ★ 只列**本机实测存在**的 OneDrive。两条写法都要留：`~/OneDrive` 与
#   `%USERPROFILE%/OneDrive` 展开成**同一个路径**是**故意的** —— 去重由 `_obs_dedupe`
#   负责（其注释记录了这个实测），不要为了"消重"删掉其中一条。
# ★ 未启用的通用候选（本机未证实，需要时再开，**别默认打开**）：
#   "~/Dropbox" · "~/iCloudDrive" · "~/Google Drive"
#   判据：目录名是**事实断言**，列错不会报错、只会"以为在盯其实盯不到"。
_SYNC_DIR_ROOTS = (
    "~/OneDrive", "%USERPROFILE%/OneDrive",
)

# G-6：索引／向量类目录。
# ★ **故意留空**（0.33.1 夜间）：本机 56 个 AI 数据根里，`index`／`indexes`／
#   `vector(s)`／`embeddings`／`vectorstore`／`vectordb`／`faiss`／`lancedb`／`chroma`
#   **0 命中** ⇒ 我们对"这类目录到底叫什么"**没有实证**。
# ★ 留空的代价是这段不产出；但**填错的代价更大**：会把"未配置"渲染成"0 处"，
#   即把"没查"写成"没发现"。所以留空 + 报告端显式打「本段未配置」（见 2529 行）。
_INDEX_SUBDIRS = ()

# G-11：输入法数据（词库＝用户打过什么字）。同样只列**本机实测存在**的
# （`_night_20260928\probe_ime_im.py`）。⚠ 已知脆弱点：部分客户端把版本号写进目录名
# （如钉钉的 `DingTalk_108`）⇒ 客户端升级后这类条目会静默失效，`_obs_dir` 返回 None、
# 报告端不显示。这是**已知债**，记录在交接件；彻底修法需要给 `_obs_dir` 加通配支持。
_IME_DIRS = (
    "%APPDATA%/SogouPy",                 # 搜狗拼音用户词库
    "%APPDATA%/Microsoft/InputMethod",   # 微软拼音
    "%APPDATA%/Tencent/SogouIme",        # 腾讯版搜狗输入法
    "%APPDATA%/Tencent/qimei",
)

# G-7：IM / 邮件本机库。只报存在与体积。同样以本机实测为准。
_IM_DIRS = (
    "%APPDATA%/Tencent/xwechat",     # 微信（新版数据根；本机实测 4528 个文件）
    "%APPDATA%/Tencent/WeChat",      # 微信（旧版路径）
    "%APPDATA%/Tencent/WeChatApp",
    "%LOCALAPPDATA%/DingTalk_108",   # 钉钉（⚠ 名字含版本号，见上）
    "%LOCALAPPDATA%/Feishu",         # 飞书
)



def _scan_roots():
    home = os.path.expanduser("~")
    return [("home", home),
            ("appdata", os.environ.get("APPDATA")
             or os.path.join(home, "AppData", "Roaming")),
            ("local", os.environ.get("LOCALAPPDATA")
             or os.path.join(home, "AppData", "Local"))]


def _reg_roots(regs):
    """24 张登记表的 `roots` → [(宿主, 登记原文, 本机绝对路径)]。

    ★ 0.29.0.r1（P0-3／P0-4 的根因）：`roots` 这张表此前**只被装载、从无消费点** ——
      全仓唯一碰它的地方是 `host_shield.load_watch_registry` 里 `d.get("roots") or []`，
      装进一个 dict 就没人再读。
      ⇒ 一张「登记了却没有任何消费点」的表不是登记表，是注释。
      ⇒ 后果实测：登记落点 43 个，其中 3 个（~/.claude.json、~/.vscode、%APPDATA%/Code）
        host-scan **永远扫不到，且输出里一字不提**（把「没查」渲染成「没发现」）。
      现在登记表是 host-scan 的**硬发现来源**：登记过的一定扫，扫不到的一定报出来。
    """
    out = []
    for host, r in (regs or {}).items():
        for rp in (r.get("roots") or []):
            out.append((host, rp, _obs_expand(rp)))
    return out


def _scan_excluded(p):
    s = p.lower()
    return next((x for x in _SCAN_EXCLUDE_PAT if x in s), None)


def _scan_is_ai(name):
    n = name.lower().lstrip(".")
    return next((k for k in _SCAN_VENDOR_KW if k in n), None)


def _scan_find_key(o, depth=0):
    """递归找 JSON 里含「外传自认」的**键名**（兼容保留：只回第一个键名）。

    ★ 判据是【键名】不是【文本出现】：zcode 的 `state.json` 里有键
      `lastAcceptedManifestHash`（＝工具自认已上传的清单哈希），这才是状态；
      而某个任务文件正文里提到 "lastAccepted" 只是**内容**，不算证据。
      （首版按文本搜，T2 因此误收了 `.workbuddy-ai/tasks/<uuid>/25.json`。）
    ★ 0.29.2 起，真取数一律走 `_scan_collect()`（它返回**完整证据链**）；本函数
      只保留给旧调用点，语义不变 —— 判据不许二次实现。
    """
    hits = _scan_collect(o)
    return hits[0]["key"] if hits else None


# ------------------------------------------------------------ 法庭级取证 ----
# ★★ 为什么要有这一层（创始人 2026-09-27 指令）：
#   「尽可能把细节参数都加上，所有用户可能关心的细节参数，都要，特别是可能作为法庭证据。」
#   改前的病：`_scan_find_key()` **一发现键名就 return**，把值、时间、上下文全丢了 ——
#   用户看到「上次打包后的体积」五个字，既不知道**什么时候**打的、打了**多大**、
#   **哪些目录**、**上传了没有**。而这些东西**本来就在文件里**（实测 zcode 的
#   `lastCompressedSize` 里就带着 workspaceSizeBytes / encryptedSizeBytes /
#   manifestHash / recordedAt 四项）。
#   ⇒ 取证的目标从「证明它写过这个词」升级为**「把这份记录完整取下来」**。

# ★★★ 0.29.2：上下文键从"宽词表"改为「**只在命中的父级链内**取」。
#
# 改前的病（本机实测踩到，2026-09-27）：原先的宽词表含 `url` / `path` / `host` /
# `hash` / `at` 这类**极常见的键名**，于是把一堆**与偷数据毫无关系**的文件全捞了进来：
#   · `known_marketplaces.json` 的 `marketplaces[0].source.url`（插件市场地址）
#   · `v2/config.json` 的 `provider.*.options.baseURL`（模型 API 地址）
#   · ★ `credentials.json` 的 `web-remote-control:external-relay:pass_hash`（**凭证！**）
#     —— 这条最严重：把用户的敏感字段当"证据"展示在结果页上，是**制造新的泄露**。
#
# ⇒ 收紧成两条硬规则：
#   ① 上下文**只在同一个父对象内**取（即：某个 dict 里出现了命中键，才把该 dict 的
#      兄弟键一并取走）。这样 `lastCompressedSize.recordedAt` 能取到，
#      而无关文件里的 `url` 永远取不到 —— 因为它们**没有**任何兄弟是命中键。
#   ② 再加一层**敏感键黑名单**（credential / token / key / secret / password /
#      pass_hash / cookie / auth）：**无论在哪，一律不取、不显示**。
#      ★ 宁可证据少一条，也不把用户的凭证搬上屏幕。
_SCAN_CONTEXT_KW = (
    "workspacepath", "workspacekey", "manifestpath", "manifesthash",
    "sizebytes", "files", "recordedat", "uploadedat", "acceptedat",
    "pushedat", "syncedat", "failurecount", "failcount", "retry",
    "attempt", "status", "state", "endpoint", "region",
)
# 敏感键黑名单：命中即**永不采集**（不是"采集后隐藏"——根本不读进来）。
_SCAN_SECRET_KW = (
    "credential", "token", "secret", "password", "pass_hash", "passhash",
    "private", "apikey", "api_key", "auth", "cookie", "session_key",
    "refresh", "bearer", "signature", "salt", "nonce",
)
# 明确是"体积/大小"的键（用于把数字翻译成人话）
_SIZE_HINT = ("size", "bytes")
# 明确是"时间"的键
_TIME_HINT = ("recordedat", "timestamp", "time", "uploadedat", "pushedat",
              "syncedat", "acceptedat", "at", "date")


def _as_epoch_ms(v):
    """把各种形状的时间值统一成 **epoch 毫秒**；认不出就返回 None（不许猜）。

    认三型（实测遇到的）：
      · 13 位整数 = epoch 毫秒（zcode `recordedAt` 实测 1788827124448）
      · 10 位整数 = epoch 秒
      · ISO 字符串 / 可被 fromisoformat 解析的字符串
    ★ 为什么必须"认不出就 None"：把非时间数字当时间是**伪造证据**，
      比不显示严重得多 —— 这是要能上法庭的东西。
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        n = int(v)
        if 10 ** 12 <= n < 10 ** 14:            # 2001-09 ~ 5138 年，毫秒
            return n
        if 10 ** 9 <= n < 10 ** 11:             # 秒
            return n * 1000
        return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:                                    # ISO 8601（含 +08:00 / Z）
            from datetime import datetime as _dt
            return int(_dt.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
        except Exception:
            return None
    return None


def _fmt_ts(ms):
    """epoch 毫秒 → 可读本地时间；同时给原始值（法庭要对原文）。"""
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _fmt_bytes(n):
    """字节 → 人话（老板看得懂）。"""
    try:
        n = float(n)
    except Exception:
        return None
    for unit, div in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= div:
            return "%.1f %s" % (n / div, unit)
    return "%d 字节" % int(n)


def _scan_collect(o, max_depth=6, max_items=200):
    """**完整取数**：把 JSON 里所有与「外传自认」有关的字段连值带上下文取下来。

    返回 list[dict]，每项 = 一条可引用的证据，字段：
      key      键名（原文）
      kpath    键路径（如 `lastCompressedSize.recordedAt`）—— 法庭要能定位
      value    原始值（字符串/数字；布尔与空值原样）
      kind     'mark'（命中自认键名）| 'context'（构成证据链的上下文键）
      is_size  值是否表示体积
      ts_ms    若是时间，统一成 epoch 毫秒；否则 None
      ts_text  可读时间
    ★ 判据：**只翻译，不判定**。这里不回答"是不是它在偷"，只负责"取全"。
    """
    out, seen = [], set()

    def _secret(kl):
        return any(s in kl for s in _SCAN_SECRET_KW)

    def _take(ks, v, kp, kind):
        sig = (kp, repr(v)[:80])
        if sig in seen:
            return
        seen.add(sig)
        ts = _as_epoch_ms(v)
        kl = ks.lower()
        out.append({
            "key": ks, "kpath": kp, "value": v, "kind": kind,
            "is_size": any(h in kl for h in _SIZE_HINT) and ts is None,
            "ts_ms": ts, "ts_text": _fmt_ts(ts),
        })

    def walk(node, path, depth):
        if depth > max_depth or len(out) >= max_items:
            return
        if isinstance(node, dict):
            # ① 先在本层找出所有"命中键"（只有一个 dict 里真出现了自认键，
            #    才把它的兄弟键当上下文取走 —— 见 _SCAN_CONTEXT_KW 的注释①）
            marks = [str(k) for k in node
                     if any(kw.lower() in str(k).lower() for kw in _SCAN_EVIDENCE_KW)]
            for k, v in node.items():
                ks = str(k)
                kl = ks.lower()
                kp = ("%s.%s" % (path, ks)) if path else ks
                if _secret(kl):
                    walk(v, kp, depth + 1)      # ★ 敏感键：不取，但继续往下走（子树里可能有正常证据）
                    continue
                is_mark = ks in marks
                is_ctx = bool(marks) and any(kw in kl for kw in _SCAN_CONTEXT_KW)
                if (is_mark or is_ctx) and not isinstance(v, (dict, list)):
                    _take(ks, v, kp, "mark" if is_mark else "context")
                walk(v, kp, depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node[:50]):
                walk(v, "%s[%d]" % (path, i), depth + 1)

    walk(o, "", 0)
    # 命中键名（mark）排前面 —— 用户最该先看到的是"自认"本身。
    out.sort(key=lambda r: (0 if r["kind"] == "mark" else 1))
    return out


def _scan_file_hit(p):
    """单个文件的「外传自认」判据 —— **目录遍历与文件型落点共用这一份**。

    ★ 0.29.0.r1（P0-4）：登记表里有**文件型落点**（实测 `~/.claude.json` 就是个文件，
      不是目录）。之前 `_scan_evidence` 只吃目录（内部 os.walk + `isdir` 挡掉文件），
      于是这类落点**从来没被扫过，而输出不提这件事** —— 把「没查」渲染成了「没发现」。
    ★ 判据不许二次实现（本仓纪律，已为「两处同一判据」付过四次学费）：
      抽成一份共用；否则「扫目录」与「扫单文件」迟早得出两种结论。
    """
    low = os.path.basename(p).lower()
    if low.endswith(_SCAN_EVIDENCE_SUFFIX):
        return "文件名后缀 %s" % os.path.splitext(low)[1]
    if not low.endswith(".json"):
        return None
    try:
        if os.path.getsize(p) > 16384:
            return None
        d = json.load(io.open(p, encoding="utf-8", errors="replace"))
    except Exception:
        return None
    k = _scan_find_key(d)
    return ("键名 " + k) if k else None


def _scan_file_evidence(p):
    """单文件 → **完整证据包**（0.29.2 新增）。

    返回 dict（未命中返回 None）：
      {file, size, mtime_ms, mtime_text, hit, items:[...]}
      · file/size/mtime —— 证据所在文件本身的属性（法庭要"证据出自哪个文件、
        多大、什么时候最后改的"）
      · items —— `_scan_collect()` 取下的字段清单（键名/键路径/值/时间）

    ★ 为什么另开一个函数而不改 `_scan_file_hit`：后者的返回值是**既有契约**
      （`"键名 X"` 这种字符串，被 T 分级、`classify()`、`_ev_human()` 一路消费）。
      动它会波及判定链路 —— 而判据不许二次实现、也不许被顺手改语义。
      ⇒ 取证升级走**新增通道**，原判定一字不动（见 `cmd_host_scan` 里两路并用）。
    """
    hit = _scan_file_hit(p)
    if not hit:
        return None
    items = []
    if p.lower().endswith(".json"):
        try:
            d = json.load(io.open(p, encoding="utf-8", errors="replace"))
            items = _scan_collect(d)
        except Exception:
            items = []
    try:
        st = os.stat(p)
        mtime_ms, size = int(st.st_mtime * 1000), st.st_size
    except OSError:
        mtime_ms, size = None, 0
    return {"file": p, "size": size, "mtime_ms": mtime_ms,
            "mtime_text": _fmt_ts(mtime_ms), "hit": hit, "items": items}


def _scan_evidence(root, max_files=2000, max_depth=3, with_detail=False):
    """在数据根内搜「工具自己写下的外传自认」。只读；限深限大，防拖死。

    ★ 三条降噪判据（本机实测踩出来的，2026-09-25）：
      1) 字段类证据必须落在【JSON 键名】上，不是文本出现（见 _scan_find_key）。
      2) 只认【小文件】(≤16KB)。状态文件都很小（zcode 的 state.json 仅 563 B），
         而会话产物／日志动辄几十 KB —— 首版没加这条，T1 的证据全指向
         `.zcode/cli/artifacts/sess_*/call_*.json`（假证据）。
      3) 目录遍历按「疑似落盘点名」优先 —— 否则 `.workbuddy-ai`（18 万文件）这类根
         会在预算耗尽前根本走不到顶层的 `pending-telemetry`（首版 T2 因此漏报为 0）。

    ★ 0.29.0.r1：`root` 也可以是一个**文件**（见 `_scan_file_hit` 的注释）。
    """
    ev, n, trunc, det = [], 0, False, []
    if os.path.isfile(root):
        _h = _scan_file_hit(root)
        if not _h:
            return ([], False, []) if with_detail else ([], False)
        if with_detail:
            _d = _scan_file_evidence(root)
            return [(root, _h)], False, ([_d] if _d else [])
        return ([(root, _h)], False)
    base_n = root.rstrip(os.sep).count(os.sep)
    for dp, dn, fs in os.walk(root):
        dn[:] = [d for d in dn if d not in _SCAN_SKIP_DIRS]
        dn.sort(key=lambda d: (0 if any(h in d.lower() for h in _SCAN_HINT) else 1,
                               d.lower()))
        if dp.count(os.sep) - base_n >= max_depth:
            dn[:] = []
        for f in fs:
            n += 1
            if n > max_files:
                return (ev, True, det) if with_detail else (ev, True)
            _fp = os.path.join(dp, f)
            hit = _scan_file_hit(_fp)
            if hit:
                ev.append((_fp, hit))
                if with_detail:
                    _d = _scan_file_evidence(_fp)
                    if _d:
                        det.append(_d)
    return (ev, trunc, det) if with_detail else (ev, trunc)


def _scan_size(p, cap=3000, deep=False):
    """0.33.1：撞上限后继续只数不读——n 变成真实总数，不再留截断断言。
    deep=True 时 cap 放大到 500K。返回 (体积, 总数, 是否截断)；
    体积 = 前 min(总数, cap) 个文件的大小之和；截断 = 总数 > cap。"""
    if deep:
        cap = 500000
    if os.path.isfile(p):
        try:
            return os.path.getsize(p), 1, False
        except OSError:
            return 0, 0, False
    tot = n = 0
    for dp, dn, fs in os.walk(p):
        dn[:] = [d for d in dn if d not in _SCAN_SKIP_DIRS]
        for x in fs:
            n += 1
            if n <= cap:
                try:
                    tot += os.path.getsize(os.path.join(dp, x))
                except OSError:
                    pass
    return tot, n, n > cap


def _obs_expand(p):
    return os.path.expandvars(os.path.expanduser(p.replace("/", os.sep)))


def _obs_dedupe(rows):
    """观察项去重（按 realpath 小写）。

    ★ 实测踩出来的：`_SYNC_DIR_ROOTS` 里 `~/OneDrive` 与 `%USERPROFILE%/OneDrive`
      展开成**同一个路径** ⇒ 报告里出现两行一模一样的 OneDrive。
      「报告了却重复报」和「报告了却指不到实体」一样，都是假报告。
    """
    out, seen = [], set()
    for r in rows:
        k = os.path.realpath(r[0]).lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _obs_dir(p, cap=2000):
    """观察项：目录存在则返回 (路径, 条目数, 总字节, 是否截断)；不存在返回 None。

    ★ 只调用 os.walk / os.path.getsize —— **不 open 任何文件**。
    """
    q = _obs_expand(p)
    if not os.path.isdir(q):
        return None
    n = tot = 0
    try:
        for dp, dn, fs in os.walk(q):
            dn[:] = [d for d in dn if d not in _SCAN_SKIP_DIRS]
            for x in fs:
                try:
                    tot += os.path.getsize(os.path.join(dp, x))
                except OSError:
                    pass
                n += 1
                if n > cap:
                    return (q, n, tot, True)
    except OSError:
        pass
    return (q, n, tot, False)


def _crash_dump_obs(dirs=()):
    """G-10：崩溃转储元数据。

    ★ 为什么单列：`.dmp` 是**整进程内存镜像**。崩溃的若是 Electron 系 AI 工具
      （Cursor/Code/豆包/Kimi…），镜像里就带着当时的工作区内容、token、密钥。
      本机实测 `%LOCALAPPDATA%\\CrashDumps` 有 10 个 .dmp、5.0–7.9 MB。
    ★ 只读【目录项 / 文件名 / 大小】，**绝不读 .dmp 内容**。
    ★ `dirs` 由 `_residue_obs` 找到的"崩溃上报目录"传入 —— 于是"崩溃目录"
      与"里面有几个内存镜像"是同一份事实的两个视角，不会各说各话。
    """
    cands = ["%LOCALAPPDATA%/CrashDumps"] + list(dirs or ())
    out = []
    seen = set()
    for d in cands:
        q = _obs_expand(d)
        if not os.path.isdir(q) or q.lower() in seen:
            continue
        seen.add(q.lower())
        n = tot = 0
        procs = []
        try:
            for x in sorted(os.listdir(q)):
                fp = os.path.join(q, x)
                if not os.path.isfile(fp) or not x.lower().endswith(".dmp"):
                    continue
                n += 1
                try:
                    tot += os.path.getsize(fp)
                except OSError:
                    pass
                pn = x.split(".")[0]
                if pn and pn not in procs:
                    procs.append(pn)
        except OSError:
            continue
        if n:
            out.append((q, n, tot, procs[:6]))
    return out


def _share_target_obs():
    """G-12：Windows「分享」面板注册的分享目标。

    ★ 这是一条**影子通道**：用户点一下分享，内容就出去了 ——
      **全程不经 Agent 工具**，钩子层原理上看不见。
      本机实测已注册 `KimiShareTarget_m564vt17ty7ce`（09-22）。
    """
    q = _obs_expand("%LOCALAPPDATA%/Packages")
    out = []
    if os.path.isdir(q):
        try:
            for x in sorted(os.listdir(q)):
                lx = x.lower()
                if "sharetarget" in lx or "share_target" in lx or "sharetargetapp" in lx:
                    out.append(x)
        except OSError:
            pass
    return out


def _cross_device_obs():
    """G-12：Windows 跨设备平台（就近共享 / 跨设备剪贴板 / Phone Link 的底座）。"""
    return _obs_dir("%LOCALAPPDATA%/ConnectedDevicesPlatform", cap=500)


def _print_spool_obs():
    """G-13：打印后台（在途文档全文）。空 = 正常。"""
    sysroot = os.environ.get("SystemRoot") or "C:\\Windows"
    return _obs_dir(os.path.join(sysroot, "System32", "spool", "PRINTERS"), cap=500)


def _ime_obs():
    """G-11：输入法数据。"""
    out = []
    for d in _IME_DIRS:
        r = _obs_dir(d, cap=800)
        if r:
            out.append(r)
    return _obs_dedupe(out)


def _im_obs():
    """G-7：IM / 邮件本机库。★ 只报存在与体积。"""
    out = []
    for d in _IM_DIRS:
        r = _obs_dir(d, cap=1500)
        if r:
            out.append(r)
    return _obs_dedupe(out)


def _sync_dir_obs():
    """G-8 取证：本机存在哪些云盘同步目录（写进去 = 会被客户端自动上传）。"""
    out = []
    for d in _SYNC_DIR_ROOTS:
        r = _obs_dir(d, cap=300)
        if r:
            out.append(r)
    return _obs_dedupe(out)


def _index_obs(roots):
    """G-6：AI 数据根下的索引 / 向量类目录（先取证，不预设它一定外传）。

    ★ 0.33.1：`_INDEX_SUBDIRS` 目前**故意为空**（本机 0 实证）⇒ 返回 `None`，
      与"查过、为空"（返回 `[]`）严格区分。报告端据此打「本段未配置」而不是「0 处」。
      判据：把"没查"渲染成"没发现"，正是这条观察项要防的病。
    """
    if not _INDEX_SUBDIRS:
        return None
    out = []
    for root in roots:
        for sub in _INDEX_SUBDIRS:
            r = _obs_dir(os.path.join(root, sub), cap=800)
            if r:
                out.append(r)
    return _obs_dedupe(out)


def _residue_obs(roots):
    """G-9：被跳过的"偷数据相关"类目录 —— 现在看得到（只看元数据）。"""
    out = []
    seen = set()
    for root in roots:
        for sub, label in _RESIDUE_SUBDIRS:
            r = _obs_dir(os.path.join(root, *sub.split("/")), cap=1500)
            if not r or r[0].lower() in seen:
                continue
            seen.add(r[0].lower())
            out.append((r[0], label, r[1], r[2], r[3]))
    return out


def cmd_egress(args):
    """外传账本：记录并呈现「谁在往哪发」，只标"值得看"，不下结论。"""
    import egress as eg
    print(eg.run(
        all_proc=bool(getattr(args, 'all', False)),
        do_resolve=not bool(getattr(args, 'no_resolve', False)),
        as_json=bool(getattr(args, 'json', False)),
        days=(getattr(args, 'days', None) or eg.LEDGER_DAYS)))


def cmd_ui(args):
    """本地体检页：在你**自己电脑的浏览器**里点一下，就把这台电脑查一遍（只读）。

    ★ 为什么必须做成本地网页：静态站跑在别人的服务器上，浏览器沙箱不让它读你的硬盘。
      一个网页如果点一下就报"你的电脑很干净"、而你本机没运行任何程序 —— 那它在撒谎，
      而**把「没查」渲染成「清白」**正是本项目最反对的事（比不做还危险）。
      ⇒ 网站只负责说服与给入口；真正去查的是你电脑上的这个程序；结果页开在本机浏览器里。
    ★ 判据与译文**一律从本文件传进去**（VERDICTS ／ _ev_human），展示层不许自己再翻一遍。
    ★ 只读：跑的是 `host-scan --json`，**不带 --arm ／ --survey** ⇒ 不登记、不布防、不上锁。
    """
    import ui_server
    return ui_server.serve(
        verdicts=VERDICTS, ev_human=_ev_human, antinel_dir=_HERE,
        port=int(getattr(args, "port", 0) or ui_server.DEFAULT_PORT),
        open_browser=not bool(getattr(args, "no_open", False)))



# ------------------------------------------- 0.29.0.r1 六档语义（对外分档）--------
# ★ 为什么产品里要放这一层：`host-scan` 此前只吐 T1/T2/T3/T4 内部编号 ＋ 英文键名
#   （`lastCompressedSize`）—— 用户拿到三样看不懂的东西，没有一个回答"所以呢？"
#   （创始人原话：「至少我看现在的 结果文件看不懂」）。分档＝把取证输出翻译成人话。
# ★ 唯一实现：判据与译文的真源在本文件；`ux_verdict.py` 等展示层一律 import 这里的
#   `classify` / `EVIDENCE_MEANING` / `VERDICTS`，**不许自己再翻一遍**（本仓纪律：
#   判据不许二次实现，否则两份实现迟早对不上）。
# ★ 措辞纪律：**一个字都不许多说**。监理的能力是「读工具自己写下的字段」，
#   所以每档都带「自认」二字 —— 写成「监理抓到它在发」就是宣称未实现的东西。
# ★ 主语纪律（创始人 2026-10-19）：用户可见文案里**不许出现「我们」** ——
#   读者是被监理的那一方，「我们」让他不知道这句话是谁说的（开发方？工具？）。
#   一律以「监理」作主语：**谁查的、谁没查到、谁的能力到哪儿**，都写「监理」。

# 证据语义表：键名/后缀 → (档位, 人话)。★ 这是**翻译**不是判定：键名字面就是它的语义。
EVIDENCE_MEANING = {
    "lastCompressedSize": ("PACK", "上次打包后的体积"),
    "encryptedSize": ("PACK", "加密后的体积"),
    "manifestHash": ("PACK", "打包清单的哈希"),
    "lastAccepted": ("SENT", "上次被服务端接受"),
    "lastUploaded": ("SENT", "上次上传"),
    "uploadedAt": ("SENT", "上传时间"),
    "pushedAt": ("SENT", "推送时间"),
    "syncedAt": ("SYNC", "上次同步时间"),
    ".reported": ("SENT", "标记为已上报"),
    ".sent": ("SENT", "标记为已发送"),
    ".uploaded": ("SENT", "标记为已上传"),
}

# 六档。★ 用户要三档（偷了/没有/有嫌疑），我们给六档 —— 因为三档里有两条我们没资格下：
#   「偷了」＝我们只读到它自己写的字，没抓到发送动作；「没有」＝没发现 ≠ 没有。
#   ⚫ BLIND（没查到）单列：它是**盲区**不是结论，与 ⚪ 合并即把盲区伪装成清白。
VERDICTS = {
    "PACK":  {"key": "PACK",  "icon": "🔴", "title": "自认打包过", "order": 0,
              "short": "工具自己在文件里写下了「上次打包后的体积 / 清单哈希」"},
    "SENT":  {"key": "SENT",  "icon": "🟠", "title": "自认往外发过", "order": 1,
              "short": "工具自己写下了「已上传 / 已被服务端接受 / 已推送」这类字样"},
    "SYNC":  {"key": "SYNC",  "icon": "🟡", "title": "自认在同步", "order": 2,
              "short": "工具自己写下了「上次同步时间」；同步 ≠ 上传整份项目"},
    "CLEAN": {"key": "CLEAN", "icon": "⚪", "title": "查过，没发现记录", "order": 3,
              "short": "扫过了，这次没找到它自己写下的外传记录 —— 不等于它没有"},
    "BLIND": {"key": "BLIND", "icon": "⚫", "title": "没查到（扫描器走不到）", "order": 4,
              "short": "登记了、你电脑上也确实有，但扫描器没走到 —— 这一项监理没查"},
    "NA":    {"key": "NA",    "icon": "·",  "title": "不适用", "order": 5,
              "short": "更新包 / 非 AI 工具本体"},
}

# 同时命中多档时取最高档（PACK > SENT > SYNC），不重复计数。
_VERDICT_PRIORITY = ("PACK", "SENT", "SYNC")


def classify(ev, excl=None, tier=None):
    """证据列表 → 六档之一。

    ★ 必须**两边都小写**再比：证据键名是驼峰（`lastSyncedAt`），词表里写的是
      `syncedAt` —— 大小写敏感匹配会把 `autoclaw` 的 `lastSyncedAt`
      **漏判成"没发现"**（本机实测踩到）。
    """
    if excl or tier == "T4":
        return "NA"
    kinds = []
    for _fp, kw in (ev or []):
        low = str(kw).lower()
        for name, (kind, _human) in EVIDENCE_MEANING.items():
            if name.lower() in low:
                kinds.append(kind)
                break
    for k in _VERDICT_PRIORITY:
        if k in kinds:
            return k
    return "CLEAN"


def _ev_human(kw):
    """证据原文 → 人话译文；查不到就原样返回（不许编）。"""
    low = str(kw).lower()
    return next((h for n, (_k, h) in EVIDENCE_MEANING.items() if n.lower() in low), kw)


def cmd_host_scan(args):
    import host_shield as hs
    root = os.path.dirname(_sibling("antinel.py"))
    if not os.path.isdir(os.path.join(root, "rules", "hosts")):
        root = os.path.dirname(root)
    regs = {r.get("host"): r for r in hs.load_watch_registry(root)}
    t1_hosts = {h for h, r in regs.items() if r.get("watch")}
    # ★ 0.33.1（夜间修订）：`host-scan` 子命令本来就注册了 `--deep`（见 add_argument：
    #   "文件数放到 50 万、不截断（默认 3000）"），与 `_scan_size(p, cap=3000, deep=False)`
    #   的语义逐字对应 —— 但本函数从未把它取出来，于是 2268/2306 两处 `deep=deep`
    #   直接 NameError，整条命令从 0.29.0 起一跑就崩。
    #   取法用 getattr 兜底：别的调用方（如 ui_server）可能传不带 deep 的命名空间。
    deep = bool(getattr(args, "deep", False))

    # ★ 0.55.1（2026-10-23，企业首日实测）：本命令**扫完才一次性出结果**，
    #   而企业机器上这一趟要几分钟到十几分钟。实测一处问题：
    #     试用第一天按 host-audit 的提示跑 `antinel host-scan`，屏幕上十分钟
    #     一个字都不出 ⇒ 人判定「卡死」、IT 直接杀进程，然后写进评估报告。
    #   改法只加**进度**，不动任何判定与口径（报告仍在 stdout，进度走 stderr，
    #   脚本读 stdout 不受影响）。
    import time as _time
    _t_scan0 = _time.time()
    sys.stderr.write(
        "正在扫描：~ ／ %APPDATA% ／ %LOCALAPPDATA%（只读）。\n"
        "  这一趟可能要几分钟：每看一个落点报一行，全部看完才出报告。\n")
    sys.stderr.flush()

    rows, seen = [], set()
    for label, base in _scan_roots():
        if not base or not os.path.isdir(base):
            continue
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for name in names:
            p = os.path.join(base, name)
            if not os.path.isdir(p) or os.path.islink(p):
                continue
            kw = _scan_is_ai(name)
            if not kw:
                continue
            key = os.path.realpath(p).lower()
            if key in seen:
                continue
            seen.add(key)
            ex = _scan_excluded(p)
            if ex:
                rows.append({"name": name, "path": p, "kw": kw, "tier": "T4",
                             "excl": ex, "ev": [], "size": 0, "files": 0,
                             "trunc": False, "src": "目录名", "mt": ""})
                continue
            sys.stderr.write("  · 正在看 %-24s %s\n" % (name, label))
            sys.stderr.flush()
            size, nf, trunc_s = _scan_size(p, deep=deep)
            ev, trunc_e, detail = _scan_evidence(p, with_detail=True)
            tier = "T1" if (ev and name.lower().lstrip(".") in t1_hosts) else (
                "T2" if ev else "T3")
            rows.append({"name": name, "path": p, "kw": kw, "tier": tier,
                         "excl": None, "ev": ev, "size": size, "files": nf,
                         "trunc": trunc_s or trunc_e, "src": "目录名",
                         "detail": detail,
                         "mt": datetime.fromtimestamp(
                             os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")})

    # ---- 0.29.0.r1（P0-3／P0-4）：登记表 roots 作为**硬发现来源** ------------------
    # ★ 上面那一轮只按"第一层目录名命中厂商词"认工具 ⇒ 三重结构性盲区：
    #     ① 只列目录（`isdir` 挡掉文件型落点）② 目录名必须命中 48 个词
    #     ③ 只列第一层、不递归。
    #   实测后果：登记的 43 个落点里 3 个永远扫不到，而输出一字不提。
    #   ⇒ 这里把登记表补齐：**登记过的一定扫，扫不到的一定报出来**。
    _reg_total, _reg_present, _reg_absent, _reg_added = 0, 0, [], []
    _reg_present_keys = []
    for _host, _raw, _q in _reg_roots(regs):
        _reg_total += 1
        if not os.path.exists(_q):
            _reg_absent.append((_host, _raw))
            continue
        _reg_present += 1
        _key = os.path.realpath(_q).lower()
        _reg_present_keys.append((_host, _raw, _key))
        if _key in seen:          # 目录名那一轮已经扫到了 —— 登记与实况对齐，不重复
            continue
        seen.add(_key)
        _ex = _scan_excluded(_q)
        _name = os.path.basename(_q.rstrip(os.sep)) or _q
        if _ex:
            rows.append({"name": _name, "path": _q, "kw": _host, "tier": "T4",
                         "excl": _ex, "ev": [], "size": 0, "files": 0,
                         "trunc": False, "src": "登记", "mt": ""})
            _reg_added.append((_host, _raw))
            continue
        _size, _nf, _ts = _scan_size(_q, deep=deep)
        _ev, _te, _detail = _scan_evidence(_q, with_detail=True)
        _tier = "T1" if (_ev and _host in t1_hosts) else ("T2" if _ev else "T3")
        try:
            _mt = datetime.fromtimestamp(os.path.getmtime(_q)).strftime("%Y-%m-%d %H:%M")
        except OSError:
            _mt = ""
        rows.append({"name": _name, "path": _q, "kw": _host, "tier": _tier,
                     "excl": None, "ev": _ev, "size": _size, "files": _nf,
                     "trunc": _ts or _te, "src": "登记", "mt": _mt,
                     "detail": _detail})
        _reg_added.append((_host, _raw))

    order = {"T1": 0, "T2": 1, "T3": 2, "T4": 3}
    rows.sort(key=lambda r: (order[r["tier"]], r["name"].lower()))
    cnt = {"T1": 0, "T2": 0, "T3": 0, "T4": 0}
    for r in rows:
        cnt[r["tier"]] = cnt.get(r["tier"], 0) + 1

    # ---- 0.29.0 (F-1)：把"有证据"的落点登记进本机 findings，供门闸裁决 ----------
    # ★ 只登记 ev 非空的行（T1/T2）。T3（未取证）不登记 —— 没有证据却送进监管，
    #   就是把"没查出来"当成"查到了"，与把崩溃目录写进排除表是同一个病。
    _arm = bool(getattr(args, "arm", False))
    _ev_rows = [{"path": r["path"], "name": r["name"], "vendor": r["kw"],
                 "tier": r["tier"], "evidence": sorted({k for _fp, k in r["ev"]})[:6],
                 "size": r["size"],
                 "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds")}
                for r in rows if r["ev"]]
    if _arm:
        try:
            hs.save_findings(_ev_rows)
        except Exception as _e:
            print("（登记 findings 失败：%r —— 本轮发现不会进监管）" % (_e,))
    # ---- 0.29.0 (F-7)：取证档案 —— 让"没查过"和"查过没发现"不再同形 ----
    if _arm or getattr(args, "survey", False):
        _hosts = [{"vendor": r["kw"], "name": r["name"], "path": r["path"],
                   "tier": r["tier"],
                   "survey": ("T4" if r["tier"] == "T4" else
                              "measured" if r["ev"] else "clean"),
                   "evidence": sorted({k for _fp, k in r["ev"]})[:6],
                   "excluded_by": r.get("excl"), "size": r["size"]}
                  for r in rows]
        _doc = {"scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "machine_host": detect_host(), "roots": [b for _l, b in _scan_roots()],
                "counts": {"measured": sum(1 for h in _hosts if h["survey"] == "measured"),
                           "clean": sum(1 for h in _hosts if h["survey"] == "clean"),
                           "excluded": sum(1 for h in _hosts if h["survey"] == "T4")},
                "hosts": _hosts}
        try:
            hs.save_survey(_doc)
            print("取证档案：%s（已取证 %d ／ 扫过未发现 %d ／ 已排除 %d）"
                  % (hs.survey_path(), _doc["counts"]["measured"],
                     _doc["counts"]["clean"], _doc["counts"]["excluded"]))
        except Exception as _e:
            print("（写取证档案失败：%r）" % (_e,))
    _st = hs.load_state()
    _verdict = {k.lower(): v for k, v in (_st.get("workspaces") or {}).items()}
    _win = {k.lower(): v for k, v in (_st.get("windows") or {}).items()}

    print("== Antinel 体检：扫你电脑上的 AI 工具（只读）")
    sys.stderr.write("  · 扫描完成，用时 %.1f 秒，下面出报告。\n" % (_time.time() - _t_scan0))
    sys.stderr.flush()
    print("扫描根：~ ／ %APPDATA% ／ %LOCALAPPDATA%")
    print("生成时刻：%s" % datetime.now().astimezone().isoformat(timespec="seconds"))
    print("判据：工具自己写下的外传自认（不看目录名——目录名启发式误报率约 85%）")
    print()
    LAB = {"T1": "T1 已取证（已布门闸，deny）",
           "T2": "T2 你电脑上实测到（已进监管：未裁决＝拦）",
           "T3": "T3 未取证（未发现证据 ≠ 没有外传）",
           "T4": "T4 已排除（更新包／浏览器内置／非 AI）。崩溃类已移出本表，改由观察项接管。"}
    for t in ("T1", "T2", "T3", "T4"):
        rs = [r for r in rows if r["tier"] == t]
        if not rs:
            continue
        print("【%s】 %d 个" % (LAB[t], len(rs)))
        for r in rs:
            if t == "T4":
                continue
            print("  %-22s %s" % (r["name"], r["path"]))
            print("      体量 %.1f MB ／ %d 文件 ／ 最后改动 %s%s"
                  % (r["size"] / 1048576, r["files"], r["mt"],
                     "  (扫描截断)" if r["trunc"] else ""))
            print("      路径存在：%s" % os.path.isdir(r["path"]))
            for fp, kw in r["ev"][:3]:
                # 0.29.0.r1：英文键名（`lastCompressedSize`）不是人话 —— 并排给出译文。
                # ★ 译文来自 `EVIDENCE_MEANING`（唯一真源），这里只做**展示**，不重判。
                print("      证据：%s（原文 %s）  @  %s  [exists=%s]"
                      % (_ev_human(kw).replace("**", ""), kw, fp,
                          os.path.isfile(fp)))
            if not r["ev"]:
                print("      证据：（本次取证未发现）")
                continue
            # ★ 0.29.0 (F-1)：裁决状态 —— "未裁决"就是要拦，必须让人看见并给出出口
            _k = r["path"].lower()
            if _k in _verdict:
                _v = _verdict[_k]
                print("      裁决：%s" % ("已确认放行（不拦）" if _v == "allow_always"
                                       else "已裁决拦截"))
            elif _win.get(_k):
                print("      裁决：窗口放行 至 %s"
                      % datetime.fromtimestamp(_win[_k]).strftime("%H:%M:%S"))
            else:
                print("      裁决：未裁决")
                if _arm:
                    print("      ⇒ 已登记 findings，门闸将拦（不放行）")
                else:
                    print("      ⇒ 本次只读、未登记；加 --arm 才交门闸监管")
                print("      放行：antinel host-shield decide \"%s\" allow_always" % r["path"])
        if t == "T4":
            for r in rs:
                print("  %-22s ← 排除原因：%s" % (r["name"], r["excl"]))
        print()
    print("汇总：发现 %d 个 AI 工具数据根 ＝ T1 %d ＋ T2 %d ＋ T3 %d ＋ T4 %d"
          % (len(rows), cnt["T1"], cnt["T2"], cnt["T3"], cnt["T4"]))
    print()
    if cnt["T1"] + cnt["T2"]:
        print("★ 你电脑上有实证的地方 %d 个（T1 %d ＋ T2 %d）。本次为只读扫描，未登记、不会拦。"
              % (cnt["T1"] + cnt["T2"], cnt["T1"], cnt["T2"]))
        print("  要交给门闸（未裁决＝拦）：antinel host-scan --arm")
        print("  逐个确认放行：antinel host-shield decide \"<路径>\" allow_always")
    print()

    # ---- 0.29.0.r1（§5.4）：结果分六档 —— 把 T1/T2/T3/T4 与英文键名翻译成人能读的结论 ----
    _vc = {}
    for _r in rows:
        _r["verdict"] = classify(_r["ev"], _r.get("excl"), _r["tier"])
        _vc[_r["verdict"]] = _vc.get(_r["verdict"], 0) + 1
    print("── 结果分六档（人话版）──────────────────────────────")
    for _k in ("PACK", "SENT", "SYNC", "CLEAN", "NA", "BLIND"):
        _v = VERDICTS[_k]
        if _k == "BLIND":
            continue          # 盲区单独在下面「覆盖对账」里报，不混进结论档
        print("  %s %-14s %3d 个   %s"
              % (_v["icon"], _v["title"], _vc.get(_k, 0),
                 _v["short"].replace("**", "")))
    print()

    # ---- 0.29.0.r1（P0-4）：登记表覆盖对账 —— 漏了必须说出来 ------------------------
    print("── 登记表覆盖核对（漏了就说，不许静默）──────────────")
    # ★ 「已扫」不是照抄 `已加入 rows` 的次数 —— 那是恒等式，等于自欺。
    #   这里拿 rows 反查一遍：登记落点里，有几个**真的出现在本次结果里**。
    _scanned_keys = {os.path.realpath(_r["path"]).lower() for _r in rows}
    _reg_scanned = sum(1 for _h, _raw, _k in _reg_present_keys
                       if _k in _scanned_keys)
    _reg_unscanned = _reg_present - _reg_scanned
    print("  登记表 %d 张 ／ 登记的地方 %d 个" % (len(regs), _reg_total))
    # ★★ 这条不是"探测器"，是**回归守卫**：登记过的一定扫 ⇒ 修好后恒为 0。
    #   它存在的意义是：谁把登记表这条路径又拆了（roots 变回死数据、落点被过滤掉），
    #   这里立刻不再是无声的 0 —— 下面第一条就是让它**有对象可查**。
    if regs and _reg_total == 0:
        print("  ★★ 告警：登记表有 %d 张，却读出 0 个地方。" % len(regs))
        print("  roots 又变回【死数据】了（P0-3 复发）。")
        print("     查登记表加载函数是否仍在装载 roots。"
              "函数名：host_shield.load_watch_registry。")
    print("  你电脑上有 %d ／ 已扫 %d ／ ★ 未扫 %d"
          % (_reg_present, _reg_scanned, _reg_unscanned))
    if _reg_unscanned:
        print("  ★★ 没扫到的登记地方（这一项监理没查，请当空白读）：")
        for _h, _raw, _k in _reg_present_keys:
            if _k not in _scanned_keys:
                print("      ⚫ %-14s %s" % (_h, _raw))
    if _reg_added:
        print("  本次由【登记表】补齐（目录名认不出的）%d 个：" % len(_reg_added))
        for _h, _raw in _reg_added:
            print("      · %-14s %s" % (_h, _raw))
    if _reg_absent:
        print("  登记了但你电脑上没有的地方 %d 个（不是盲区，是没装）：" % len(_reg_absent))
        for _h, _raw in _reg_absent:
            print("      · %-14s %s" % (_h, _raw))
    print("  ⚠ 上面只覆盖【已登记的 %d 个工具】＋【目录名命中 %d 个厂商词的目录】；"
          % (len(regs), len(_SCAN_VENDOR_KW)))
    print("    这两者之外的地方，本命令没有看 —— 不是「看了没发现」。")
    # ★ 0.33.1（2026-09-28）：**布防数**。此前 `host-audit` 会打「登记表共 24 个宿主，
    #   其中【已布门闸】1 个」，而本命令没有 ⇒ 用户只看到「这条说 24、那条说 1」，
    #   拼不出全貌，于是"登记了 24 个"很容易被读成"24 个都被盯住"。
    #   这里给出同源数字；**完整的那句声明在末尾「⚠ 覆盖声明」块**（读者停在那里）。
    print("  ⚠ 登记 %d 个宿主，其中【已布门闸】%d 个；其余 %d 个没有门闸。"
          % (len(regs), len(t1_hosts), len(regs) - len(t1_hosts)))
    print()

    # ---- 0.29.0 观察项（G-6/G-7/G-9/G-10/G-11/G-12/G-13）---------------------
    # ★ 只报元数据（存在／条目数／体积／进程名），**不读内容、不判定是否外传**。
    #   判据：观察项陈述事实；把"有 10 个内存镜像"说成"被偷了"就是自我安慰的反面
    #   —— 那是吓人，同样是不可信的检查器。
    obs_roots = [r["path"] for r in rows]
    # ★ 0.55.1：观察项是**第二段慢活**（云盘同步／IM 库／索引／崩溃转储都是大目录），
    #   没有这一行的话，前面 50 多行进度走完之后又会静默几分钟。
    sys.stderr.write("  · 已看完 %d 个落点，正在看观察项（云盘同步／IM 库／索引／崩溃转储）…\n"
                     % len(rows))
    sys.stderr.flush()
    residue = _residue_obs(obs_roots)
    crash_dirs = [p for (p, lbl, _n, _t, _tr) in residue if "崩溃上报" in lbl]
    dumps = _crash_dump_obs(crash_dirs)
    crash_res = [r for r in residue if "崩溃上报" in r[1]]
    other_res = [r for r in residue if "崩溃上报" not in r[1]]
    ime = _ime_obs()
    im = _im_obs()
    sync = _sync_dir_obs()
    shares = _share_target_obs()
    cross = _cross_device_obs()
    spool = _print_spool_obs()
    index = _index_obs(obs_roots)

    def _m(b):
        return b / 1048576.0

    print("── 观察项（只报元数据，不读内容，不判定是否外传）────")
    if dumps:
        tot_n = sum(d[1] for d in dumps)
        tot_b = sum(d[2] for d in dumps)
        print("  [崩溃转储] %d 个 .dmp，共 %.1f MB" % (tot_n, _m(tot_b)))
        print("       ★ .dmp 是整进程内存镜像：崩溃当时的工作区内容/密钥/token 都在里面。")
        for (q, n, b, procs) in dumps:
            print("       %s" % q)
            print("           %d 个 ／ %.1f MB ／ 进程：%s" % (n, _m(b), ", ".join(procs)))
    else:
        print("  [崩溃转储] 0 个 .dmp")
    if crash_res:
        print("  [崩溃上报目录] %d 处（Crashpad 会自动把这里的内容传给厂商）" % len(crash_res))
        for (q, _lbl, n, b, tr) in crash_res[:8]:
            print("       %s  条目 %d ／ %.1f MB%s" % (q, n, _m(b), "（截断）" if tr else ""))
    else:
        print("  [崩溃上报目录] 0 处")
    if other_res:
        print("  [会话/历史/日志/诊断类] %d 处（旧版整类跳过、看不见；现在只报体量）"
              % len(other_res))
        for (q, lbl, n, b, tr) in other_res[:10]:
            print("       %-14s %s  条目 %d ／ %.1f MB%s"
                  % (lbl, q, n, _m(b), "（截断）" if tr else ""))
    else:
        print("  [会话/历史/日志/诊断类] 0 处")
    if index is None:
        print("  [索引/向量类] 本段未配置：_INDEX_SUBDIRS 为空（本机 0 实证）。"
              "这里没有查，不是「查过、0 处」。")
    elif index:
        print("  [索引/向量类] %d 处（先取证：不预设它一定外传）" % len(index))
        for (q, n, b, tr) in index[:8]:
            print("       %s  条目 %d ／ %.1f MB%s" % (q, n, _m(b), "（截断）" if tr else ""))
    else:
        print("  [索引/向量类] 0 处")
    if ime:
        print("  [输入法数据] %d 处（词库＝用户打过什么字）" % len(ime))
        for (q, n, b, tr) in ime[:6]:
            print("       %s  条目 %d ／ %.1f MB" % (q, n, _m(b)))
    else:
        print("  [输入法数据] 0 处")
    if im:
        print("  [IM/邮件的本地库] %d 处（全部往来记录；只报存在与体积）" % len(im))
        for (q, n, b, tr) in im[:8]:
            print("       %s  条目 %d ／ %.1f MB%s" % (q, n, _m(b), "（截断）" if tr else ""))
    else:
        print("  [IM/邮件的本地库] 0 处")
    if sync:
        print("  [云盘同步目录] %d 处 —— 写进去＝客户端自动上传（DST-11 已盯）" % len(sync))
        for (q, n, b, tr) in sync[:8]:
            print("       %s  条目 %d ／ %.1f MB" % (q, n, _m(b)))
    else:
        print("  [云盘同步目录] 0 处")
    if shares:
        print("  [系统分享目标] %d 个 —— 影子通道：点一下分享内容就出去。"
              % len(shares))
        print("  全程不经 Agent 工具，钩子看不见。")
        for s in shares[:8]:
            print("       %s" % s)
    else:
        print("  [系统分享目标] 0 个")
    if cross:
        print("  [跨设备平台] %s  条目 %d ／ %.1f MB（就近共享/跨设备剪贴板的底座）"
              % (cross[0], cross[1], _m(cross[2])))
    else:
        print("  [跨设备平台] 不存在")
    if spool:
        print("  [打印后台] 条目 %d ／ %.1f MB%s"
              % (spool[1], _m(spool[2]), "" if spool[1] else "（空 = 正常）"))
    else:
        print("  [打印后台] 不存在")
    print()

    print("⚠ 覆盖声明：")
    print("  · 本扫描为【本次取证】。未发现证据 ≠ 没有外传 —— 只代表这一遍没查出来。")
    print("  · 门闸只对 T1 生效（避免误报）。T2/T3 是否布防见《全工具覆盖设计 v1.0》§6 待拍板。")
    print("  · 门闸拦的是【文件落盘】这一步；工具若直接内存发包（不经落盘），只能记账、拦不住。")
    print("  · 观察项不读文件内容：它告诉你「这里有什么、有多大」，"
          "不替你下「这是外传」的结论。")
    print("  · 登记的地方 %d 个：已扫 %d ／ ★ 未扫 %d（见上方「登记表覆盖核对」）。"
          % (_reg_total, _reg_scanned, _reg_unscanned))
    # ★ 0.33.1（2026-09-28）：**布防数**放在读者真正会读到的地方（末尾这一块）。
    #   中部「登记表覆盖对账」段里另有一行同源数字，两处**故意重复** ——
    #   原因是读者会停在末尾这块看"声明"，中部那块是给逐项核对的人看的。
    #   本行措辞与 host-audit:1559 的覆盖声明**同族**（都用「登记表共 N 个宿主，
    #   其中【已布门闸】M 个」），这样用户在两页看到的是同一句话。
    print("  · 登记表共 %d 个宿主，其中【已布门闸】%d 个（即 T1）；"
          % (len(regs), len(t1_hosts)))
    print("    其余 %d 个没有门闸 —— 本命令能看到它们，但拦不住它们的落盘。"
          % (len(regs) - len(t1_hosts)))
    if getattr(args, "json", False):
        print()
        print(json.dumps({"generated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"), "tools": rows,
            # ★ 0.29.2：把 detail 单独抽出来，避免与既有的 `ev` 契约混淆。
            #   `ev` 仍是判定链路的输入（不可动）；`detail` 是给展示层的**完整证据包**。
            "details": {_r["path"]: (_r.get("detail") or []) for _r in rows},
            "coverage": {"registered_hosts": len(regs),
                         # ★ 0.33.1：把"登记了"与"真在盯"分开报。只报 registered_hosts
                         #   会让展示层把"24 个都登记了"渲染成"24 个都被守住了"。
                         "armed_hosts": len(t1_hosts),
                         "unarmed_hosts": len(regs) - len(t1_hosts),
                         "registered_roots": _reg_total,
                         "present": _reg_present, "scanned": _reg_scanned,
                         "unscanned": _reg_unscanned,
                         "added_by_registry": len(_reg_added),
                         "absent": len(_reg_absent)},
            "counts_by_verdict": _vc,
            "verdicts": VERDICTS,
            "observations": {
                "crash_dumps": [{"path": q, "count": n, "bytes": b, "processes": p}
                                for (q, n, b, p) in dumps],
                "crash_report_dirs": [{"path": q, "label": l, "entries": n, "bytes": b,
                                       "truncated": t} for (q, l, n, b, t) in crash_res],
                "residue_dirs": [{"path": q, "label": l, "entries": n, "bytes": b,
                                  "truncated": t} for (q, l, n, b, t) in other_res],
                # ★ 0.53.0 修复（2026-10-17）：`_index_obs()` 在 `_INDEX_SUBDIRS`
                #   为空时**故意**返回 None（区分「没配置、没查」与「查过、0 处」），
                #   人读分支判了 None，JSON 分支却直接拿去迭代 ⇒ 本命令 `--json`
                #   自 0.33.1 起一跑就崩（TypeError），`antinel ui` 体检页因此
                #   永远取不到数。这里必须渲染成 null，**绝不能写 `or []`** ——
                #   那正好把两种状态压成一种，是该观察项明令禁止的病。
                "index_dirs": ([{"path": q, "entries": n, "bytes": b}
                                for (q, n, b, _t) in index]
                               if index is not None else None),
                "ime_dirs": [{"path": q, "entries": n, "bytes": b} for (q, n, b, _t) in ime],
                "im_stores": [{"path": q, "entries": n, "bytes": b} for (q, n, b, _t) in im],
                "sync_dirs": [{"path": q, "entries": n, "bytes": b} for (q, n, b, _t) in sync],
                "share_targets": shares,
                "cross_device": ({"path": cross[0], "entries": cross[1], "bytes": cross[2]}
                                 if cross else None),
                "print_spool": ({"path": spool[0], "entries": spool[1], "bytes": spool[2]}
                                if spool else None)},
        }, ensure_ascii=False, indent=1))


# 0.29.0（D-5）：删掉 _host_python()。它原先用来给 host-shield 的 .cmd shim 选解释器，
# 但那个调用点早已改成 sys.executable（见 host-shield enable 段），此后全仓再无引用 —— 死代码。
# 它硬编码了作者机路径 r"C:/Users/大马/.workbuddy/.../3.13.12/python.exe"，把作者的 Windows
# 用户名与一个会过期的版本号带进了要发 PyPI 的包（PII ＋ 可移植性），且那条路径只对作者机成立。
# 留档（供将来真要"用宿主自己的解释器"时参考）：候选顺序是宿主 binaries 目录 → ~/.zcode → sys.executable。


# ─────────────────────────────────────────────────────────────────────────
# ★ 0.48.4 · Agent 零摩擦入口（install / skill / agent）
#
# 为什么必须做（2026-10-11 夜，wheel 安装态实测）：
#   装完 pip 包后，Agent 手里只有一个 `antinel` 命令。而它的 --help 是**给人看的**
#   60 行营销文案：既没有「装钩子」这一步，也没有机器可读出口，SKILL.md 又**不在
#   wheel 里**（实测 wheel 133 成员，SKILL.md 0 命中）⇒ Agent 装完不知道下一步。
#   「下载者多半是 Agent」这个前提一旦成立，这个缺口就是第一摩擦点。
#
#   判据：装完 pip 包后，Agent 只需 `antinel agent --json` 一条命令就能拿到
#   「我是什么环境 / 装没装 / 下一步敲什么 / 结果在哪」的全部答案。
# ─────────────────────────────────────────────────────────────────────────

def _skill_md_path():
    """随包 SKILL.md 的绝对路径。找不到返回 None（不抛）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    # 顺序说明：源码树里 antinel.py 与 SKILL.md 同级（第 1 条命中）；wheel 安装态
    # 下 SKILL.md 随 `psl/` 包走（顶层非 .py 文件没有可靠的随包机制，而 psl 的
    # package-data 已声明 `*.md`），故第 3 条覆盖 pip 装完的形态。
    for p in (os.path.join(here, "SKILL.md"),
              os.path.join(here, "agent", "SKILL.md"),
              os.path.join(here, "psl", "SKILL.md"),
              os.path.join(os.path.dirname(here), "SKILL.md")):
        if os.path.isfile(p):
            return p
    return None


def cmd_install(args):
    """`antinel install` —— 装钩子。等价于 python -m scripts.install。

    为什么要在 CLI 里再给一个入口：Agent 装完 pip 包后记得的只有 `antinel`
    这一个词。让它再猜出 `python -m scripts.install` 这一串，是纯摩擦。"""
    argv = []
    if getattr(args, "root", None):
        argv += ["--root", args.root]
    if getattr(args, "host", None):
        argv += ["--host", args.host]
    if getattr(args, "global_hooks", False):
        argv.append("--global")
    if getattr(args, "check", False):
        argv.append("--check")
    if getattr(args, "uninstall", False):
        argv.append("--uninstall")
    if getattr(args, "purge", False):
        argv.append("--purge")
    if getattr(args, "skip_scan", False):
        argv.append("--skip-scan")
    try:
        from scripts import install as _inst
        return _inst.main(argv)
    except Exception as _e:                      # 委派失败不许甩栈给人
        print("✗ antinel install 这一步失败了：%s: %s" % (type(_e).__name__, _e),
              file=sys.stderr)
        print("  等价命令（可自己跑）：python -m scripts.install " + " ".join(argv),
              file=sys.stderr)
        return 1


def cmd_skill(args):
    """`antinel skill` —— 把随包的操作手册交给 Agent。

    --path：只打路径（省 token，Agent 自己读文件）
    默认：打全文（Agent 在拿不到文件路径时也有一份）"""
    p = _skill_md_path()
    if not p:
        print("（本安装里没有随包 SKILL.md；源码仓根目录有 SKILL.md）")
        return 2
    if getattr(args, "path_only", False):
        print(p)
        return 0
    try:
        with open(p, encoding="utf-8") as f:
            sys.stdout.write(f.read())
        return 0
    except Exception as _e:
        print("✗ 读 SKILL.md 失败：%s: %s" % (type(_e).__name__, _e), file=sys.stderr)
        return 1


def _agent_state_json():
    """Agent 真正需要的那几件事：装没装、什么宿主、下一步敲什么。"""
    root = None
    try:
        root = find_project_root()
    except Exception:
        root = None
    if not root:
        root = os.getcwd()
    manifest_p = os.path.join(root, ".psl", "manifest.json")
    installed = os.path.isfile(manifest_p)
    m = {}
    if installed:
        try:
            with open(manifest_p, encoding="utf-8") as f:
                m = json.load(f)
        except Exception:
            m = {}
    try:
        host = detect_host()
    except Exception:
        host = "unknown"
    skill = _skill_md_path()
    steps = []
    if not installed:
        steps.append({"do": "antinel install",
                      "why": "把钩子装进当前项目，之后 Agent 的每个动作才进审计链"})
        steps.append({"do": "antinel agent --json",
                      "why": "装完再看一次，确认 installed=true"})
    else:
        steps.append({"do": "antinel brief", "why": "决策层一页纸：有没有外发、该做什么"})
        steps.append({"do": "antinel digest --days 1", "why": "近一天干了什么、拦了什么"})
        steps.append({"do": "python -m scripts.scan --json", "why": "静态扫描，机器可读"})
        steps.append({"do": "antinel verify", "why": "审计链有没有被动过"})
    return {
        "product": "Antinel",
        "pypi_package": "antinel",
        "install_command": "pip install antinel",
        "package_version": VERSION,
        "python": "%d.%d.%d" % sys.version_info[:3],
        "platform": sys.platform,
        "project_root": root,
        "installed": installed,
        # ★ 键名必须说清它是什么。manifest 里那一份是**钩子协议版本**（0.33.1，
        #   只在协议变化时 bump），与包版本（0.48.x）是两个不同的数。写成
        #   `manifest_version` 会让 Agent 看到两个数打架却无从判断哪个是
        #   "装了什么"—— 正是本次要消掉的那一类混淆。
        "hook_protocol_version": m.get("version") or m.get("skill_version"),
        "host_detected": host,
        "audit_dir": os.path.join(root, ".psl", "audit"),
        "skill_md": skill,
        "next_steps": steps,
        "exit_code_contract": {
            "antinel install --check": "0=一致 / 1=未安装 / 3=与登记不符",
            "python -m tools.antinel_verify": "0=current / 1=superseded / 2=无法校验",
            "python -m scripts.scan": "0=扫描完成（有发现也是 0；看 JSON 里的 findings）",
        },
        "notes": [
            "运行时不联网；只用标准库；无第三方依赖",
            "扫描只匹配工具调用文本与文件内容，不解析脚本语义；不是隔离层",
            "装/改配置后需重启宿主一次，钩子在宿主启动时加载",
        ],
    }


def cmd_agent(args):
    """antinel agent [--json] —— 机器可读的「我现在该干什么」。"""
    d = _agent_state_json()
    if getattr(args, "json", False):
        print(json.dumps(d, ensure_ascii=False, indent=1))
        return 0
    print("Antinel %s ｜ 宿主 %s ｜ 项目根 %s"
          % (d["package_version"], d["host_detected"], d["project_root"]))
    print("已装钩子：%s" % ("是" if d["installed"] else "否 —— 先跑 antinel install"))
    print("下一步：")
    for s in d["next_steps"]:
        print("  · %s  —— %s" % (s["do"], s["why"]))
    if d["skill_md"]:
        print("随包操作手册：%s（antinel skill 可直接打印）" % d["skill_md"])
    print("机器可读：antinel agent --json")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="antinel", add_help=False,
                                 description="Antinel 单入口（无参数=帮助清单）")
    # ★ 0.48.2（J2 用户旅程模拟实测）：补顶层 -h/--help 出口。
    #   此前顶层 add_help=False 且没有补出口 ⇒ 用户第一直觉命令
    #   `antinel -h` 与 `antinel --help` 双双报 "unrecognized arguments"，
    #   帮助只藏在 `antinel help` 子命令里（实测证据见 _uxtest2/ 的 M3 幕）。
    #   为什么不是直接 add_help=True：本工具「无参数即帮助清单」是既有契约，
    #   argparse 自动帮助会把子命令清单以另一种版式再印一遍 ⇒ 两个版本不一致。
    #   故显式补出口，复用同一个 cmd_help()（单一真源）。
    ap.add_argument("-h", "--help", action="store_true", dest="show_help",
                    help="显示帮助（等同 antinel help）")
    # 多宿主共存：目录探测会误报（装了谁就报谁）——Agent/用户可显式指定所在宿主
    ap.add_argument("--host", dest="force_host",
                    help="显式指定宿主。可选值："
                         "workbuddy|zcode|qoder|claude-code|generic。"
                         "多宿主共存时由 Agent 自报。")
    # ★ 0.34.0：补 --version。此前 VERSION 常量在 :37 却没有出口，
    #   包管理器／CI／用户无法查询已安装版本（实测 `antinel --version` 报
    #   "unrecognized arguments"）—— 对一个声明了 [project.scripts] 入口的 CLI 是硬伤。
    #   走 argparse 正规出口（不是自己 if argv 拦），这样 `--help` 里也能看见。
    ap.add_argument("-V", "--version", action="version", version="antinel %s" % VERSION)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("roots"); ps = p.add_subparsers(dest="sub", required=True)
    for name in ("add", "remove"):
        q = ps.add_parser(name); q.add_argument("path")
    ps.add_parser("list")

    for kind in ("paths", "domains", "commands"):
        p = sub.add_parser(kind); ps = p.add_subparsers(dest="sub", required=True)
        for name in ("add", "remove"):
            q = ps.add_parser(name); q.add_argument("value")
        ps.add_parser("list")

    p = sub.add_parser("settings"); ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("list")
    q = ps.add_parser("get"); q.add_argument("key")
    q = ps.add_parser("set"); q.add_argument("key"); q.add_argument("value")

    p = sub.add_parser("credits"); ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("snapshot"); q.add_argument("balance")
    q.add_argument("--base"); q.add_argument("--gift"); q.add_argument("--reward")
    q.add_argument("--cycle")
    ps.add_parser("list"); ps.add_parser("forecast")
    q = ps.add_parser("plan"); q.add_argument("yuan"); q.add_argument("credits")
    ps.add_parser("reconcile")

    # ★ 0.38.0：粮（哨兵的口粮）。**与 `credits` 分开命名、分开显示** ——
    #   两本账（credits 记宿主工具烧的积分；粮是哨兵站岗的口粮），混了会污染口径。
    p = sub.add_parser("粮", aliases=["granary"])
    ps = p.add_subparsers(dest="sub")
    ps.add_parser("余额")
    q = ps.add_parser("明细"); q.add_argument("--n", type=int, default=20)
    ps.add_parser("规则")

    p = sub.add_parser("pricing"); ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("show")
    q = ps.add_parser("set"); q.add_argument("model"); q.add_argument("field"); q.add_argument("price")
    q = ps.add_parser("update"); q.add_argument("--model", action="append")

    p = sub.add_parser("digest"); p.add_argument("--days", type=int)
    p.add_argument("--scope", choices=["project", "all"])
    sub.add_parser("morning")

    # 0.31.0 (F3)：源码金丝雀——"查查是否被偷数据"的最直接证据器。
    p = sub.add_parser("canary"); ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("plant"); q.add_argument("--name")
    ps.add_parser("list")

    p = sub.add_parser("verify")
    p = sub.add_parser("report"); p.add_argument("--session", default="latest")
    p.add_argument("--write", action="store_true")
    # ★ 0.53.0 修复（2026-10-17）：`scripts/report.py:777` 早就支持 --days
    #   （「only the last N calendar days」），本层却从未注册也从未透传 ⇒ 产品在
    #   四处输出里提示用户敲 `antinel report --days N`，敲下去必得 argparse 报错。
    #   与 host-scan --arm 同一族：实现有、出口没接上。
    p.add_argument("--days", type=int)

    # ★ 0.34.0（E1）：决策层一页纸。默认不带参数就能跑（days 默认 7）。
    p = sub.add_parser("brief"); p.add_argument("--days", type=int, default=7)
    # ★ 0.53.0（T4.1）：按天账的机器出口。`--json` 给程序吃（`null`＝当天无记录）。
    p = sub.add_parser("ledger", help="按天账（拦截/注意/防护缺口/已处理）；--json 给程序吃")
    p.add_argument("--days", type=int, default=7,
                   help="往回数几个日历天（含当天，默认 7）")
    p.add_argument("--json", dest="json_out", action="store_true",
                   help="输出 JSON（无记录的天是 null，不是 0）")

    p = sub.add_parser("hub"); ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("register"); q.add_argument("path"); q.add_argument("--host")
    q = ps.add_parser("unregister"); q.add_argument("path")
    q = ps.add_parser("tools"); q.add_argument("tools", nargs="+")
    ps.add_parser("list")

    p = sub.add_parser("routes"); p.add_argument("--markdown", action="store_true")
    sub.add_parser("help")
    # ★ 0.48.4 · Agent 零摩擦三件套（见 cmd_install/cmd_skill/cmd_agent 的实测注释）
    p = sub.add_parser("install", help="装/查/卸钩子（等价 python -m scripts.install）")
    p.add_argument("--root", default=None, help="项目根（默认当前目录）")
    p.add_argument("--host", choices=["claude-code", "zcode", "qoder", "generic"], default=None)
    p.add_argument("--global", dest="global_hooks", action="store_true")
    p.add_argument("--check", action="store_true", help="只比对不改动（0=一致/1=未安装/3=与登记不符）")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("--purge", action="store_true")
    p.add_argument("--skip-scan", action="store_true")
    p = sub.add_parser("skill", help="打印随包 SKILL.md（给 Agent 的操作手册）")
    p.add_argument("--path", dest="path_only", action="store_true", help="只打印路径，省 token")
    p = sub.add_parser("agent", help="机器可读的「我现在该干什么」")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("host-shield")
    ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("status"); ps.add_parser("disable")
    q = ps.add_parser("enable")
    q.add_argument("--no-desktop", action="store_true",
                   help="不在桌面放 Antinel 监理入口（默认放）")
    # ★ 0.52.0：桌面入口补建/刷新（enable 默认就建；这个是当时关了要补的出口）。
    ps.add_parser("desktop")
    q = ps.add_parser("decide"); q.add_argument("workspace"); q.add_argument("decision")
    ps.add_parser("list")
    # 0.29.0 (H-4)：**已上锁目录必须有出口**。此前用户跑 status 时因 workspaces == {}
    # 而什么都不显示 ⇒ 4 把锁挂在机器上本人毫不知情（2026-09-26 实测）。
    ps.add_parser("locks")
    q = ps.add_parser("unlock"); q.add_argument("path")
    # 0.29.0 (H-2)：待裁决队列的呈现端（此前只有记录端，报告写了没人看）。
    ps.add_parser("queue")
    # ★ 0.35.0：Antinel 监理 —— 自包含 CLI（收件箱 / 日报 / 托盘 / 守护进程 / 心跳配置）。
    #   `REMAINDER` 把 `antinel inbox` 之后的全部参数**原样**交给 inbox_cli 自己的
    #   argparse；这样将来给 inbox 加子命令**不必再动 antinel.py**
    #   —— 集成面永远只有这 6 行，`inbox_cli` 可整体摘除而不影响别处。
    p = sub.add_parser("inbox")
    p.add_argument("rest", nargs=argparse.REMAINDER)

    # 0.29.1：本地体检页 —— 网站点不到你的硬盘，真正去查的必须是你电脑上的程序。
    import ui_server
    p = sub.add_parser("ui")
    p.add_argument("--port", type=int, default=ui_server.DEFAULT_PORT,
                   help="本地端口（默认 %d，被占则顺延）" % ui_server.DEFAULT_PORT)
    p.add_argument("--no-open", action="store_true",
                   help="不自动打开浏览器，只打印地址")
    p = sub.add_parser("host-audit")
    p.add_argument("--host"); p.add_argument("--probe", action="store_true")
    p = sub.add_parser("host-scan")
    p.add_argument("--json", action="store_true")
    p.add_argument("--deep", action="store_true",
                   help="真正查完：文件数放到 50 万、不截断（默认 3000）")
    # 0.29.0 (F-6)：**默认只读，--arm 才登记并进监管**。
    # ★ 为什么必须分开：本命令的标题就写着"（只读）"。若默认既写 findings 又让门闸
    #   对未裁决落点上锁，那"只读"就是假的 —— 扫一遍 = 开始拦，用户还没看报告。
    #   副作用用**显式动作**控制，而不是靠命令不跑。
    #   默认：只看不动（可放心跑）。--arm：登记 findings、门闸开始监管。
    # ★ 0.53.0 修复（2026-10-17）：这两行**原先注册在 egress 上**，而真正消费
    #   args.arm / args.survey 的代码一直在本命令里（见上面 save_findings /
    #   save_survey 两段），cmd_egress 从头到尾没读过它们 ⇒ 两个后果：
    #     ① 本命令自己输出里提示的 `antinel host-scan --arm` 敲不了（argparse 报错）；
    #     ② `antinel egress --arm` 是个**静默空操作** —— 用户以为布防了，
    #        门闸其实什么都没收到。静默无效比报错更危险，所以参数归位而不是补文案。
    p.add_argument("--arm", action="store_true",
                   help="登记发现并交门闸监管（未裁决＝拦）。默认只读不写")
    # 0.29.0 (F-7)：**写本机取证档案**。--arm 隐含 --survey（布防必先留档）。
    p.add_argument("--survey", action="store_true",
                   help="把你电脑上的取证状态写入档案（含'扫过但没找到证据'的工具），不改随包表、不进监管")
    p = sub.add_parser("egress")
    p.add_argument("--all", action="store_true")
    p.add_argument("--no-resolve", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--days", type=int)
    p = sub.add_parser("zone"); ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("add"); q.add_argument("dir")
    q = ps.add_parser("remove"); q.add_argument("dir")
    ps.add_parser("list")

    args = ap.parse_args(argv)
    if getattr(args, "force_host"):
        os.environ["ANTINEL_FORCE_HOST"] = args.force_host   # detect_host 优先读它
    if getattr(args, "show_help", False) or args.cmd is None or args.cmd == "help":
        cmd_help()
        return 0

    prof = load_economics(detect_host())
    if args.cmd == "roots":
        cmd_roots(args)
    elif args.cmd in ("paths", "domains", "commands"):
        _wl(args.cmd, args.sub, args)
    elif args.cmd == "settings":
        cmd_settings(args)
    elif args.cmd == "credits":
        cmd_credits(args, prof)
    elif args.cmd in ("粮", "granary"):
        cmd_granary(args, prof)
    elif args.cmd == "morning":
        cmd_morning(args)
    elif args.cmd == "pricing":
        root = find_project_root()
        pp = os.path.join(root or os.getcwd(), ".psl", "rules", "pricing.json")
        cache_p = os.path.join(root or os.getcwd(), ".psl", "state", "pricing_cache.json")
        if args.sub == "show":
            try:
                d = _load_json(pp)
                print("协议价覆盖位（版本 %s，币种 %s）" % (d.get("version"), d.get("currency")))
                for m, r in (d.get("rates") or {}).items():
                    if not str(m).startswith("_"):
                        print("  [协议]", m, r)
            except Exception:
                print("（无协议价覆盖文件）")
            try:
                c = _load_json(cache_p)
                print("牌价参照缓存（来源 %s @ %s）" % (c.get("source"), str(c.get("fetched_at"))[:16]))
                for m, r in (c.get("rates") or {}).items():
                    print("  [参照]", m, "in=%.3f out=%.3f cache=%.3f USD/1M" % (
                        r.get("input", 0), r.get("output", 0), r.get("cache_read", 0)))
                if c.get("unmatched"):
                    print("  未匹配：", ", ".join(c["unmatched"]))
            except Exception:
                print("（无牌价缓存——antinel pricing update 拉取）")
        elif args.sub == "set":
            d = _load_json(pp) if os.path.isfile(pp) else {
                "version": "custom-1", "currency": "USD", "unit": "per_1m_tokens",
                "rates": {}}
            d.setdefault("rates", {}).setdefault(args.model, {})[args.field] = float(args.price)
            _save_json_atomic(pp, d)
            print("✓ 已写入（协议价覆盖位）：", args.model, args.field, args.price)
        else:
            targets = set(args.model or [])
            try:
                sd0 = _session_dna()
                for _d, rec in sd0._rows(sd0._iter_day_files(_audit_dir(root)), float("inf"), [False]):
                    if rec.get("type") == "usage_delta":
                        for e in (rec.get("entries") or []):
                            if e.get("model"):
                                targets.add(e["model"])
            except Exception:
                pass
            if not targets:
                _die("账本里还没有模型记录；用 --model 指定，例：antinel pricing update --model deepseek-v4.1-flash")
            import urllib.request
            sources = [
                ("litellm", ("https://raw.githubusercontent.com/BerriAI/litellm/main/"
                             "model_prices_and_context_window.json")),
                ("openrouter", "https://openrouter.ai/api/v1/models"),
            ]
            table, used_src = None, None
            for src_name, url in sources:
                for attempt in (1, 2):
                    try:
                        print("拉取 %s（第 %d 次）…" % (src_name, attempt))
                        req = urllib.request.Request(
                            url, headers={"User-Agent": "antinel/%s" % VERSION})
                        with urllib.request.urlopen(req, timeout=45) as r:
                            table = json.loads(r.read())
                        used_src = src_name
                        break
                    except Exception as e:
                        table = None
                        print("  拉取失败：%s" % type(e).__name__)
                if table is not None:
                    break
            if table is None:
                _die("牌价拉取失败（网络）——缓存未变；稍后重试 antinel pricing update")

            def _rate_from_litellm(e):
                if not e or e.get("input_cost_per_token") is None:
                    return None
                return {"input": round((e.get("input_cost_per_token") or 0) * 1e6, 4),
                        "output": round((e.get("output_cost_per_token") or 0) * 1e6, 4),
                        "cache_read": round((e.get("cache_read_input_token_cost") or 0) * 1e6, 4)}

            def _rate_from_openrouter(e):
                pr = (e or {}).get("pricing") or {}
                try:
                    return {"input": round(float(pr.get("prompt", 0)) * 1e6, 4),
                            "output": round(float(pr.get("completion", 0)) * 1e6, 4),
                            "cache_read": round(float(pr.get("input_cache_read", 0) or 0) * 1e6, 4)}
                except Exception:
                    return None

            rates, unmatched = {}, []
            if used_src == "litellm":
                for t in sorted(targets):
                    tl = t.lower()
                    hit = next((k for k in table
                                if k.lower() == tl or k.lower().endswith("/" + tl)), None)
                    hit = hit or next((k for k in table if tl in k.lower()), None)
                    r = _rate_from_litellm(table.get(hit) if hit else None)
                    if r and hit:
                        rates[t] = dict(r, match=hit)
                    else:
                        unmatched.append(t)
            else:  # openrouter: data[].id
                models = table.get("data") or []
                for t in sorted(targets):
                    tl = t.lower()
                    e = next((m for m in models
                              if str(m.get("id", "")).lower().endswith("/" + tl)
                              or str(m.get("id", "")).lower() == tl), None)
                    e = e or next((m for m in models if tl in str(m.get("id", "")).lower()), None)
                    r = _rate_from_openrouter(e) if e else None
                    if r and e:
                        rates[t] = dict(r, match=e.get("id"))
                    else:
                        unmatched.append(t)
            cache = {"source": used_src, "source_url": url,
                     "fetched_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                     "currency": "USD", "unit": "per_1m_tokens",
                     "rates": rates, "unmatched": unmatched}
            p = cache_p
            os.makedirs(os.path.dirname(p), exist_ok=True)
            _save_json_atomic(p, cache)
            print("✓ 牌价缓存已写（参照位）：", p)
            for m, r in rates.items():
                print("  %-24s in=%.3f out=%.3f cache=%.3f USD/1M（匹配 %s）"
                      % (m, r["input"], r["output"], r["cache_read"], r["match"]))
            if unmatched:
                print("  未匹配（如实列出，不估价）：", ", ".join(unmatched))
    elif args.cmd == "digest":
        cmd_digest(args)
    elif args.cmd == "verify":
        cmd_verify(args)
    elif args.cmd == "report":
        cmd_report(args)
    elif args.cmd == "brief":                     # ★ 0.34.0 (E1)
        sys.exit(cmd_brief(args) or 0)
    elif args.cmd == "ledger":                    # ★ 0.53.0 (T4.1)
        return cmd_ledger_top(args)
    elif args.cmd == "hub":
        cmd_hub(args)
    elif args.cmd == "routes":
        cmd_routes(args)
    elif args.cmd == "host-shield":
        cmd_host_shield(args)
    elif args.cmd == "inbox":                     # ★ 0.35.0：Antinel 监理（自包含 CLI）
        import inbox_cli
        return inbox_cli.main(args.rest)
    elif args.cmd == "host-audit":
        cmd_host_audit(args)
    elif args.cmd == "host-scan":
        cmd_host_scan(args)
    elif args.cmd == "egress":
        cmd_egress(args)
    elif args.cmd == "canary":
        cmd_canary(args)
    elif args.cmd == "ui":
        return cmd_ui(args)
    elif args.cmd == "zone":
        cmd_zone(args)
    elif args.cmd == "install":                  # ★ 0.48.4
        return cmd_install(args)
    elif args.cmd == "skill":
        return cmd_skill(args)
    elif args.cmd == "agent":
        return cmd_agent(args)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    # ★ 2026-09-26（A2）：**任何未捕获异常都不许把 traceback 直接甩给用户**。
    #   实测：`host-shield enable` 在计划任务工具被策略禁止启动时抛 PermissionError，
    #   用户看到 30 行英文调用栈 —— 首页刚建立起来的信任，在"装哨兵"这一步被冲掉。
    #   处置：一行人话 ＋ 一行原始错误 ＋ **完整栈落盘**（可复算，不藏）。
    #   只接住"意外"：SystemExit（_die 的正常退出）与 Ctrl-C 原样放行。
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as _e:
        import traceback as _tb
        _p = os.path.join(os.path.expanduser("~"), ".antinel", "last-error.txt")
        try:
            os.makedirs(os.path.dirname(_p), exist_ok=True)
            with open(_p, "w", encoding="utf-8", newline="\n") as _f:
                _f.write("".join(_tb.format_exception(type(_e), _e, _e.__traceback__)))
        except OSError:
            _p = "(无法写入)"
        print("✗ 这一步失败了：%s: %s" % (type(_e).__name__, _e), file=sys.stderr)
        print("  完整错误栈已写入：%s" % _p, file=sys.stderr)
        print("  → 其余功能不受影响；若这是「装监理」失败，把上面第一行原文发来即可。",
              file=sys.stderr)
        sys.exit(3)
