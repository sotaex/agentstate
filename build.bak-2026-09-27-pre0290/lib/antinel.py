#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.27.0 - antinel 单入口（定稿方案 v1.1/v1.2）.

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
import subprocess
import sys
from datetime import datetime, timedelta, date

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from strings import detect_lang, get_string

VERSION = "0.27.0"
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ---------------------------------------------------------------- ROUTES ----
# 单一数据源：help 清单与 skill 路由件都从这里生成（定稿方案 §六 纪律）。
ROUTES = [
    ("这个会话花了多少 / 烧了多少积分", "antinel report --session latest ＋ antinel credits forecast", "账本"),
    ("今天/昨天干了什么，拦了什么", "antinel digest [--days N] [--scope all]", "报告"),
    ("今天这个AI工具有没有胡搞/乱来/出格", "antinel digest --days 1 ＋ antinel host-audit", "报告"),
    ("今日日报 / 日报 / 昨天干了什么", "antinel digest --days 1（工作区=项目根）", "报告"),
    ("把 D:\\xxx 加进项目路径/白名单", "antinel roots add D:\\xxx ｜ antinel paths add <前缀>", "安全"),
    ("xxx 域名放行（装包老报警）", "antinel domains add xxx", "安全"),
    ("预算快超了提醒我 / 给会话设个预算", "antinel settings set budget_tokens_per_session <N>", "账本"),
    ("记一下积分余额", "antinel credits snapshot <余额> [--reward N@到期日] [--cycle 到期日]", "账本"),
    ("积分还够不够 / 什么时候烧完", "antinel credits forecast", "账本"),
    ("订阅和API直付哪个划算（对账）", "antinel credits reconcile", "账本"),
    ("阻止Agent外传 / 开安全区", "antinel settings set net_mode block ＋ antinel zone add <目录>", "安全"),
    ("证据链有没有被动过", "antinel verify", "安全"),
    ("跨工具汇总（多个AI工具一起看）", "antinel digest --scope all", "报告"),
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
    "net_mode": "warn|block（block：未白名单域名的网络命令升级为拦截——对抗分析 v1.0）",
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
                "digest_primary": "tokens", "note": "画像缺失，兜底 tokens"}


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
    sd = _session_dna()
    if not sd.append_chained(audit_dir, rec):
        sys.stderr.write("警告：policy_changed 未能进链（记录不落无链账本）\n")
        return False
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
def seven_step(label, target_file, loader, mutator, impact, undo_hint,
              field, root):
    """统一的写命令七步。mutator(data) 就地修改并返回变更摘要字符串；
    返回 None 表示无变化（不写盘、不留痕）。"""
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
        return
    new_raw = json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8")
    print("变更：%s" % label)
    print("  影响：%s" % impact)
    old_h = hashlib.sha256(old_raw).hexdigest()[:12]
    new_h = hashlib.sha256(new_raw).hexdigest()[:12]
    print("  %s  %s… → %s…" % (target_file, old_h, new_h))
    if not _confirm("应用前确认？"):
        print("已取消（未写盘）")
        return
    _save_json_atomic(target_file, data)
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
           "type": "policy_changed", "tool": "-", "session": "antinel-cli",
           "host": detect_host(), "decision": "allow", "severity": "warning",
           "field": field, "change": summary,
           "old_sha256": "sha256:" + old_h, "new_sha256": "sha256:" + new_h,
           "invoked_by": _invoked_by(),
           "reason": impact}
    _chain_record(_audit_dir(root), rec)
    print("✓ 已应用并进审计链（policy_changed）")
    print("  撤销：%s" % undo_hint)


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
                   find_project_root() or os.getcwd())
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
               "%s %s" % (undo, val), "whitelist.%s" % key, root)


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
               "global_settings." + key, root)


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
        _die("当前宿主（%s）经济画像为 %s——无积分口径，credits 不可用"
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
        print("✓ 套餐口径已存（你报的）：%.2f 元 / %s 积分 = %.4f 元/积分"
              % (yuan, format(int(credits), ","), data["yuan_per_credit"]))
        return
    if args.sub == "reconcile":
        snaps = _snapshots(audit)
        if len(snaps) < 2:
            _die("对账需要 ≥2 次快照")
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
                print("  → %.4f 积分/千token ≈ %.5f 元/千token（派生）" % (observed, observed * ppc))
        except Exception:
            print("【套餐】未登记——antinel credits plan <月费元> <每月积分>")
        cache_p = os.path.join(root, ".psl", "state", "pricing_cache.json")
        try:
            cache = _load_json(cache_p)
            print("【牌价参照】来源 %s @ %s（对公开价，非你的账单）"
                  % (cache.get("source"), str(cache.get("fetched_at"))[:16]))
        except Exception:
            print("【牌价参照】无缓存——antinel pricing update 拉取（可选参考位）")
        print("  差异来源：缓存计价／模型组合变化／时间窗；不同口径永不加和。")
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
        _die("预测需要 ≥2 次快照（现在 %d 次）——明天再记一次余额即可" % len(snaps))
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
                lines.append("自上次快照已耗 %d tokens（估）——按此速度请明天再快照一次以细化预测" % recent)
            rb = (b.get("buckets") or {}).get("reward") or {}
            if rb.get("expires"):
                lines.append("⚠ 奖励积分 %s 将于 %s 过期（平台通常先扣先过期的桶）"
                             % (rb.get("value"), rb.get("expires")))
        except Exception:
            lines.append("周期日期无法解析：%s" % b.get("cycle_end"))
    else:
        lines.append("未登记周期——antinel credits snapshot <余额> --cycle 2026-09-30")
    print("\n".join(lines))


# ------------------------------------------------------------ digest ----
def _agg_audit(audit_dir, days):
    sd = _session_dna()
    from datetime import timedelta
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    acts = blocks = warns = 0
    by_rule = {}
    toks = 0
    for day, rec in sd._rows(sd._iter_day_files(audit_dir), float("inf"), [False]):
        if day[:10] < since:
            continue
        t = rec.get("type")
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
    return {"actions": acts, "blocks": blocks, "warnings": warns,
            "by_rule": by_rule, "tokens": toks}


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
    total = {"actions": 0, "blocks": 0, "warnings": 0, "tokens": 0}
    heads = {}
    for proot, host, _meta in projects:
        ad = _audit_dir(proot)
        if not os.path.isdir(ad):
            continue
        a = _agg_audit(ad, days)
        a.update({"root": proot, "host": host})
        per.append(a)
        for k in total:
            total[k] += a[k]
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
          "token 进出 %s（事实）；记账口径 %s=%s%s。"
          % (days, len(per), total["actions"], total["blocks"],
             format(total["tokens"], ","), detect_host(), unit, econ))
    for a in sorted(per, key=lambda x: -x["actions"]):
        print("  %-9s %s" % (a["host"], a["root"]))
        print("    操作 %d｜拦截 %d %s｜提醒 %d｜tokens %s"
              % (a["actions"], a["blocks"],
                 ("（%s）" % ",".join("%s×%d" % kv for kv in sorted(a["by_rule"].items()))) if a["by_rule"] else "",
                 a["warnings"], format(a["tokens"], ",")))
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
               "reason": "跨项目聚合快照（派生物；各项目链仍是唯一事实源）"}
        import hub as hubmod
        _session_dna().append_chained(hubmod.rollup_dir(), rec)
        print("（汇总快照已进中枢链：~/.antinel/rollup/）")


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
        _die("本项目还没有账本（.psl/audit 不存在）——先接入宿主跑一次 Agent 会话")
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
        print("  最重一条：[%s] %s（已拦下）" % (rid, detail))
    print("  对比昨日：动作 %s ｜拦截 %s ｜tokens %s"
          % (_diff(cur["a"], prev["a"]), _diff(cur["b"], prev["b"]),
             _diff(cur["t"], prev["t"])))
    unit = (load_economics(detect_host()).get("unit_label") or "tokens")
    print("  覆盖：本项目 / 宿主 %s（未接入工具不在此列）；记账口径 %s"
          % (detect_host(), unit))
    print("  生成 %.2fs · 数据源=本地审计链（逐条可复算）" % (_t.time() - t0))



def _sibling(name):
    """包内寻址：源码树（同级）与安装布局（scripts/hooks/tools 子目录）都成立。"""
    for d in (_HERE, os.path.join(_HERE, "scripts"), os.path.join(_HERE, "hooks"),
              os.path.join(_HERE, "tools")):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return os.path.join(_HERE, name)


def cmd_verify(args):
    root = find_project_root()
    if root is None:
        _die("未找到项目")
    cands = (_sibling(os.path.join("tools", "verify_chain.py")),
             os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "tools", "verify_chain.py"))
    for cand in cands:
        if os.path.isfile(cand):
            sys.exit(subprocess.call([sys.executable, cand, _audit_dir(root)]))
    _die("verify_chain.py 不存在")


def _sibling_dir(sub):
    return os.path.join(_HERE, sub)


def cmd_report(args):
    root = find_project_root()
    if root is None:
        _die("未找到项目")
    argv = [sys.executable, _sibling("report.py"),
            "--root", root, "--session", args.session]
    if getattr(args, "write", False):
        argv.append("--write")
    if args.write:
        argv.append("--write-dna")
    rc = subprocess.call(argv)
    sys.exit(rc)


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
HELP_HOSTLINE = "Antinel Security Suite v%s ｜ 宿主: %s（记账口径: %s）"


def cmd_help(_args=None):
    host = detect_host()
    prof = load_economics(host)
    print(HELP_HOSTLINE % (VERSION, host, prof.get("unit", "?")))
    print("── 你可以对 Agent 说 ───────────────────────")
    for u, _c, _cat in ROUTES:
        print("  「%s」" % u)
    print("── 命令（Agent 替你跑，也可以自己跑）─────────")
    for cat in ("安全", "账本", "报告"):
        rows = [(u, c) for (u, c, k) in ROUTES if k == cat]
        if rows:
            print("  ◇ %s" % cat)
            for _u, c in rows:
                print("    %s" % c)
    print("    antinel settings list ｜ hub list ｜ routes --markdown")
    print("── 提示 ───────────────────────────────────")
    print("  拦截消息里给出的命令可直接执行；所有配置变更均进审计链。")
    print("  多宿主共存机器：Agent 自报宿主（antinel --host zcode …），口径即随宿主。")
    print("  分寸：记录 Agent 的行为与消耗；不做人的效率排名。")


def cmd_routes(args):
    if args.markdown:
        print("<!-- 由 `antinel routes --markdown` 生成；与 help 同源（ROUTES） -->")
        print("当用户表达下列意图时，运行对应命令（命令幂等；配置变更自动进审计链）。")
        print()
        print("**★ 语义匹配，不是词表匹配**：下面的用户话语只是**示例**，不是触发条件。")
        print("用户用任何说法表达同类意图——「胡搞/乱来/越界/偷传/不乖/瞎动」或未来任何新说法——")
        print("都应执行对应命令：**语义对上就执行，不要等词对上**。")
        print()
        for u, c, _cat in ROUTES:
            print("- 「%s」→ `%s`" % (u, c.replace("\\", "\\\\")))
        print("- 「antinel / 帮助 / 你能做什么」→ `antinel`（help 清单）")
        print("- 多宿主共存的机器上，Agent 应自报所在宿主：`antinel --host zcode …`"
              "（workbuddy|zcode|qoder|claude-code），否则记账口径按本机探测显示。")
        return
    for u, c, _cat in ROUTES:
        print("%s\t%s" % (u, c))


# ------------------------------------------------------------ main ----
# ------------------------------------------------------ host-shield/audit ----
def cmd_zone(args):
    """0.26.0 安全区：目录进保险库——防篡改（deny 写）+ 出网被闸（net_mode=block）。
    数据经用户同意放入，之后区内不可变；出口在 NET block。"""
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

    def mut(data):
        zs = data.setdefault("zones", [])
        if norm.replace("/", "\\") in [z.replace("/", "\\") for z in zs]:
            return None
        zs.append(norm)
        return "zones + %s" % norm

    seven_step("zone add %s" % norm, pol_path, _policy_loader(pol_path), mut,
               "安全区生效：该目录对 Agent/宿主进程 只读（防篡改），配合 net_mode=block 出网被闸",
               "antinel zone remove %s" % norm, "zones", root)
    # 同步进哨兵状态（哨兵只认 host_shield.json 的 zones）
    try:
        import host_shield as hs
        st = hs.load_state()
        st.setdefault("zones", []).append(norm)
        hs.save_state(st)
        print("✓ 哨兵已纳入执法（防篡改锁即时生效）")
    except Exception:
        print("（哨兵未运行；防篡改锁将在哨兵启动时生效）")


def cmd_host_shield(args):
    import host_shield as hs
    st = hs.load_state()
    if args.sub == "status":
        print("护盾：", "开着（宿主外传路径默认拒绝）" if st.get("enabled")
              else "关着（默认。开启：antinel host-shield enable）")
        for k, v in (st.get("workspaces") or {}).items():
            print("  %s → %s" % (k, v))
        for k, v in (st.get("windows") or {}).items():
            print("  [放行窗] %s 至 %s" % (k, datetime.fromtimestamp(v)))
        return
    if args.sub == "enable":
        st["enabled"] = True
        hs.save_state(st)
        shim = os.path.join(os.path.expanduser("~"), ".antinel", "antinel-shield.cmd")
        os.makedirs(os.path.dirname(shim), exist_ok=True)
        with open(shim, "w", encoding="ascii", newline="\r\n") as f:
            f.write('@echo off\r\n"%s" -I -S "%s" sentinel "%s"\r\n'
                    % (_host_python(), _sibling("host_shield.py"), os.path.dirname(_sibling("antinel.py"))))
        subprocess.run(["schtasks", "/Create", "/TN", "AntinelHostShield",
                        "/TR", '"%s"' % shim, "/SC", "ONLOGON", "/F"],
                       capture_output=True, timeout=30)
        subprocess.Popen([shim], close_fds=True)
        hs.record(None, "host_shield_changed", decision="allow", severity="warning",
                  field="enabled", change="false → true", invoked_by=_invoked_by(),
                  reason="宿主审计门闸已布防（默认拒绝所有登记路径的外传落盘）")
        print("✓ 护盾已布防：登记路径的外传落盘点默认拒绝；哨兵已启动并注册开机自启")
        print("  代价：被拦工作区的 ZCode 检查点回滚不可用。撤销：antinel host-shield disable")
        return
    if args.sub == "disable":
        st["enabled"] = False
        hs.save_state(st)
        subprocess.run(["schtasks", "/Delete", "/TN", "AntinelHostShield", "/F"],
                       capture_output=True, timeout=30)
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
                  field="enabled", change="true → false", invoked_by=_invoked_by(),
                  reason="宿主审计门闸已撤防（ACL 已还原）")
        print("✓ 护盾已撤防，ACL 已还原")
        return
    if args.sub == "decide":
        ws = os.path.abspath(args.workspace).lower()
        dec = args.decision
        if dec not in ("allow_once", "allow_always", "deny"):
            _die("决定取 allow_once|allow_always|deny")
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
        if not resolved:
            _die("未找到匹配的外传落盘点（antinel host-shield list 查看）")
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
    for reg in regs:
        print("== 宿主:", reg.get("host"))
        for w in reg.get("watch", []):
            base = hs.expand(w.get("path", ""))
            print("  路径:", base, "存在" if os.path.isdir(base) else "不存在")
            if not os.path.isdir(base):
                continue
            total = sum(f.count(b"\n") for f2 in
                        [open(p, "rb") for p in [base]] for f in [f2] if False) if False else None
            size = 0
            for dp, _dn, fs in os.walk(base):
                for x in fs:
                    try:
                        size += os.path.getsize(os.path.join(dp, x))
                    except OSError:
                        pass
            print("  体量: %.1f MB" % (size / 1048576))
            for ws in sorted(os.listdir(base)):
                wd = os.path.join(base, ws)
                if not os.path.isdir(wd):
                    continue
                accepted = pending_n = 0
                git_n = sens_n = entries = 0
                ws_path = ""
                for f2 in glob.glob(wd + r"\**\*.json", recursive=True):
                    try:
                        s = io.open(f2, encoding="utf-8", errors="replace").read()
                    except Exception:
                        continue
                    if "lastAccepted" in s:
                        accepted += 1
                    if "workspacePath" in s:
                        i = s.find('"workspacePath"')
                        ws_path = s[i + 17:i + 80].split('"')[0]
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
                for f2 in glob.glob(wd + r"\**\pending\*", recursive=True):
                    pending_n += 1
                line = "  工作区 %s: %s | 条目 %d | .git %d | 敏感 %d | pending %d" % (
                    ws[:12], (ws_path or "?")[:46], entries, git_n, sens_n, pending_n)
                if accepted:
                    line += " | ⚠ 已上传接受"
                print(line)
                if sens_n:
                    print("    ⚠ 敏感扩展命中——核对凭据轮换")
    print("（覆盖声明：仅列登记宿主；未登记工具不在本报告中）")


def _host_python():
    for cand in (r"C:/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python.exe",
                 os.path.expanduser("~/.zcode/binaries/python/versions/3.13.12/python.exe")):
        if os.path.isfile(cand):
            return cand
    return sys.executable


def main(argv=None):
    ap = argparse.ArgumentParser(prog="antinel", add_help=False,
                                 description="Antinel 单入口（无参数=帮助清单）")
    # 多宿主共存：目录探测会误报（装了谁就报谁）——Agent/用户可显式指定所在宿主
    ap.add_argument("--host", dest="force_host",
                    help="显式指定宿主（workbuddy|zcode|qoder|claude-code|generic），"
                         "多宿主共存时 Agent 应自报所在宿主")
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

    p = sub.add_parser("pricing"); ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("show")
    q = ps.add_parser("set"); q.add_argument("model"); q.add_argument("field"); q.add_argument("price")
    q = ps.add_parser("update"); q.add_argument("--model", action="append")

    p = sub.add_parser("digest"); p.add_argument("--days", type=int)
    p.add_argument("--scope", choices=["project", "all"])
    sub.add_parser("morning")

    p = sub.add_parser("verify")
    p = sub.add_parser("report"); p.add_argument("--session", default="latest")
    p.add_argument("--write", action="store_true")

    p = sub.add_parser("hub"); ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("register"); q.add_argument("path"); q.add_argument("--host")
    q = ps.add_parser("unregister"); q.add_argument("path")
    q = ps.add_parser("tools"); q.add_argument("tools", nargs="+")
    ps.add_parser("list")

    p = sub.add_parser("routes"); p.add_argument("--markdown", action="store_true")
    sub.add_parser("help")
    p = sub.add_parser("host-shield")
    ps = p.add_subparsers(dest="sub", required=True)
    ps.add_parser("status"); ps.add_parser("enable"); ps.add_parser("disable")
    q = ps.add_parser("decide"); q.add_argument("workspace"); q.add_argument("decision")
    ps.add_parser("list")
    p = sub.add_parser("host-audit")
    p.add_argument("--host"); p.add_argument("--probe", action="store_true")
    p = sub.add_parser("zone"); ps = p.add_subparsers(dest="sub", required=True)
    q = ps.add_parser("add"); q.add_argument("dir")
    q = ps.add_parser("remove"); q.add_argument("dir")
    ps.add_parser("list")

    args = ap.parse_args(argv)
    if getattr(args, "force_host"):
        os.environ["ANTINEL_FORCE_HOST"] = args.force_host   # detect_host 优先读它
    if args.cmd is None or args.cmd == "help":
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
    elif args.cmd == "hub":
        cmd_hub(args)
    elif args.cmd == "routes":
        cmd_routes(args)
    elif args.cmd == "host-shield":
        cmd_host_shield(args)
    elif args.cmd == "host-audit":
        cmd_host_audit(args)
    elif args.cmd == "zone":
        cmd_zone(args)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
