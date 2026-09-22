#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SessionStart hook: one-line protection banner, once per session.

additionalContext is injected into the conversation, so the AGENT knows
protection is active (and can tell the user); the exit code is always 0.
Set global_settings.session_banner=false in .psl/policy.json to silence.

0.22.0 (A5): bounded roll-up -- the most recent PREVIOUS session that has no
session_dna record gets one, chained (newest 2 day files, 64 MB, fail-open).
0.24.0 (定稿方案): 技能/插件用户零安装——首次会话自举项目（从插件复制规则/
定价/画像）并登记个人中枢；幂等；任何失败不阻断会话（A-08）。"""
import json
import os
import shutil
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# session_dna.py / hub.py sit at the package root; this hook lives in <pkg>/hooks.
try:
    _PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PARENT not in sys.path:
        sys.path.insert(0, _PARENT)
    import session_dna as _sd
except Exception:
    _sd = None


def _rule_count():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     os.pardir, "rules", "default.json")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return len(json.load(f).get("rules", []))
    except Exception:
        return "?"


def _banner_quiet():
    for base in (os.getcwd(), os.path.dirname(os.getcwd())):
        p = os.path.join(base, ".psl", "policy.json")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    gs = (json.load(f).get("global_settings") or {})
                return gs.get("session_banner") is False
            except Exception:
                return False
    return False


def _current_session_id():
    """SessionStart stdin carries {session_id, ...}; best-effort read."""
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        return (json.loads(raw).get("session_id") or "")
    except Exception:
        return ""


def _bootstrap_project():
    """0.24.0: 零安装自举。首次会话把插件自带的规则/定价/画像复制进项目
    .psl/rules（幂等：只在缺失时补），并登记个人中枢。全部 fail-open。"""
    try:
        src_rules = os.path.join(_PARENT, "rules")
        dst_rules = os.path.join(os.getcwd(), ".psl", "rules")
        for name in ("default.json", "pricing.json"):
            dst = os.path.join(dst_rules, name)
            src = os.path.join(src_rules, name)
            if not os.path.isfile(dst) and os.path.isfile(src):
                os.makedirs(dst_rules, exist_ok=True)
                shutil.copy2(src, dst)
        src_econ = os.path.join(src_rules, "economics")
        dst_econ = os.path.join(dst_rules, "economics")
        if os.path.isdir(src_econ) and not os.path.isdir(dst_econ):
            shutil.copytree(src_econ, dst_econ)
    except Exception:
        pass
    try:
        if _sd is not None:
            import hub as _hub
            home = os.path.expanduser("~")
            host = "generic"
            for tag, d in (("workbuddy", ".workbuddy"), ("zcode", ".zcode"),
                           ("qoder", ".qoder"), ("claude-code", ".claude")):
                if os.path.isdir(os.path.join(home, d)):
                    host = tag
                    break
            _hub.register(os.getcwd(), host, registered_by="session")
    except Exception:
        pass


def _rollup_previous_session(current_sid):
    """0.22.0 (A5): chain a session_dna for the most recent previous session
    that has none. Bounded and fail-open; a DNA that cannot be chained is not
    written unchained (evidence never enters the ledger naked)."""
    if _sd is None:
        return
    d = os.path.join(os.getcwd(), ".psl", "audit")
    if not os.path.isdir(d):
        return
    try:
        total = sum(os.path.getsize(os.path.join(d, f))
                    for f in os.listdir(d) if f.endswith(".jsonl"))
    except OSError:
        return
    if total > _sd.MAX_ROLLUP_BYTES:
        return
    sid = _sd.find_undone_session(d, exclude=(current_sid,), max_files=2)
    if not sid:
        return
    dna = _sd.compute(d, sid, max_bytes=_sd.MAX_ROLLUP_BYTES, max_files=2,
                      generated_by="session_start_rollup")
    if dna is not None:
        _sd.append_chained(d, dna)


def main():
    # 0.17.0 (P-A5): session heartbeat. Best-effort: a failed heartbeat write
    # never breaks the banner (fail-open, A-08).
    try:
        d = os.path.join(os.getcwd(), ".psl", "audit")
        os.makedirs(d, exist_ok=True)
        from datetime import datetime
        fn = os.path.join(d, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
        with open(fn, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
                "type": "session_start", "tool": "-", "session": "banner",
                "decision": "allow", "severity": "none",
                "reason": "SessionStart heartbeat (hook ran; banner shown)"},
                ensure_ascii=False) + "\n")
    except Exception:
        pass
    try:
        current_sid = _current_session_id()
        _bootstrap_project()
        _rollup_previous_session(current_sid)
    except Exception:
        pass
    if _banner_quiet():
        return 0
    n = _rule_count()
    msg = ("Antinel Security Suite 正在守护此项目：" + str(n) + " 条规则 · 4 道闸门 · "
           "危险操作将被拦截并留痕（审计 .psl/audit）。"
           "用户问「干了什么/有没有胡搞/花了多少/积分/预算/白名单」时，"
           "不要猜——读 AGENTS.md 的 Antinel 段并按路由执行对应 antinel 命令；"
           "用户永远不需要自己运行命令。"
           "被拦截的操作重试无效；放行见 .psl/policy.json。")
    try:
        print(json.dumps({"additionalContext": msg}, ensure_ascii=False))
    except Exception:
        pass
    return 0


sys.exit(main())
