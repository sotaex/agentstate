#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.27.0 - host shield (定稿方案 v1.2: 宿主审计门闸+哨兵).

第一原则：默认全部关闭。enable 前本模块不做任何事（无 ACL、无进程、无计划任务）。

职责：
  1. 按 rules/hosts/<host>.json 登记表监视宿主外传路径（如 ~/.zcode/v2/checkpoints）
  2. 门闸：对每条 watch 路径下的 pending 类子目录施加"拒绝写" ACL（用户仅 RD+X+WDAC，
     WDAC 保留给哨兵翻窗能力）；写通道被拒 = 宿主打包上传被拦
  3. 同意流：拦截后发系统通知（信息式，默认已拦、无需急）；用户经
     `antinel host-shield decide <工作区> allow_once|allow_always|deny` 决定；
     allow_once=开 120s 放行窗后自动重新 deny；allow_always=该工作区不再拦
  4. 留痕：拦截/放行/拒绝/心跳/ACL 异常全部进链（~/.antinel/rollup）；绕过必留痕（D3）
  5. 心跳：每 10 分钟一条；断档即事后可证（dead-man）

红线（A3）：永不读密文内容——只 stat 路径/大小/mtime/数量；manifest 只读前 200KB。
单轮预算 <50ms。哨兵自身零上传（E1）。

stdlib only, no network. Windows only（本版）。Python 3.10+。
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta

POLL_SECONDS = 2
HEARTBEAT_SECONDS = 600
ALLOW_WINDOW_SECONDS = 120
DENIED_RIGHTS = "(RD,X,WDAC)"           # 读+执行+改权限；无写/追加/删子项


# ---------------------------------------------------------------- state ----
def state_path():
    d = os.environ.get("ANTINEL_HUB_DIR") or os.path.join(os.path.expanduser("~"), ".antinel")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "host_shield.json")


def load_state():
    try:
        with open(state_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "workspaces": {}}


def save_state(st):
    tmp = state_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, state_path())


def load_watch_registry(root):
    """rules/hosts/*.json → [{host, watch:[{path, kind, gate_default}]}]"""
    out = []
    gdir = os.path.join(root, "rules", "hosts")
    try:
        for f in sorted(os.listdir(gdir)):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(gdir, f), encoding="utf-8") as fh:
                        d = json.load(fh)
                    out.append({"host": d.get("host", f[:-5]),
                                "watch": d.get("watch") or []})
                except Exception:
                    continue
    except OSError:
        pass
    return out


def expand(path):
    return os.path.expanduser(path.replace("/", os.sep))


# ------------------------------------------------------------ ACL (icacls) --
def _user_sid():
    return "%s\\%s" % (os.environ.get("COMPUTERNAME", "% COMPUTERNAME %"),
                       os.environ.get("USERNAME", ""))


def acl_deny(path):
    """拒绝写：移除继承，显式授 SYSTEM/Admins 完全控制 + 当前用户只读+改权限。
    Windows ACL 偶发瞬时失败（实测）→ 内部重试并用 is_denied 验证，返回是否锁住。"""
    user = _user_sid()
    for _attempt in (1, 2, 3):
        subprocess.run(["icacls", path, "/inheritance:r"], capture_output=True, timeout=20)
        r2 = subprocess.run(["icacls", path, "/grant:r", "*S-1-5-18:(OI)(CI)F",
                             "*S-1-5-32-544:(OI)(CI)F",
                             "%s:%s" % (user, DENIED_RIGHTS)], capture_output=True, timeout=20)
        if r2.returncode == 0 and is_denied(path):
            return True
        time.sleep(0.05)
    return is_denied(path)


def acl_allow(path):
    """放行：恢复继承并授当前用户完全控制。"""
    user = _user_sid()
    subprocess.run(["icacls", path, "/reset"], capture_output=True, timeout=20)
    subprocess.run(["icacls", path, "/grant:r", "%s:(OI)(CI)F" % user],
                   capture_output=True, timeout=20)


def is_denied(path):
    """探测：哨兵尝试在其中建临时文件——成功=未拦；PermissionError=已拦。"""
    probe = os.path.join(path, ".shield_probe")
    try:
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        return False
    except PermissionError:
        return True
    except OSError:
        return True                          # 其他失败按已拦处理（fail-closed）
    finally:
        try:
            os.remove(probe)
        except OSError:
            pass


# ------------------------------------------------------------- 留痕 ----
_IMPORT_OK = None


def _chain(audit_dir, rec):
    """进链（复用 session_dna.append_chained）。audit_dir=None → 个人中枢。"""
    global _IMPORT_OK
    if _IMPORT_OK is None:
        try:
            parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if parent not in sys.path:
                sys.path.insert(0, parent)
            import session_dna  # noqa: F401
            _IMPORT_OK = True
        except Exception:
            _IMPORT_OK = False
    if not _IMPORT_OK:
        return False
    import session_dna
    return session_dna.append_chained(audit_dir, rec)


def record(audit_dir, kind, **kw):
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
           "type": kind, "tool": "-", "session": "host-shield", "host": "generic",
           "decision": kw.pop("decision", "allow"), "severity": kw.pop("severity", "warning"),
           "reason": kw.pop("reason", "")}
    rec.update(kw)
    return _chain(audit_dir, rec)


# ------------------------------------------------------- 哨兵主循环 ----
def scan_once(root, state, audit_dir):
    """一轮巡视：门闸执法 + 安全区防篡改 + 放行窗执法 + 任务哨卫。永不读密文内容（A3）。"""
    touched = False
    if not state.get("enabled"):
        return False
    for z in state.get("zones") or []:               # 0.26.0 安全区：区内防篡改
        zpath = expand(z)
        if os.path.isdir(zpath) and not is_denied(zpath):
            acl_deny(zpath)
            record(audit_dir, "host_shield_zone_locked", decision="deny",
                   severity="warning", reason="安全区已上锁（区内防篡改；出网由 net_mode 把闸）：%s" % zpath)
            touched = True
    now = time.time()
    if now - state.get("last_task_check", 0) >= 300:   # #6: 任务哨卫（5 分钟一查）
        state["last_task_check"] = now
        save_state(state)
        if not task_installed():
            record(audit_dir, "host_shield_breach", decision="deny",
                   severity="warning", reason="计划任务 AntinelHostShield 缺失"
                   "——哨兵不会随登录自启（#6）")
            touched = True
    now = time.time()
    for reg in load_watch_registry(root):
        for w in reg.get("watch", []):
            base = expand(w.get("path", ""))
            if not os.path.isdir(base):
                continue
            lock_dirs = [d.lower() for d in (w.get("lock_dirs") or ["pending"])]
            for dirpath, dirnames, _files in os.walk(base):
                for dn in dirnames:
                    target = os.path.join(dirpath, dn)
                    if os.path.islink(target):     # #7: symlink 入树=绕过载体
                        rep = state.setdefault("symlink_reported", [])
                        key = target.lower()
                        if key not in rep:         # 去重：同一路径只告警一次
                            rep.append(key)
                            save_state(state)
                            record(audit_dir, "host_shield_breach",
                                   decision="deny", severity="warning",
                                   reason="发现符号链接（绕过载体），不予放行：%s" % target)
                            touched = True
                        dirnames.remove(dn)
                        continue
                    key = target.lower()
                    mode = (state.get("workspaces") or {}).get(key)
                    if mode == "allow_always":
                        continue
                    win = (state.get("windows") or {}).get(key) or 0
                    if win and now < win:
                        if is_denied(target):       # 放行窗内：开窗一次
                            acl_allow(target)
                            touched = True
                        continue
                    if win and now >= win:          # 窗口到期：重新上锁并留痕
                        if not is_denied(target):
                            acl_deny(target)
                            record(audit_dir, "host_shield_window_closed",
                                   decision="allow", severity="warning",
                                   reason="放行窗到期，%s 已重新上锁" % target)
                            touched = True
                        state.setdefault("windows", {}).pop(key, None)
                        save_state(state)
                        continue
                    # 只锁登记声明的落盘目录（如 pending）；工作区级目录永不上锁
                    if os.path.basename(target).lower() not in lock_dirs:
                        continue
                    if not is_denied(target):       # D3 绕过必留痕：补锁+告警
                        acl_deny(target)
                        record(audit_dir, "host_shield_breach",
                               decision="deny", severity="warning",
                               reason="发现未拦的外传落盘点，已补锁：%s" % target)
                        touched = True
    return touched


def task_installed():
    """#6: 计划任务存在性（enabled 时缺失=门闸裸奔告警）。"""
    try:
        return subprocess.run(["schtasks", "/Query", "/TN", "AntinelHostShield"],
                              capture_output=True, timeout=20).returncode == 0
    except Exception:
        return True                          # 查询失败不误报


def run_sentinel(root):
    """哨兵主循环（由计划任务/antinel host-shield start 启动）。"""
    root = os.path.abspath(root)
    audit_dir = os.path.join(root, ".psl", "audit") if os.path.isdir(
        os.path.join(root, ".psl")) else os.path.expanduser(r"~\.antinel\rollup")
    state = load_state()
    last_beat = 0.0
    print("Antinel host-shield 哨兵已启动（宿主审计门闸）", flush=True)
    while True:
        touched = False
        try:
            state = load_state()
            now = time.time()
            if state.get("enabled") and now - last_beat >= HEARTBEAT_SECONDS:
                record(audit_dir, "host_shield_heartbeat", decision="allow",
                       severity="none", reason="哨兵心跳（门闸在岗）",
                       watched=len(load_watch_registry(root)))
                last_beat = now
            if scan_once(root, state, audit_dir):
                touched = True
        except Exception:
            pass
        time.sleep(POLL_SECONDS)
