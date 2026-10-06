#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentState v0.30.0 - host shield (定稿方案 v1.2: 宿主审计门闸+哨兵).

第一原则：默认全部关闭。enable 前本模块不做任何事（无 ACL、无进程、无计划任务）。

职责：
  1. 按 rules/hosts/<host>.json 登记表监视宿主外传路径（如 ~/.zcode/v2/checkpoints）
  2. 门闸：对每条 watch 路径下的 pending 类子目录施加"拒绝写" ACL（用户仅 RD+X+WDAC，
     WDAC 保留给哨兵翻窗能力）；写通道被拒 = 宿主打包上传被拦
  3. 同意流：拦截后弹窗告知；用户经 `antinel host-shield decide` 决定
     （allow_* 需 TTY 交互，防 Agent 自签字——0.28.3）
  4. 留痕：拦截/放行/拒绝/心跳/ACL 异常全部进链（~/.antinel/rollup）并同步
     外置镜像（0.28.3：~/.workbuddy/antinel-audit/rollup，C1 单副本软肋）
  5. 心跳：每 10 分钟一条；晨报/status 呈现断档（dead-man）
  6. 哨兵存活性 v1（0.28.1）：真实入口；脱离 Job 的拉起；钩子 paramedic 复活
  7. 哨兵存活性 v2（0.28.3，对《哨兵绕过全谱》B/C/E 类的闭合）：
     - 状态进链，链为准（B4b/b2/c/d）：armed 只认链上最近记录（changed/field=enabled
       或执法证据型记录）；state 文件与链不一致=篡改：照链执法+host_shield_tamper+强制弹窗；
       workspaces/zones/windows 指纹无链背书变化→2 拍宽限后回写恢复
     - 心跳陈旧判死（B2）：pid 活着但心跳 >3×600s（挂起/僵死）→ 杀掉重拉
     - 外部命令绝对路径（B4i/C4）：icacls/schtasks/taskkill/powershell 全部 System32 绝对路径
     - 启动/拉起自检（B4e/f）：自身脚本与登记表对 psl/manifest.json 哈希，不符→tamper，
       拉起拒绝（不启动被改过的代码）
     - 拉锯解除节流（B6）：300s 内 breach≥5 → severity 升 critical 且弹窗不再节流
     - rollup 外置镜像（C1）：每条门闸事件同步 append 到第二物理位置+日锚

红线（A3）：永不读密文内容——只 stat 路径/大小/mtime/数量；manifest 只读前 200KB。
哨兵自身零上传（E1）。stdlib only, no network. Windows only（本版）。Python 3.10+。

已知残差（诚实声明，详见《哨兵绕过办法全谱与根方案对照 v1.0》）：
  - 同用户攻击者可伪造链记录（无签名）——状态进链把"改一个 JSON 字段"抬成
    "伪造审计记录并保持全链自洽"，配合外置镜像可被离线识破；彻底解=账户隔离/外部锚。
  - 全链被删+state 被改时，新哨兵无本地记忆可依，回退 state 文件（镜像存在时可离线发现）。
  - 补锁失败（有进程对抗）只能 critical+连环弹，不能物理阻止。
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime

POLL_SECONDS = 2
HEARTBEAT_SECONDS = 600
ALLOW_WINDOW_SECONDS = 120
DENIED_RIGHTS = "(RD,X,WDAC)"           # 读+执行+改权限；无写/追加/删子项
REVIVE_MIN_INTERVAL = 300               # paramedic 复活尝试节流（秒），防钩子风暴
_STALE_AFTER = 3 * HEARTBEAT_SECONDS    # 心跳陈旧判死（B2）：pid 活着但心跳超时→杀重拉
_BREACH_WINDOW = 300                    # 拉锯判定滑动窗（B6）
_BREACH_FORCE_N = 5                     # 窗内第 N 条起=拉锯：critical+弹窗不节流
# Windows creationflags: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
_SPAWN_FLAGS = 0x00000008 | 0x00000200 | 0x01000000
_SPAWN_FLAGS_NO_BREAKAWAY = 0x00000008 | 0x00000200

# 0.28.3（B4i/C4）：外部命令一律绝对路径——Windows 的程序搜索顺序里应用目录先于
# System32，往 python.exe 同目录丢一个假 icacls.exe 就能让补锁永远"成功"地不生效。
_SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
_ICACLS = os.path.join(_SYS32, "icacls.exe")
_SCHTASKS = os.path.join(_SYS32, "schtasks.exe")
_TASKKILL = os.path.join(_SYS32, "taskkill.exe")
_POWERSHELL = os.path.join(_SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")


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
        # B4c/B4d（文件被改坏/删）返回 disabled 默认——但 armed 的权威在链上
        # （见 chain_armed_scan/armed_state），文件缺失不再等于整体解除。
        return {"enabled": False, "workspaces": {}}


def save_state(st):
    tmp = state_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, state_path())


def findings_path():
    """0.29.0 (F-1)：host-scan 的发现落盘点（供门闸裁决）。

    ★ 为什么单独一份文件：`rules/hosts/*.json` 是**随包发布**的通用登记表（24 个宿主），
    而 host-scan 的发现是**本机特有**的（你机器上装了什么、哪个目录有外传自认）。
    两者混在一起会让随包文件带上个人机器信息。
    """
    return os.path.join(os.path.expanduser("~"), ".antinel", "findings.json")


def load_findings():
    """本机待裁决落点。文件不存在 = 还没扫过 = 监管范围为空（保持旧行为）。"""
    try:
        with open(findings_path(), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, list) else d.get("findings", [])
    except Exception:
        return []


def survey_path():
    """0.29.0 (F-7)：本机取证档案 —— 记录**每个**被扫到的宿主取到了什么、没取到什么。

    ★ 为什么必须单独一份：`rules/hosts/*.json` 的 `watch: []` 空数组，
      和"这个宿主真的没有外传落点"在字面上**长得一样**。读表的人会以为 24 个宿主
      都查过了、23 个没问题 —— 而实际上它们**从来没被取证过**。
      这正是本项目最忌的病：**「没查」被伪装成「没发现」**。
      档案把两者分开：`measured`（有实证）／`clean`（扫过、未发现证据）／`unmeasured`（没扫过）。
    """
    return os.path.join(os.path.expanduser("~"), ".antinel", "survey.json")


def load_survey():
    try:
        with open(survey_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_survey(doc):
    p = survey_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def save_findings(rows):
    p = findings_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def load_watch_registry(root):
    """rules/hosts/*.json → [{host, lock_dirs, tier, roots, watch:[{path, kind, gate_default, lock_dirs}]}]

    0.28.4（C1）：顶层 `lock_dirs` 下沉到各 watch 条目。
    ★ 修静默缺陷：0.28.3 及以前，scan_once 只读 `w["lock_dirs"]`，而 zcode.json 把它写在
      顶层 ⇒ **顶层写法被丢弃、无任何报错**（因默认值恰好也是 ["pending"] 才没暴露）。
      若有人写 `"lock_dirs": ["pending","uploads"]`，会静默只锁 pending。
    ★ 修法是**改代码兼容数据**，不是改数据迁就代码（zcode.json 字节级不动）。
      条目内已显式写 lock_dirs 的，以条目内为准（更具体者优先）。
    """
    out = []
    gdir = os.path.join(root, "rules", "hosts")
    try:
        for f in sorted(os.listdir(gdir)):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(gdir, f), encoding="utf-8") as fh:
                        d = json.load(fh)
                    top_lock = d.get("lock_dirs")
                    watch = []
                    for w in (d.get("watch") or []):
                        w = dict(w)
                        if top_lock and not w.get("lock_dirs"):
                            w["lock_dirs"] = top_lock
                        watch.append(w)
                    out.append({"host": d.get("host", f[:-5]),
                                "lock_dirs": top_lock,
                                "tier": d.get("tier"),
                                "roots": d.get("roots") or [],
                                "watch": watch})
                except Exception:
                    continue
    except OSError:
        pass
    return out


def expand(path):
    """展开 `~` 与 `%VAR%`。

    0.28.4：登记表 roots 里用了 `%APPDATA%`／`%LOCALAPPDATA%`（比写死
    `~/AppData/Roaming/...` 可读、可跨机移植），故在 expanduser 之外补 expandvars。
    """
    return os.path.expandvars(os.path.expanduser(path.replace("/", os.sep)))


# ------------------------------------------------------------ ACL (icacls) --
def _user_sid():
    return "%s\\%s" % (os.environ.get("COMPUTERNAME", "% COMPUTERNAME %"),
                       os.environ.get("USERNAME", ""))


def acl_deny(path):
    """拒绝写：移除继承，显式授 SYSTEM/Admins 完全控制 + 当前用户只读+改权限。
    Windows ACL 偶发瞬时失败（实测）→ 内部重试并用 is_denied 验证，返回是否锁住。
    0.28.2（11:58 验警演练实测）：/grant:r 只替换【同用户同标志】的 ACE——
    acl_allow 留下的 大马:(OI)(CI)F 是另一条 ACE，会与新授的 (WDAC,RD,X) 并存，
    ACL 取并集 ⇒ F 胜出，锁等于没上。先 /remove 清掉该用户全部显式 ACE 再授。    ★ H-7（0.29.0）：先移除 `OWNER RIGHTS`(*S-1-3-4) ACE，否则**锁看起来上了、实际没上**。
      实测（2026-09-26）：目录经 `/inheritance:r` 后会保留继承来的
      `OWNER RIGHTS:(OI)(CI)(F)`，它授予**所有者**完全控制并压过受限授予 ⇒
      `icacls` 明明显示 `大马:(WDAC,RD,X)`，`is_denied()` 却返回 False（仍可写）。
      这很可能就是 09-24 同一目录被反复补锁 54 次（拉锯 3h13m）的根因：
      每轮都"补锁"、每轮都没真锁住。移除后实测 `1 → 0` 全链路成立（锁得住、解得开）。
    """
    user = _user_sid()
    for _attempt in (1, 2, 3):
        subprocess.run([_ICACLS, path, "/inheritance:r"], capture_output=True, timeout=20)
        subprocess.run([_ICACLS, path, "/remove", user], capture_output=True, timeout=20)
        subprocess.run([_ICACLS, path, "/remove:g", "*S-1-3-4"], capture_output=True, timeout=20)
        r2 = subprocess.run([_ICACLS, path, "/grant:r", "*S-1-5-18:(OI)(CI)F",
                             "*S-1-5-32-544:(OI)(CI)F",
                             "%s:%s" % (user, DENIED_RIGHTS)], capture_output=True, timeout=20)
        if r2.returncode == 0 and is_denied(path):
            return True
        time.sleep(0.05)
    return is_denied(path)


def acl_allow(path):
    """放行：恢复继承并授当前用户完全控制。"""
    user = _user_sid()
    subprocess.run([_ICACLS, path, "/reset"], capture_output=True, timeout=20)
    subprocess.run([_ICACLS, path, "/grant:r", "%s:(OI)(CI)F" % user],
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


# --------------------------------------- H 批次：闸门合理化（0.29.0）----
# ★ 本块每一条都由**实测**逼出来，不是设计推演；出处逐条写在注释里。
# ★ 起因：门闸在用户零裁决（workspaces == {}）下对 zcode 的 4 个 pending 直接上锁，
#   09-24 一天 54 次补锁同一目录（拉锯 3h13m），锁上后因 `if not is_denied` 而**永不留痕**。

GATE_REPORT, GATE_DENY, GATE_ALLOW = "report", "deny", "allow"

# H-5：留痕节奏。LOCK_HELD_EVERY —— 锁着的目录也要周期性报一次状态，否则账本上
# 一片空白（旧机制：锁上之后永不留痕，09-25/26 审计里只剩心跳、零 breach）。
LOCK_HELD_EVERY = 6 * 3600
# H-5：拉锯判定窗口/次数。同一落点在该窗口内被补锁这么多次 ⇒ 判"未稳定生效或被对抗"。
CONTEST_WINDOW = 600
CONTEST_TIMES = 3


def _gate_of(w):
    """H-1（0.29.0）：读登记条目的 `gate_default` —— **此前该字段代码从不读取**。

    ★ 实测（2026-09-26）：`rules/hosts/*.json` 里写了 `gate_default`，但全仓只有
      drift_audit 的 G2 判它**合法**，host_shield **一行都没读** ⇒ 写 deny 还是 allow，
      行为完全相同：未裁决即上锁。这就是「字段写了不生效」——记录 ≠ 实际的新一处。
    ★ 缺省按 **report**（默认只报不拦），与创始人 09-26 定的策略一致：
      报告必须经用户确认；用户不放行才拦。
    """
    g = (w or {}).get("gate_default")
    return g if g in (GATE_REPORT, GATE_DENY, GATE_ALLOW) else GATE_REPORT


def _has_write_evidence(target, baseline=None):
    """H-3（0.29.0）：上锁门槛 —— 目录**非空**，或 mtime 相对基线**有变化**。

    ★ 为什么加门槛：现状 4 个被锁的 pending **全是空目录**，拿不出任何一条写入证据，
      却已被硬锁（ACL `大马:(WDAC,RD,X)`，连用户本人都写不进去）。
      「目录存在」不等于「是外传落点」。
    ★ 用 **mtime 不用 ctime**：Windows 下 `st_ctime` 是**创建时间**，不是 Unix 的
      元数据变更时间——当变更时间用必错。
    ★ `icacls` 改 ACL **不改 mtime**（2026-09-26 实测，前后完全一致）
      ⇒ 上锁动作不自我污染，mtime 是干净的"内容写入"判据。
    """
    try:
        if os.listdir(target):
            return True
    except OSError:
        return False
    try:
        mt = os.path.getmtime(target)
    except OSError:
        return False
    b = (baseline or {}).get(target.lower())
    return b is not None and mt > b + 1e-6


_SELF_ROOT_CACHE = None


def self_protected_roots():
    """H-4：自保护名单 —— Antinel 自身数据根 + **当前宿主**的数据根。

    ★ 为什么必须有：2026-09-26 实测 `.workbuddy`/`.workbuddy-ai`/`.antinel` 下的
      `pending` 目录数**均为 0**，所以 `--arm` 恰巧没锁死自己。但那是**巧合不是保障**——
      哪天多出一个名为 pending 的子目录就会锁死自己，且按旧机制**不留任何痕**。
      本函数把巧合换成明示判据。
    """
    global _SELF_ROOT_CACHE
    if _SELF_ROOT_CACHE is not None:
        return _SELF_ROOT_CACHE
    home = os.path.expanduser("~")
    roots = set([os.path.join(home, ".antinel").lower()])
    host = os.environ.get("ANTINEL_HOST") or ""
    try:
        sv = load_survey() or {}
        host = host or (sv.get("machine_host") or "")
        for h in (sv.get("hosts") or []):
            if host and (h.get("vendor") == host or h.get("name") == host):
                p = h.get("path")
                if p:
                    roots.add(os.path.abspath(os.path.expanduser(p)).lower())
    except Exception:
        pass                                  # survey 缺失时退化为只保护 Antinel 自身
    _SELF_ROOT_CACHE = roots
    return roots


def is_self_protected(path):
    """H-4：target 是否落在自保护名单内。命中 ⇒ 门闸不得上锁（除非用户显式 deny）。"""
    if not path:
        return False
    p = os.path.abspath(os.path.expanduser(path)).lower()
    for r in self_protected_roots():
        if p == r or p.startswith(r + os.sep):
            return True
    return False


def iter_gate_targets(root, regs=None):
    """H-4：产出全部受监管候选 `(base, lock_dirs, gate, source)`。

    ★ 与 scan_once / list_locks **共用同一遍历**（G5 纪律）：监管范围扩大时不重写判据，
      否则就是「两处各写一遍 ⇒ 行为漂移」（静默后门那一病）。
    """
    for reg in (regs if regs is not None else load_watch_registry(root)):
        for w in reg.get("watch", []):
            yield (expand(w.get("path", "")),
                   [d.lower() for d in (w.get("lock_dirs") or ["pending"])],
                   _gate_of(w), "watch")
    for fd in load_findings():
        yield (expand(fd.get("path", "")), ["pending"], _gate_of(fd), "findings")


def list_locks(root, regs=None):
    """H-4：列出当前**处于上锁状态**的目录 —— 此前完全没有这个出口。

    ★ 实测的痛：用户查 `host-shield status` 时，因 `workspaces == {}` 而**什么都不显示**，
      于是 4 把锁挂在机器上而本人毫不知情。有锁就必须能列出来。
    """
    out = []
    for base, lock_dirs, gate, source in iter_gate_targets(root, regs):
        if not base or not os.path.isdir(base):
            continue
        for dirpath, dirnames, _f in os.walk(base):
            for dn in dirnames:
                target = os.path.join(dirpath, dn)
                if os.path.basename(target).lower() not in lock_dirs:
                    continue
                if is_denied(target):
                    out.append({"path": target, "gate": gate, "source": source})
    return out


def pending_path():
    return os.path.join(os.path.dirname(state_path()), "pending_decisions.json")


def load_pending():
    """H-2：待裁决队列（未裁决 ⇒ 只报不拦，但必须让用户**看得见**）。"""
    try:
        return json.load(open(pending_path(), encoding="utf-8")) or []
    except Exception:
        return []


def save_pending(rows):
    try:
        with open(pending_path(), "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def note_pending(target, gate, source, why):
    """H-2：登记一个待裁决落点。已存在则只更新 last_seen，不重复堆条目。"""
    rows = load_pending()
    key = os.path.abspath(target).lower()
    for r in rows:
        if (r.get("path") or "").lower() == key:
            r["last_seen"] = datetime.now().isoformat(timespec="seconds")
            r["gate"] = gate
            r["why"] = why
            save_pending(rows)
            return
    rows.append({"path": os.path.abspath(target), "gate": gate, "source": source,
                 "why": why, "status": "unjudged",
                 "first_seen": datetime.now().isoformat(timespec="seconds"),
                 "last_seen": datetime.now().isoformat(timespec="seconds")})
    save_pending(rows)


# ------------------------------------------------------------- 留痕 ----
_IMPORT_OK = None

# 0.28.2/0.28.3 报警：需要实时触达主人的事件（心跳/放行窗关闭等常规事件不弹）。
# host_shield_changed 入列（0.28.3）：enable/disable/decide 的每次变更都让主人看见，
# 堵 E1"自己签字自己放行还不响铃"。
_ALERT_KINDS = {"host_shield_breach", "host_shield_revived",
                "host_shield_spawn_failed", "host_shield_zone_locked",
                "host_shield_changed", "host_shield_tamper"}
_NOTIFY_MIN_INTERVAL = 1800          # 同类弹窗 30 分钟内不重复（链上留痕不受限）


def _notify(title, body):
    """Windows 气泡通知（fire-and-forget）。失败静默——留痕已在链上，弹窗只是门铃。
    ANTINEL_SHIELD_NOTIFY=0 关闭（回归套件用）。"""
    try:
        if os.environ.get("ANTINEL_SHIELD_NOTIFY") == "0":
            return
        t = str(title).replace("'", "''")
        b = str(body).replace("'", "''")[:180]
        ps = ("Add-Type -AssemblyName System.Windows.Forms;"
              "Add-Type -AssemblyName System.Drawing;"
              "$n=New-Object System.Windows.Forms.NotifyIcon;"
              "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
              "$n.ShowBalloonTip(15000,'%s','%s','Warning');"
              "Start-Sleep -Seconds 8;$n.Dispose()" % (t, b))
        subprocess.Popen([_POWERSHELL, "-NoProfile", "-WindowStyle", "Hidden",
                          "-Command", ps],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         creationflags=0x08000000 if os.name == "nt" else 0)
    except Exception:
        pass


def notify(title, body):
    """公开包装（0.28.3）：CLI 安全键变更的非 TTY 可视化（E2）等复用同一气泡通道。"""
    _notify(title, body)


def _notify_throttled(kind, body, force=False):
    try:
        if force:
            _notify("Antinel 门闸", body)
            return
        st = load_state()
        sent = st.setdefault("notify_sent", {})
        try:
            last = float(sent.get(kind) or 0)
        except (TypeError, ValueError):
            last = 0.0
        now = time.time()
        if now - last < _NOTIFY_MIN_INTERVAL:
            return
        sent[kind] = now
        save_state(st)
        _notify("Antinel 门闸", body)
    except Exception:
        pass


def _ensure_pkg_on_path():
    """host_shield.py 所在目录 = 包根（session_dna.py / audit_chain.py 同目录）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def _hub_rollup_dir():
    d = os.environ.get("ANTINEL_HUB_DIR") or os.path.join(os.path.expanduser("~"), ".antinel")
    return os.path.join(d, "rollup")


def _mirror_dir():
    """0.28.3（C1）：门闸链的外置第二副本。真实部署放宿主级镜像树（与项目块记录
    的镜像同一棵），与 rollup 不同目录——删单目录不再能抹史；套件沙箱（设了
    ANTINEL_HUB_DIR）放 hub 内，不污染真实家目录。"""
    hub = os.environ.get("ANTINEL_HUB_DIR")
    if hub:
        return os.path.join(hub, "rollup-mirror")
    return os.path.join(os.path.expanduser("~"), ".workbuddy", "antinel-audit", "rollup")


def _chain(audit_dir, rec):
    """进链（复用 session_dna.append_chained）。audit_dir=None → 个人中枢 rollup。"""
    global _IMPORT_OK
    if _IMPORT_OK is None:
        try:
            import session_dna  # noqa: F401
            _IMPORT_OK = True
        except Exception:
            try:
                _ensure_pkg_on_path()
                import session_dna  # noqa: F401
                _IMPORT_OK = True
            except Exception:
                _IMPORT_OK = False
    if not _IMPORT_OK:
        return False
    import session_dna
    if audit_dir is None:
        audit_dir = _hub_rollup_dir()
    return session_dna.append_chained(audit_dir, rec)


def record(audit_dir, kind, **kw):
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
           "type": kind, "tool": "-", "session": "host-shield", "host": "generic",
           "decision": kw.pop("decision", "allow"), "severity": kw.pop("severity", "warning"),
           "reason": kw.pop("reason", "")}
    force = bool(kw.pop("alert_force", False))
    # 0.28.3（B6 拉锯判定）：窗口在 record()——所有 breach 的必经之路。放在
    # scan_once 会让 paramedic/CLI/直调的 breach 绕过判定（F-19 首版实测踩过：
    # 窗口放 scan_once，直调 record 的 6 连发全是 warning——假方案）。
    if kind == "host_shield_breach":
        now_m = time.monotonic()
        _BREACH_TIMES.append(now_m)
        while _BREACH_TIMES and now_m - _BREACH_TIMES[0] > _BREACH_WINDOW:
            _BREACH_TIMES.pop(0)
        if len(_BREACH_TIMES) >= _BREACH_FORCE_N:
            force = True
            if str(kw.get("severity", "warning")).lower() == "warning":
                kw["severity"] = "critical"
    rec.update(kw)
    ok = _chain(audit_dir, rec)
    # 0.28.2/0.28.3：高危事件实时弹窗；host_shield_changed/tamper 入列（E1）；
    # force=True（拉锯判定/补锁失败）不节流。
    if kind in _ALERT_KINDS or force:
        _notify_throttled(kind, "%s：%s" % (kind, str(rec.get("reason", ""))[:150]),
                          force=force)
    # 0.28.3（C1）：同步外置镜像——单副本链对"删目录"不设防。
    if os.environ.get("ANTINEL_SHIELD_MIRROR") != "0":
        try:
            _ensure_pkg_on_path()
            import audit_chain
            md = _mirror_dir()
            os.makedirs(md, exist_ok=True)
            fn = os.path.join(md, datetime.now().strftime("%Y-%m-%d") + ".jsonl")
            audit_chain.append_locked(fn, json.dumps(rec, ensure_ascii=False) + "\n")
            audit_chain.touch_day_manifest(fn)
        except Exception:
            pass                                    # 镜像失败不碍主链（主链已写）
    return ok


# --------------------------------------------------- manifest 自检 (B4e/f) ----
def _pkg_root():
    return os.path.dirname(os.path.abspath(__file__))


def _manifest_hash(rel):
    """psl/manifest.json 的 files[rel]（"sha256:..."）。缺失/不可读 → None（无法校验≠校验失败）。"""
    mp = os.path.join(_pkg_root(), "psl", "manifest.json")
    try:
        with open(mp, encoding="utf-8") as f:
            return (json.load(f).get("files") or {}).get(rel)
    except Exception:
        return None


def _file_sha256(path):
    try:
        with open(path, "rb") as f:
            return "sha256:" + hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def self_check():
    """0.28.3（B4e/B4f）：自身脚本与登记表对 psl/manifest.json 哈希。
    返回 (ok, problems)。manifest 缺失 → (True, [])（无法校验，如实不谎报）。"""
    problems = []
    root = _pkg_root()
    me = _manifest_hash("host_shield.py")
    live = _file_sha256(os.path.join(root, "host_shield.py"))
    if me and live and me != live:
        problems.append("host_shield.py 与 manifest 不符（运行代码可能被改）")
    gdir = os.path.join(root, "rules", "hosts")
    try:
        names = sorted(os.listdir(gdir))
    except OSError:
        names = []
    for name in names:
        if not name.endswith(".json"):
            continue
        rel = "rules/hosts/" + name
        mh = _manifest_hash(rel)
        lv = _file_sha256(os.path.join(gdir, name))
        if mh and lv and mh != lv:
            problems.append("%s 与 manifest 不符（登记表可能被毒化）" % rel)
    return (not problems), problems


# ------------------------------------------------ 哨兵存活性 v2 (0.28.3) ----
def _shield_audit_dir(pkg_root):
    """与 run_sentinel 同口径：包根有 .psl → 包审计；否则个人中枢 rollup。
    pkg_root=None（CLI status/morning 视角）→ 直接看中枢：哨兵把记录写在哪
    取决于【哨兵进程】的包根，与调用者的 cwd 无关。"""
    if pkg_root is None:
        return _hub_rollup_dir()
    root = os.path.abspath(pkg_root)
    if os.path.isdir(os.path.join(root, ".psl")):
        return os.path.join(root, ".psl", "audit")
    return _hub_rollup_dir()


def pid_alive(pid):
    """Windows 存活探测；探测失败按存活（宁可少复活，不做误杀判断）。"""
    try:
        _ensure_pkg_on_path()
        import audit_chain
        return audit_chain.pid_alive(int(pid))
    except Exception:
        return True


def _pid_image(pid):
    """进程镜像完整路径（查不到→None）。挂起进程同样可查。"""
    try:
        import ctypes
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x1000, 0, int(pid))      # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
            return None
        finally:
            k.CloseHandle(h)
    except Exception:
        return None


def sentinel_alive(state=None):
    """state 里登记的哨兵 pid 是否还活着。无登记 = 不在。"""
    st = state if state is not None else load_state()
    pid = st.get("sentinel_pid")
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    return pid_alive(pid)


def spawn_sentinel(pkg_root, python_exe=None):
    """拉起哨兵：优先脱离当前作业对象/会话（breakaway）——宿主会话结束不再连带杀。
    幂等：已有活哨兵直接返回。自检不过（B4e/f：脚本/登记表被改）→ 拒绝拉起
    被改过的代码，如实返回原因。成功把 pid 登记进 state。"""
    if os.name != "nt":
        return False, 0, "unsupported-platform"
    st = load_state()
    if sentinel_alive(st):
        return True, st.get("sentinel_pid"), "already-running"
    ok_self, problems = self_check()
    if not ok_self:
        return False, 0, "self-check-failed: " + "；".join(problems)[:120]
    py = python_exe or sys.executable
    script = os.path.join(_pkg_root(), "host_shield.py")
    if not os.path.isfile(script):
        return False, 0, "script-missing"
    argv = [py, "-I", "-S", script, "sentinel", os.path.abspath(pkg_root)]
    for flags, mode in ((_SPAWN_FLAGS, "detached+breakaway"),
                        (_SPAWN_FLAGS_NO_BREAKAWAY, "detached")):
        try:
            p = subprocess.Popen(argv, creationflags=flags,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
            st = load_state()
            st["sentinel_pid"] = p.pid
            st["sentinel_started_at"] = datetime.now().isoformat(timespec="seconds")
            save_state(st)
            return True, p.pid, mode
        except (OSError, ValueError):
            continue                              # breakaway 被策略禁止 → 降级重试
    return False, 0, "spawn-failed"


# ------------------------------------------- 链权威 armed (B4b/b2/c/d) ----
# 能证明"哨兵当时在执法"的记录类型：它们只在 armed 时才会被写。
_ENFORCE_EVIDENCE = {"host_shield_heartbeat", "host_shield_breach",
                     "host_shield_zone_locked", "host_shield_revived"}


def _armed_of(rec):
    """从一条 changed/field=enabled 记录取 armed 值：优先 armed 字段（0.28.3 起
    CLI 写入），兼容旧件按 change 字符串（"false → true"）解析。"""
    if "armed" in rec:
        return bool(rec.get("armed"))
    ch = str(rec.get("change", "")).replace(" ", "")
    return ch.endswith("true")


def chain_armed_scan(audit_dir, max_files=3):
    """最新→最旧扫最近 max_files 天，找最新一条"能证明 armed 状态"的记录：
    changed/field=enabled → 取其 armed；执法证据型记录 → armed=True。
    返回 True/False（有依据）或 None（链上无任何依据→调用方回退 state 文件，
    残差：全链被删+state 被改时新哨兵无从分辨——见模块头"已知残差"）。"""
    d = audit_dir or _hub_rollup_dir()
    try:
        names = sorted((f for f in os.listdir(d) if f.endswith(".jsonl")), reverse=True)[:max_files]
    except OSError:
        return None
    for name in names:
        try:
            with open(os.path.join(d, name), "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in reversed(lines):
            if '"host_shield_' not in line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            t = rec.get("type")
            if t == "host_shield_changed" and rec.get("field") == "enabled":
                return _armed_of(rec)
            if t in _ENFORCE_EVIDENCE:
                return True
    return None


def armed_state(audit_dir, state):
    """armed 的唯一裁决入口：链有据→链说了算；无据→回退 state 文件。"""
    a = chain_armed_scan(audit_dir)
    if a is None:
        return bool(state.get("enabled"))
    return a


def _state_fp(st):
    """安全敏感字段指纹（0.28.3 B4 系）：workspaces/zones/windows 的无链背书变化
    会被哨兵回写恢复。last_task_check/sentinel_pid/notify_sent 等运行字段不在内。"""
    try:
        return json.dumps({"w": st.get("workspaces") or {},
                           "z": sorted(st.get("zones") or []),
                           "win": st.get("windows") or {}}, sort_keys=True)
    except Exception:
        return ""


class _ChainTail(object):
    """增量跟读当日链文件：sentinel 每轮取新增记录（changed→armed 更新；
    执法证据→armed=True）。换日/文件变小→全量重扫（由调用方做 chain_armed_scan）。"""

    def __init__(self, audit_dir):
        self.audit_dir = audit_dir
        self.day = None
        self.size = 0

    def new_records(self):
        """返回 (records, saw_changed, reset)。reset=True 表示发生过换日/截断，
        调用方应全量重扫 chain_armed_scan。reset 时 saw_changed=True（给指纹
        宽限：跨午夜落在昨日文件里的 changed 记录不应触发误回写）。"""
        day = datetime.now().strftime("%Y-%m-%d") + ".jsonl"
        fn = os.path.join(self.audit_dir, day)
        try:
            size = os.path.getsize(fn)
        except OSError:
            self.day, self.size = day, 0
            return [], False, False
        reset = (self.day != day) or (size < self.size)
        if reset:
            self.day, self.size = day, 0
        recs, saw_changed = [], reset
        if size > self.size:
            try:
                with open(fn, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(self.size)
                    chunk = f.read()
                self.size = size
            except OSError:
                return [], False, reset
            for line in chunk.splitlines():
                if '"host_shield_' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                recs.append(rec)
                if rec.get("type") == "host_shield_changed":
                    saw_changed = True
        return recs, saw_changed, reset


def _sentinel_uptime(st):
    """哨兵已活多久（秒）——读它自己登记的 `sentinel_started_at`；读不到返 None。

    ★ 0.34.0 新增（F-17 配套）：判「心跳缺失」时需要第二个独立来源。
      心跳（audit 目录里的记录）与启动时刻（state 文件）**是两处副本**，
      单看一处就会出现「两处都查不到 ⇒ 不知道是真没有还是查不到」的盲区。
      这里刻意只用**墙钟**（`sentinel_started_at` 是 ISO 字符串），不用 monotonic——
      它跨进程，只能读墙钟；墙钟被回拨时本函数会返回负数，调用方按 <= 宽限期处理。
    """
    raw = st.get("sentinel_started_at")
    if not raw:
        return None
    try:
        t = datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:                      # 2026-09-30：naive/aware 混比会 TypeError
        t = t.astimezone()
    return time.time() - t.timestamp()


def ensure_alive(pkg_root, cause="manual"):
    """paramedic：布防中且哨兵不在/僵死 → 拉起并留痕；拉不起也留痕（不再沉默）。
    armed 以链为准（B4b 系）。心跳陈旧（B2 挂起/僵死）→ 杀掉重拉。
    ★ 0.34.0（F-17）：心跳「查不到」不再等价于「还活着」——改看进程启动时刻定宽限，
      见函数体内注释。
    返回 "disabled"|"throttled"|"alive"|"stale-revived"|"revived"|"spawn-failed"|"error"。"""
    try:
        st = load_state()
        audit_dir = _shield_audit_dir(pkg_root)
        armed = armed_state(audit_dir, st)
        if not armed:
            return "disabled"
        now = time.time()
        try:
            last_try = float(st.get("last_revive_attempt") or 0)
        except (TypeError, ValueError):
            last_try = 0.0
        if now - last_try < REVIVE_MIN_INTERVAL:
            return "throttled"
        old_pid = st.get("sentinel_pid")
        if sentinel_alive(st):
            # B2：pid 活着 ≠ 在干活。心跳陈旧 = 挂起/僵死 → 杀掉重拉。
            try:
                age = heartbeat_age(audit_dir)[0]
            except Exception:
                age = None
            # ★★ 0.34.0 修 F-17（fail-open → 有条件 fail-closed）。
            # 原判据：`if age is None or age <= _STALE_AFTER: return "alive"`。
            # 问题：**`age is None`（查不到心跳）与「心跳新鲜」被当成同一件事** ⇒
            #   哨兵一次都没打过心跳（首拍未到 / 审计目录被轮转清空 / 从未 armed）时，
            #   ensure_alive 永远返回 "alive" ⇒ **哨兵僵死、永不重启**，而调用方
            #   （host-shield status / morning / digest）读到的是"在岗"。
            #   这是 B2 这条判据自己的**反面**：它本意是"pid 活着不等于在干活"，
            #   却在"查不到"这一支上又退回了"pid 活着就算在干活"。
            # 修法（三条，缺一不可）：
            #   ① age 有值：按原口径与 _STALE_AFTER 比（不变）。
            #   ② age 为 None：改看**进程自己报的启动时刻** `sentinel_started_at`。
            #      距启动未满 _STALE_AFTER ⇒ 判"首拍未到"，返回 alive（**不误杀**，
            #      否则每次冷启动都会杀掉刚起来的哨兵）。
            #      距启动已超 _STALE_AFTER ⇒ 心跳**本该早就有了** ⇒ 判陈旧，走下面的
            #      杀掉重拉（**不再把盲区读成清白**——与站点 /check/ 页
            #      「⚪是结论、⚫是盲区，两者混在一起你会把盲区读成清白」同一条纪律）。
            #   ③ 启动时刻也读不到（state 被改/损坏）⇒ 保守返回 alive 并留痕，
            #      **不在无据时杀进程**（宁可少杀不可误杀：杀错的是用户的活进程）。
            started_age = _sentinel_uptime(st)
            if age is None:
                if started_age is not None and started_age <= _STALE_AFTER:
                    return "alive"                      # 首拍未到（armed 才打首拍）
                if started_age is None:
                    record(audit_dir, "host_shield_breach", decision="deny",
                           severity="warning",
                           reason="哨兵 pid=%s 活着但心跳与启动时刻均不可读——"
                                  "无法判定在岗，保守不杀（宁可漏杀不可误杀）；"
                                  "请人工检查" % old_pid)
                    return "alive"
                # 落到这里：进程活得比 _STALE_AFTER 久，却一条心跳都没有 → 判僵死
            elif age <= _STALE_AFTER:
                return "alive"
            img = _pid_image(old_pid) if old_pid else None
            # ★ 0.34.0（F-17）：`age` 可能是 None（心跳一条都没有）。
            #   下面三处文案都要用它换算分钟数 —— 直接 `age / 60.0` 会 TypeError，
            #   而 ensure_alive 末尾的 `except Exception: return "error"` 会把它
            #   **静默吞成一个 "error"**（实测：判死其实已经执行了、pid 也换了，
            #   调用方却只看到 "error" ⇒ 又一次「盲区被读成结论」）。
            #   ⇒ 判死文案必须能表达"从来没有心跳"这件事，而不是假装有一个年龄。
            age_txt = ("从未有过心跳" if age is None
                       else "%.0f 分钟前" % (age / 60.0))
            if img and not img.lower().endswith(("python.exe", "pythonw.exe")):
                record(audit_dir, "host_shield_breach", decision="deny", severity="critical",
                       reason="哨兵无心跳（%s）且旧进程镜像异常（%s），"
                              "拒绝自动重启——须人工检查 pid=%s" % (age_txt, img, old_pid))
                return "stale-revived"
            if old_pid:
                subprocess.run([_TASKKILL, "/F", "/PID", str(old_pid)],
                               capture_output=True, timeout=30)
                time.sleep(1)
            ok, pid, mode = spawn_sentinel(pkg_root)
            if ok:
                record(audit_dir, "host_shield_revived", decision="allow", severity="critical",
                       reason="哨兵无心跳（%s，疑似挂起/僵死），已强制重启"
                              "（旧 pid=%s，mode=%s）" % (age_txt, old_pid, mode),
                       pid=pid, cause=cause, spawn_mode=mode)
                return "stale-revived"
            record(audit_dir, "host_shield_spawn_failed", decision="deny", severity="critical",
                   reason="哨兵无心跳（%s）且重启失败（旧 pid=%s，cause=%s）——门闸无人值守"
                          % (age_txt, old_pid, cause),
                   cause=cause)
            return "spawn-failed"
        st["last_revive_attempt"] = now
        save_state(st)
        ok, pid, mode = spawn_sentinel(pkg_root)
        if ok:
            record(audit_dir, "host_shield_revived", decision="allow", severity="warning",
                   reason="哨兵不在（旧 pid=%s），由 %s 重新拉起（mode=%s）" % (old_pid, cause, mode),
                   pid=pid, cause=cause, spawn_mode=mode)
            return "revived"
        record(audit_dir, "host_shield_spawn_failed", decision="deny", severity="critical",
               reason="哨兵死亡（旧 pid=%s）且拉起失败（cause=%s，mode=%s）——门闸无人值守"
                      % (old_pid, cause, mode), cause=cause)
        return "spawn-failed"
    except Exception:
        return "error"


def heartbeat_age(pkg_root=None):
    """(age_seconds|None, last_ts|None)：最近一条 host_shield_* 记录的年龄。
    供晨报/paramedic 判断档（B2）。跨进程只能用墙钟（记录 ts 是墙钟）。"""
    d = _shield_audit_dir(pkg_root)
    best_ts = None
    try:
        files = sorted((f for f in os.listdir(d) if f.endswith(".jsonl")), reverse=True)[:3]
    except OSError:
        files = []
    for name in files:
        try:
            with open(os.path.join(d, name), "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if '"host_shield_' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if not str(rec.get("type", "")).startswith("host_shield_"):
                        continue
                    ts = rec.get("ts")
                    if ts and (best_ts is None or ts > best_ts):
                        best_ts = ts
        except OSError:
            continue
    if not best_ts:
        return None, None
    try:
        age = (datetime.now().astimezone() - datetime.fromisoformat(best_ts)).total_seconds()
        return max(0.0, age), best_ts
    except (ValueError, TypeError):
        return None, best_ts


# ------------------------------------------------------- 哨兵主循环 ----
_BREACH_TIMES = []                               # 拉锯判定滑动窗（B6，monotonic）
_DIVERGE_LAST = [0.0]                            # enabled 发散 tamper 的上报节流（wall）


def scan_once(root, state, audit_dir, regs=None):
    """一轮巡视：门闸执法 + 安全区防篡改 + 放行窗执法 + 任务哨卫。永不读密文内容（A3）。
    state["enabled"] 由 run_sentinel 以【链权威 armed】覆写后传入（B4b 系）。
    regs（0.28.3 B4f）：哨兵缓存的登记表——None 时自读（套件直调兼容）。"""
    touched = False
    if not state.get("enabled"):
        return False
    for z in state.get("zones") or []:               # 0.26.0 安全区：区内防篡改
        zpath = expand(z)
        if os.path.isdir(zpath) and not is_denied(zpath):
            _ok = acl_deny(zpath)
            record(audit_dir, "host_shield_zone_locked", decision="deny",
                   severity="warning" if _ok else "critical",
                   reason=("安全区已上锁（区内防篡改；出网由 net_mode 把闸）：%s" if _ok
                           else "安全区【上锁失败】——有进程在对抗门闸，须人工介入：%s") % zpath)
            touched = True
    now = time.time()
    if now - state.get("last_task_check", 0) >= 300:   # #6: 任务哨卫（5 分钟一查）
        state["last_task_check"] = now
        save_state(state)
        # 三态判断（2026-09-24 修复）："查不出来"与"查到了是坏的"是两件事。
        _ti = task_installed()
        if _ti is False:
            record(audit_dir, "host_shield_breach", decision="deny",
                   severity="warning", reason="登录自启缺失（计划任务与启动文件夹均无）"
                                              "——哨兵不会随登录自启（#6）")
            touched = True
        elif _ti is None:
            record(audit_dir, "host_shield_task_unknown", decision="alert",
                   severity="warning", reason="无法确认自启状态（schtasks 不可用或被策略拦截）"
                                              "——门闸是否随登录自启，这台电脑查不出来（#6）")
        # 0.31.0 (F4): hook-registration watchdog —— 哨兵只能为"仍然注册着的
        # 闸门"作保。布防时登记 settings 文件与其哈希（antinel.py host-shield
        # enable 写入 state["hook_registration"]）；此处核对：文件消失 /
        # 标记不在 / 哈希变了 → breach 子类⑤。诚实边界：用户正常编辑 settings
        # 与攻击者拔钩子在这里**看起来一样**，都大声报——合法编辑后重新
        # host-shield enable 刷新基线即可（fail-loud 胜过 fail-silent）。
        _reg = state.get("hook_registration") or {}
        if _reg.get("settings_file"):
            try:
                _sp = expand(_reg["settings_file"])
                if not os.path.isfile(_sp):
                    record(audit_dir, "host_shield_breach", decision="deny",
                           severity="critical", subkind="hook_registration_lost",
                           reason="宿主钩子注册文件消失：%s —— 闸门可能已被拔线"
                                  "（uninstall 或删除），须人工确认" % _sp)
                    touched = True
                else:
                    with open(_sp, "rb") as _f:
                        _txt = _f.read().decode("utf-8", errors="replace")
                    _cur = _file_sha256(_sp)
                    if "pre_tool_use.py" not in _txt and "post_tool_use.py" not in _txt:
                        record(audit_dir, "host_shield_breach", decision="deny",
                               severity="critical", subkind="hook_registration_lost",
                               reason="注册文件中已找不到 Antinel 钩子条目：%s" % _sp)
                        touched = True
                    elif _cur != _reg.get("sha256"):
                        record(audit_dir, "host_shield_breach", decision="deny",
                               severity="warning", subkind="hook_registration_changed",
                               reason="钩子注册文件与布防时不一致（合法编辑后请重新 "
                                      "host-shield enable 刷新基线）：%s" % _sp)
                        touched = True
            except Exception:
                pass
    now = time.time()
    # 0.29.0 (H-4)：watch 表与 findings 的遍历**合并到 iter_gate_targets**，
    # 与 list_locks 共用同一实现 —— 监管范围扩大时不重写判据（G5 那条纪律）。
    for base, lock_dirs, gate, source in iter_gate_targets(root, regs):
        if _lock_pending_tree(base, lock_dirs, state, audit_dir, now,
                              gate=gate, source=source):
            touched = True
    return touched


def _lock_pending_tree(base, lock_dirs, state, audit_dir, now,
                       gate=GATE_REPORT, source="watch"):
    """巡视 base，对 lock_dirs 列出的落盘子目录维持"拒绝写"ACL。返回是否动过手。

    ★ 裁决优先级（0.29.0 F-0 修正）：
        `allow_always`（永久放行，**已锁则解锁**）> 放行窗内（解锁）> 上锁。
    ★ F-0 修的缺陷：旧代码 `allow_always` 只 `continue`，不给**已上锁**的目录解锁
      ⇒ 用户跑 `host-shield decide <path> allow_always` 确认放行之后，目录仍然锁着，
      "用户确认放行 = 不拦"这条要求**落空**。放行窗分支有 acl_allow，allow_always
      分支没有 —— 两处不对称，是同一种"改了一半"。
    ★★ H-1（0.29.0）**这一支被推翻了**：旧注释写着「未裁决落在最后一支（上锁）：
      用户没点头 = 不放行 = 拦住」—— 这正是 2026-09-26 实测到的病根。
      「没点头」是**未裁决**，不是**拒绝**；把两者并成一支，等于替用户做了决定。
      现在：未裁决 + gate != deny ⇒ **只登记进待裁决队列（H-2），不上锁**。
      创始人原话：「默认只报不拦——报告必须要用户确认，用户如果确认放行，则不拦，
      用户如果不放行，就拦住」。
    """
    touched = False
    if not base or not os.path.isdir(base):
        return touched
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
                # ★ F-0：确认放行必须真的放行 —— 已上锁的要解开，不能只 continue。
                if is_denied(target):
                    acl_allow(target)
                    record(audit_dir, "host_shield_changed",
                           decision="allow", severity="warning",
                           field="workspace:" + target, change="allow_always",
                           reason="用户已确认永久放行，门闸解锁：%s" % target)
                    touched = True
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
            # 基线 mtime：首次见到先记下，下一轮才有得比（H-3 的"有变化"判据）
            _baseline = state.setdefault("lock_mtime_baseline", {})
            if key not in _baseline:
                try:
                    _baseline[key] = os.path.getmtime(target)
                    save_state(state)
                except OSError:
                    pass
            # ★ H-4 自保护：Antinel 自身 / 当前宿主的数据根**不上锁**（除非用户显式 deny）。
            #   旧代码没有这条，"没锁到自己"只是因为那些根里恰好没有 pending 目录。
            if is_self_protected(target) and mode != "deny":
                continue
            # ★ H-1：gate=report/allow ⇒ 未裁决不上锁（默认只报不拦），但要让用户看得见
            if gate != GATE_DENY:
                note_pending(target, gate, source,
                             "未裁决且 gate=%s ⇒ 只报不拦；要拦请跑 host-shield decide … deny"
                             % gate)
                continue
            # ★ H-3：无写入证据 ⇒ 不是落点。空目录 + mtime 未变 ⇒ 不锁。
            #   现状 4 个被锁的 pending 全是空目录，就是被这一条挡住的。
            if not _has_write_evidence(target, _baseline):
                note_pending(target, gate, source,
                             "登记为 deny 但无写入证据（空且 mtime 未变）⇒ 暂不上锁，转入观察")
                continue
            if is_denied(target):
                # ★ H-5：锁着也要有状态留痕。旧机制下 `not is_denied` 为假 ⇒ **整支跳过**，
                #   ⇒ 锁挂了两个月，账本上一字不提（09-25/26 审计只剩心跳、零 breach）。
                _held = state.setdefault("lock_held_at", {})
                if now - (_held.get(key) or 0) >= LOCK_HELD_EVERY:
                    _held[key] = now
                    save_state(state)
                    record(audit_dir, "host_shield_lock_held", decision="deny",
                           severity="none",
                           reason="门闸持锁中（周期性状态留痕；旧机制此处空白）：%s" % target)
                    touched = True
                continue
            _ok = acl_deny(target)
            # ★ H-5：同一落点只在**首次**留痕（旧机制每轮一条 ⇒ 09-24 同一目录 54 条刷屏）；
            #   窗口内补锁 ≥3 次 ⇒ 单列"未稳定生效或被对抗"，不再刷屏。
            _att = state.setdefault("lock_attempts", {})
            _cnt, _first = _att.get(key, (0, now))
            if now - _first > CONTEST_WINDOW:
                _cnt, _first = 0, now
            _cnt += 1
            _att[key] = (_cnt, _first)
            save_state(state)
            if _cnt == 1:
                # ★ H-7：补锁失败的诊断必须说对。旧文案写"有进程在对抗门闸"——
                #   实测真因是 OWNER RIGHTS 类 ACE 让锁**没生效**，不是有人对抗。
                record(audit_dir, "host_shield_breach", decision="deny",
                       severity="critical" if not _ok else "warning",
                       reason=(("发现未拦的外传落盘点（有写入证据），已上锁：%s" % target) if _ok
                               else ("发现未拦的外传落盘点，但【上锁未生效】：%s —— 本目录 ACL"
                                     "未能限制写入（常见于 OWNER RIGHTS 类 ACE）；"
                                     "**不等于**有进程在对抗门闸" % target)))
            elif _cnt == CONTEST_TIMES:
                record(audit_dir, "host_shield_contested", decision="deny",
                       severity="critical",
                       reason="同一落点 %.0f 分钟内被补锁 %d 次 —— 上锁未稳定生效或"
                              "有进程在对抗门闸，须人工介入：%s"
                              % (CONTEST_WINDOW / 60.0, _cnt, target))
            touched = True
    return touched


def task_installed():
    """#6: 登录自启存在性（enabled 时缺失=门闸裸奔告警）。

    ★ 三态（2026-09-24 修复）：True=在 / False=不在 / None=查不出来。
    0.28.2 起：schtasks 被拦时回退到启动文件夹 shim——自启真实存在即算"在"，
    否则哨兵每 5 分钟误报裸奔，把真信号淹掉。"""
    try:
        if subprocess.run([_SCHTASKS, "/Query", "/TN", "AntinelHostShield"],
                          capture_output=True, timeout=20).returncode == 0:
            return True
    except Exception:
        return None                          # 查不出来 ≠ 已安装：把"未知"如实上抛
    try:
        appdata = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.isfile(os.path.join(appdata, "Microsoft", "Windows",
                                           "Start Menu", "Programs", "Startup",
                                           "antinel-shield.cmd"))
    except Exception:
        return False                         # 查到了：没有自启


def run_sentinel(root):
    """哨兵主循环（由计划任务/antinel host-shield enable/spawn_sentinel 启动）。

    0.28.3（B/C/E 类闭合）：
      - armed 以链为准：启动时全量判一次，之后增量跟读当日链文件；
        state 文件的 enabled 与链不一致 → host_shield_tamper（critical+弹窗），
        照链继续执法（改文件不再能无声解除布防）。
      - workspaces/zones/windows 指纹无链背书变化 → 2 拍宽限后回写恢复+篡改留痕
        （堵"加一条 allow_always/window 就无声开门"）。
      - 启动自检（自身/登记表 vs manifest）不符 → tamper（照常执法，大声）。"""
    # ★ 出口账本采样计数器（0.29.0）：节流用，见循环内的说明
    _eg_tick = [0]
    root = os.path.abspath(root)
    audit_dir = _shield_audit_dir(root)
    state = load_state()
    # 唯一性：已有活哨兵（pid 活着且不是本进程）→ 安静退出，避免双跑双锁
    try:
        _old = int(state.get("sentinel_pid"))
    except (TypeError, ValueError):
        _old = 0
    if _old and _old != os.getpid() and pid_alive(_old):
        return
    # 启动自检（B4e/f）：不符大声说，照常执法（进程内代码仍是装运版）
    ok_self, problems = self_check()
    if not ok_self:
        record(audit_dir, "host_shield_tamper", decision="deny", severity="critical",
               field="self-check",
               reason="哨兵启动自检不符：" + "；".join(problems))
    # armed 权威（B4b 系）：链有据→链；无据→state 文件（残差见模块头）
    chain_armed = chain_armed_scan(audit_dir)
    armed = bool(state.get("enabled")) if chain_armed is None else chain_armed
    if chain_armed is not None and chain_armed != bool(state.get("enabled")):
        record(audit_dir, "host_shield_tamper", decision="deny", severity="critical",
               field="enabled",
               reason="state 文件 enabled=%s 与审计链最近状态（%s）不一致——以链为准。"
                      "如非本人操作请检查；需变更请走 antinel host-shield enable/disable"
                      % (state.get("enabled"), "armed" if chain_armed else "disarmed"))
    state["enabled"] = armed
    last_good = json.loads(json.dumps(state))       # 深拷贝基线（workspaces/zones/windows 的可信值）
    fp = _state_fp(last_good)
    grace = 0
    tail = _ChainTail(audit_dir)
    state["sentinel_pid"] = os.getpid()
    state["sentinel_started_at"] = datetime.now().isoformat(timespec="seconds")
    save_state(state)
    # B4f（0.28.3）：登记表运行期防毒——启动缓存基线，之后每 5 拍校验一次：
    # 文件变了先问 manifest（自检）：相符=合法更新→采纳；不符=被毒→tamper+按缓存执法。
    regs = load_watch_registry(root)
    reg_fp = json.dumps(regs, sort_keys=True)
    poll_n = 0
    _REG_TAMPER_LAST = [0.0]
    last_beat = 0.0                                 # monotonic（C5：不受系统时钟回拨影响）
    print("Antinel host-shield 哨兵已启动（宿主审计门闸）", flush=True)
    while True:
        try:
            state = load_state()
            # 1) 链增量：changed→armed 更新；执法证据→armed=True
            recs, saw_changed, reset = tail.new_records()
            if reset:
                chain_armed = chain_armed_scan(audit_dir)
                if chain_armed is not None:
                    armed = chain_armed
            for rec in recs:
                t = rec.get("type")
                if t == "host_shield_changed" and rec.get("field") == "enabled":
                    armed = _armed_of(rec)
                elif t in _ENFORCE_EVIDENCE:
                    armed = True
            # 1b) B4b 运行期发散：文件 enabled ≠ 链权威 → 立即回写修复；
            #     tamper 记录同类 30 分钟至多一条（回写每拍都做，记录防拉锯刷屏）。
            #     【实测缺口】首版只在启动时比对一次，运行期翻转静默无痕（drill v2）。
            if bool(state.get("enabled")) != armed:
                state["enabled"] = armed
                save_state(state)
                if time.time() - _DIVERGE_LAST[0] > 1800:
                    _DIVERGE_LAST[0] = time.time()
                    record(audit_dir, "host_shield_tamper", decision="deny",
                           severity="critical", field="enabled",
                           reason="state 文件 enabled 在运行期被改为 %s，与链权威（%s）不一致"
                                  "——已回写恢复。如非本人操作请检查；变更请走 "
                                  "antinel host-shield enable/disable"
                                  % (not armed, "armed" if armed else "disarmed"))
            state["enabled"] = armed
            # 2) state 安全字段守卫（B4 系）：无链背书的变化 → 宽限 2 拍后回写恢复
            fp2 = _state_fp(state)
            if fp2 != fp:
                if saw_changed:
                    fp, last_good, grace = fp2, json.loads(json.dumps(state)), 0
                else:
                    grace += 1
                    if grace >= 2:
                        record(audit_dir, "host_shield_tamper", decision="deny",
                               severity="critical", field="state",
                               reason="state 文件的 workspaces/zones/windows 在无链背书下被修改，"
                                      "已回写恢复（疑似加白名单/开窗绕过）")
                        save_state(last_good)
                        state = json.loads(json.dumps(last_good))
                        state["enabled"] = armed
                        fp = _state_fp(last_good)
                        grace = 0
                    else:
                        # 宽限期内按基线执法（不采纳未背书的变化）
                        state = json.loads(json.dumps(last_good))
                        state["enabled"] = armed
            else:
                fp, last_good, grace = fp2, json.loads(json.dumps(state)), 0
            # 3) 心跳（armed 才打；monotonic 计时）
            now_m = time.monotonic()
            if armed and now_m - last_beat >= HEARTBEAT_SECONDS:
                record(audit_dir, "host_shield_heartbeat", decision="allow",
                       severity="none", reason="哨兵心跳（门闸在岗）",
                       watched=len(load_watch_registry(root)))
                last_beat = now_m
            # B4f：登记表防毒（每 5 拍一查，文件哈希对 manifest）
            poll_n += 1
            if poll_n % 5 == 0:
                cur = load_watch_registry(root)
                if json.dumps(cur, sort_keys=True) != reg_fp:
                    ok_regs, prob_regs = self_check()
                    if ok_regs:
                        regs, reg_fp = cur, json.dumps(cur, sort_keys=True)
                    elif time.time() - _REG_TAMPER_LAST[0] > 1800:
                        _REG_TAMPER_LAST[0] = time.time()
                        record(audit_dir, "host_shield_tamper", decision="deny",
                               severity="critical", field="registry",
                               reason="登记表与 manifest 不符（疑似运行期投毒）——按启动缓存执法："
                                      + "；".join(prob_regs)[:120])
            scan_once(root, state, audit_dir, regs=regs)
            # ★ 出口账本（0.29.0）：节流到每 15 拍 ≈ 30 秒一次。
            #   采样只写独立账本（~/.antinel/egress/），**不进主审计链** ——
            #   30 秒一条的高频数据灌进主链会把真信号淹掉。
            _eg_tick[0] += 1
            if _eg_tick[0] % 15 == 0:
                try:
                    import egress
                    egress.tick()
                except Exception:
                    pass          # 采样失败绝不能拖死哨兵
        except Exception:
            pass
        time.sleep(POLL_SECONDS)


# 0.28.1（死因 RC1）：真实入口。此前 host_shield.py 没有任何 __main__/argv 处理——
# shim 的 `python -I -S host_shield.py sentinel <root>` 只会定义完函数就退出。
if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "sentinel":
        run_sentinel(sys.argv[2] if len(sys.argv) >= 3 else os.getcwd())
    else:
        sys.stderr.write("用法: host_shield.py sentinel <包根>\n")
        sys.exit(2)
