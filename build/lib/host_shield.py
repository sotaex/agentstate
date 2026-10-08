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
import re
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
# ★ 0.35.3：登录自启缺失是**持续状态**（不是复发事件）。原实现每 5 分钟记一条完全
#   相同的 breach ⇒ 一天 288 条 + 每 30 分钟一次弹窗，永远不停（创始人报障「右下
#   一直冒泡」）。改为**状态转变时留痕**，持续期最多每 24h 再提醒一次（不隐藏，只降噪）。
_TASK_MISSING_REANNOUNCE = 86400
# Windows creationflags: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
_SPAWN_FLAGS = 0x00000008 | 0x00000200 | 0x01000000
_SPAWN_FLAGS_NO_BREAKAWAY = 0x00000008 | 0x00000200
# ★★ 0.35.3（创始人报障：窗口不停弹出又马上关掉）：哨兵自己由 DETACHED_PROCESS
#   拉起 ⇒ **没有控制台**。它再去起**控制台程序**（icacls/taskkill/schtasks/
#   netstat/tasklist/powershell）时，若不显式 `CREATE_NO_WINDOW`，Windows 会为子
#   进程**新建一个控制台** —— 用户就看到黑窗一闪。egress 采样每 30 秒一次
#   （netstat+tasklist 各一次）⇒ 一直闪。修法：凡起控制台程序一律带此 flag。
#   `-WindowStyle Hidden` **挡不住**这个闪（那是 PowerShell 自己的窗，控制台宿主
#   的窗在建进程时就已创建）。非 Windows 上该参数必须为 0，否则 ValueError。
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# 0.28.3（B4i/C4）：外部命令一律绝对路径——Windows 的程序搜索顺序里应用目录先于
# System32，往 python.exe 同目录丢一个假 icacls.exe 就能让补锁永远"成功"地不生效。
_SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
_ICACLS = os.path.join(_SYS32, "icacls.exe")
_SCHTASKS = os.path.join(_SYS32, "schtasks.exe")
_TASKKILL = os.path.join(_SYS32, "taskkill.exe")
_POWERSHELL = os.path.join(_SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")


# ---------------------------------------------------------------- state ----
def _hub_dir():
    """Antinel 中枢目录 —— **唯一实现**（state / findings / survey / rollup 全读它）。

    ★★ 0.35.3 收口：此前本文件里同一件事有**两种写法** —— `state_path()` 与
      `_hub_rollup_dir()` 认 `ANTINEL_HUB_DIR` 沙箱，而 `findings_path()` /
      `survey_path()` **硬编码** `~/.antinel`。
      后果：设了沙箱的判据（`ANTINEL_HUB_DIR=<tmp>`）仍会**静默读到真机**的
      findings/survey ⇒ 判据随机器而飘（长期飘红的守卫＝没守卫）。
      修法是**消灭副本**（全部读这一个真源），不是把副本逐个改新。
      ★ 生产不受影响：`ANTINEL_HUB_DIR` 未设时展开结果与旧写法逐字相同。
    """
    return (os.environ.get("ANTINEL_HUB_DIR")
            or os.path.join(os.path.expanduser("~"), ".antinel"))


def state_path():
    d = _hub_dir()
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
    return os.path.join(_hub_dir(), "findings.json")


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
    return os.path.join(_hub_dir(), "survey.json")


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
        subprocess.run([_ICACLS, path, "/inheritance:r"], capture_output=True,
                       timeout=20, creationflags=_CREATE_NO_WINDOW)
        subprocess.run([_ICACLS, path, "/remove", user], capture_output=True,
                       timeout=20, creationflags=_CREATE_NO_WINDOW)
        subprocess.run([_ICACLS, path, "/remove:g", "*S-1-3-4"], capture_output=True,
                       timeout=20, creationflags=_CREATE_NO_WINDOW)
        r2 = subprocess.run([_ICACLS, path, "/grant:r", "*S-1-5-18:(OI)(CI)F",
                             "*S-1-5-32-544:(OI)(CI)F",
                             "%s:%s" % (user, DENIED_RIGHTS)], capture_output=True,
                            timeout=20, creationflags=_CREATE_NO_WINDOW)
        if r2.returncode == 0 and is_denied(path):
            return True
        time.sleep(0.05)
    return is_denied(path)


def acl_allow(path):
    """放行：恢复继承并授当前用户完全控制。"""
    user = _user_sid()
    subprocess.run([_ICACLS, path, "/reset"], capture_output=True,
                   timeout=20, creationflags=_CREATE_NO_WINDOW)
    subprocess.run([_ICACLS, path, "/grant:r", "%s:(OI)(CI)F" % user],
                   capture_output=True, timeout=20, creationflags=_CREATE_NO_WINDOW)


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
    # ★ 0.35.3：中枢根改读 `_hub_dir()`（消灭副本）——沙箱里保护沙箱中枢，
    #   生产里仍是 `~/.antinel`（未设 ANTINEL_HUB_DIR ⇒ 逐字相同）。
    roots = set([_hub_dir().lower()])
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

# ★★ 0.35.3 新增：**告警链路上必须受保护的文件**（唯一真源仍是 manifest 哈希，
#   这里只声明"哪些文件属于这条链路"，不自己算第二套哈希 —— 复制必漂）。
#   为什么加：原`self_check()` 只查 host_shield.py 与 rules/hosts 登记表，
#   **改hooks/pre_tool_use.py 不用重刷 manifest 也照样绿** ——
#   而那正是"门怎么响"的入口。本清单是修那个旁路。
_GUARDED_CHAIN_FILES = (
    "hooks/pre_tool_use.py",          # 判定与拦截入口
    "hooks/post_tool_use.py",         # 留痕入口
    "tools/enforce_probe.py",         # 自检探针（它失效就没人知道门失效）
    "egress.py",                      # 出口记账
)


#: 气泡停留秒数（＝可点击的时间窗）。★ 判据要能在秒级验完 ⇒ 允许调小。
_NOTIFY_LINGER = 15


def console_is_visible():
    """★ 0.36.5：值守台窗口**此刻是否可见**（真实枚举，不是推测）。

    ★★★ 这条是「右下角又冒小泡泡」那个遗留的**根治点**。
      先纠正上一轮的结论：那次我给的是「服务没启动」—— 那是**现象**，不是根因。
      实测本轮：服务在监听、值守台窗口在位（520×640）⇒ 它是**间歇**的。
      ⇒ 「重启就好了」必然复发，因为它压根没碰机制。

      泡泡的真身是 `_notify()` 的 `ShowBalloonTip` —— **Windows 气泡通知**，
      它与值守台窗口是**两条互不相干的通道**。所以「泡泡 ≠ 值守台」不是故障，
      是机制设计如此；真正的缺陷是：**该有窗口的时候，它照样弹**。

      ⇒ 机制性修法：把「此刻有没有该看的窗口」变成**一个可判定的事实**，
        降噪闸据此决定弹不弹。**不再靠各处自觉、不再靠重启。**

    ★ 为什么用 `find_console_windows(visible_only=True)` 而不自己枚举：
      **判据不许二次实现** —— 窗口枚举已经有唯一实现（0.36.4 建立的），
      这里是**import 它**，不写第二份 Win32 遍历。
    ★ 取不到模块 / 非 Windows / 枚举抛错 ⇒ 返回 **None（未知）**，
      **不是 False**。方向往严的一边偏：判不出来时**照弹**（宁可多弹不可漏报），
      因为"漏报"会把真失守藏起来，而"多弹"只是多一次打扰。
    """
    try:
        import inbox_window as WIN
    except Exception:                                          # noqa: BLE001
        return None
    try:
        # `run_id` 缺省 ⇒ 取**全部**已知形态。
        # ★★ 0.36.6 修正（实测抓到）：原来只判 `bool(find_console_windows())`，
        #   而那个枚举的"可见"口径是 `IsWindowVisible` ——
        #   **窗口最小化时它照样返回 True**（实测：IsWindowVisible=True、
        #   IsIconic=True、rect=(-32000,-32000,160,28)）。
        #   ⇒ 用户明明看不到，降噪闸却认为"用户正开着窗口" ⇒ **不弹泡泡**
        #   ⇒ 那条急事就这么被吞掉了。
        # ⇒ 现在逐个问「用户真的看得见吗」（可见 **且** 未最小化）。
        # ★ 注意：`find_console_windows()` **不改成排除最小化**——
        #   最小化的窗口仍然要能被"收旧窗"找到并关掉；
        #   只是**不能**用它当"用户正在看"的证据。这两件事必须分开。
        for _h in WIN.find_console_windows():
            _on = WIN.is_window_on_screen(_h)
            if _on is True:
                return True
            if _on is None:
                # ★ 判不出 ⇒ 整条结论就是"判不出"，**不许**当成"不在"。
                #   判不出时照弹（宁可多弹不可漏报）—— 与 console_is_visible
                #   的取向同源，只是这里必须**立刻返回**，不能让它掉到
                #   最后的 `return False`（那会把"不知道"记成"没有"）。
                return None
        # 一个都没有真在屏幕上的 ⇒ 明确回答"不在"（不是 None）。
        return False
    except Exception:                                          # noqa: BLE001
        return None


def _console_open_cmd():
    """点气泡时执行的命令：**产品自己的 CLI** —— `python -m antinel inbox open`。

    ★ 为什么走 CLI 而不是在这里自己拼 URL / 起服务：起服务与开窗口的逻辑在
      `inbox_server` / `inbox_daemon` 里**已经有一份** ⇒ 这里只发一条命令，
      **不二次实现**。
    ★ 拿不到包根（`antinel.py` 不在本文件同目录）⇒ 返回 `None` ——
      那就不挂点击，气泡照旧显示（**降级但不假装成功**）。
    返回 `(argv, cwd)` 或 `None`。
    """
    try:
        pkg = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isfile(os.path.join(pkg, "antinel.py")):
            return None
        return [sys.executable, "-m", "antinel", "inbox", "open"], pkg
    except Exception:                           # noqa: BLE001
        return None


def _human_kind(kind):
    """内部类型名 → **人话**。唯一真源：`inbox_model.TITLE_OF_KIND`（**不二次实现**）。

    ★ 为什么（0.35.2 真缺陷）：气泡原来直接显示 `host_shield_breach：…` ——
      把内部标识当人话给创始人看，正是本项目明令禁止的「黑话」。
    ★ 查不到 ⇒ **原样返回**（不编造、不猜）。
    """
    try:
        import inbox_model as _M
        return _M.TITLE_OF_KIND.get(kind) or kind
    except Exception:                           # noqa: BLE001
        return kind


def _notify_icon_and_tip():
    """★ 0.36.5：通知图标**随当前姿态取**，不再一律「黄色警告」。

    返回 `(SystemIcons 名, BalloonTipIcon 名)`。

    ★★ 为什么必须改（本轮「右下角又冒小泡泡」的根因之一）：
      原实现两处都写死 `Warning`（黄色三角）。于是：
        · 状态良好、值守中、只是提醒一句 ⇒ 弹出**警告三角**。
      用户看到的信号是"出事了"，而链上并没有事。
      ⇒ 那个气泡就成了**每 30 分钟复现、与真实状态无关的假警报** ——
        这正是"冒泡泡"让人不适的真正来源：**它在撒谎，且撒谎是默认行为。**

    ★ 映射方向：**只有真的出事了才用警告图标。**
      · down / interrupted / warn  ⇒ Warning（真问题）
      · guarding（值守中）           ⇒ Information（中性，不谎称出事）
      · 判不出 / 取不到              ⇒ Information（**偏中性**）
      ⇒ 「宁可少 alarming，不可误 alarming」：漏报由窗口与链上记录兜底，
        而误报会让用户对真告警也脱敏。

    ★ **不二次实现姿态语义**：直接用 `guard_posture()` 的返回值，
      不在这里重新判断"什么算失守"。
    """
    try:
        st = guard_posture()
        s = st.get("state") if isinstance(st, dict) else None
    except Exception:                                          # noqa: BLE001
        s = None
    bad = ("down", "interrupted", "warn")
    if s in bad:
        return "Warning", "Warning"
    # 研发态：用 Information —— 它不是故障（`POSTURE_DEV` 的定义就是"非故障"），
    # 但用警告图标会让"我在写代码"看起来像"代码出事了"。
    return "Information", "Information"


def _notify(title, body, click_cmd=None, click_cwd=None):
    """Windows 气泡通知（fire-and-forget）。失败静默——留痕已在链上，弹窗只是门铃。
    ANTINEL_SHIELD_NOTIFY=0 关闭（回归套件用）。

    ★★ 0.35.2 改（创始人 2026-10-06「右下冒泡是有问题的」）：
      1. **可点**：点气泡直接开值守台（旧版 8 秒后自己消失，点了**没有任何反应**）。
      2. 想收到点击就必须**泵消息**：`Start-Sleep` **不泵消息** ⇒
         `BalloonTipClicked` 永远不会触发。这里改成
         **有时限的 `Application::DoEvents()` 循环** —— 既泵消息，又**不会永久挂住**
         （比 `Application::Run()` 安全：后者一旦定时器没触发就会留下常驻进程）。
      3. 内容不再拿内部类型名当人话（见 `_notify_throttled` / `_human_kind`）。

    ★★★ 0.36.5 修根因②（**这才是「又冒泡泡」的机制性根因之一**）：
      图标原来**写死** `SystemIcons.Warning`（黄色警告三角），**与当前姿态无关**。
      ⇒ 「值守中」也用警告图标 ⇒ 每次通知看起来都像"出事了"，
        而用户恰恰在**状态良好**时收到它 —— 于是"冒泡泡"成了一个
        **每 30 分钟复现、无视真实状态**的假警报。
      ⇒ 现在图标**随姿态取**：真出事了才是警告色，正常通知用普通信息图标。
        取不到姿态 ⇒ 用 Information（**偏中性**，不谎称出事）。

    ★ 为什么不干脆改成「不发气泡」：气泡是**唯一在窗口不可见时还能到用户眼前**的通道。
      砍掉它 ⇒ 真失守在后台时用户完全不知道 ⇒ 那是把一个假警报换成一个真盲区。
      ⇒ 正确的修法是**让它别撒谎**（图标随姿态）＋ **别重复**（可见即不弹，
        见 `_notify_throttled`），而不是删掉通道。
    """
    try:
        if os.environ.get("ANTINEL_SHIELD_NOTIFY") == "0":
            return
        t = str(title).replace("'", "''")
        b = str(body).replace("'", "''")[:180]
        click = ""
        if click_cmd:
            exe = str(click_cmd[0]).replace("'", "''")
            args = ",".join("'%s'" % str(a).replace("'", "''") for a in click_cmd[1:])
            wd = ("" if not click_cwd
                  else " -WorkingDirectory '%s'" % str(click_cwd).replace("'", "''"))
            click = ("$n.add_BalloonTipClicked({ Start-Process -FilePath '%s'"
                     " -ArgumentList %s -WindowStyle Hidden%s });" % (exe, args, wd))
        # ★ 0.36.5：图标随姿态取，不再一律 Warning（判据见 inbox_guards_0365）
        icon, tip = _notify_icon_and_tip()
        ps = ("Add-Type -AssemblyName System.Windows.Forms;"
              "Add-Type -AssemblyName System.Drawing;"
              "$n=New-Object System.Windows.Forms.NotifyIcon;"
              "$n.Icon=[System.Drawing.SystemIcons]::%s;$n.Visible=$true;"
              "%s"
              "$n.ShowBalloonTip(%d,'%s','%s','%s');"
              "$end=(Get-Date).AddSeconds(%d);"
              "while((Get-Date) -lt $end){[System.Windows.Forms.Application]::DoEvents();"
              "Start-Sleep -Milliseconds 120};"
              "$n.Visible=$false;$n.Dispose()"
              # ★★ 0.36.5：第 4 个参数（BalloonTipIcon）**也**随姿态，
              #   不只托盘图标。原先两处都写死 'Warning' ⇒ 任务栏气泡同样是
              #   黄色警告三角 ⇒ 值守中也在"报警"。
              #   ⚠️ 占位符与参数**逐一对应**（实测核对，别凭印象加）：
              #     %s 托盘图标名 ｜ %s 点击处理 ｜ %d 停留毫秒 ｜ %s 标题
              #     %s 正文 ｜ %s 气泡图标名 ｜ %d 停留秒
              % (icon, click, _NOTIFY_LINGER * 1000, t, b, tip,
                 _NOTIFY_LINGER))
        subprocess.Popen([_POWERSHELL, "-NoProfile", "-WindowStyle", "Hidden",
                          "-Command", ps],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         creationflags=_CREATE_NO_WINDOW)
    except Exception:
        pass


def notify(title, body):
    """公开包装（0.28.3）：CLI 安全键变更的非 TTY 可视化（E2）等复用同一气泡通道。

    ★★ 0.36.8：接入与 `_notify_throttled` 同一条可见性闸（不变式 I4 通道一致性）。
      修之前本函数直接调 `_notify`，**绕过了 0.36.5 的「窗口可见 ⇒ 不重复弹」判据**
      ⇒ 实测链条：安全键变更（`antinel roots add` / `policy set` / `settings set`）
        → `seven_step` → 本函数 → `_notify` → `_notify_icon_and_tip`（真身
        ShowBalloonTip），**全链无闸** ⇒ 值守台窗口开着、正显示同一条急事时，
        右下角照样弹泡。
      这是同族第 7 例，也是第一例由**机器调用图**（JDG-02）指出的——
      前 6 例都是人眼撞见的。闸不二次实现：直接问 `console_is_visible()`；
      判不出 ⇒ 照弹（方向与 `_notify_throttled` 一致：宁可多弹一次，
      不可把真急事藏起来）。
    """
    try:
        if console_is_visible() is True:
            return
    except Exception:
        pass                                # 判不出 ⇒ 照弹
    _notify(title, body)


def _notify_throttled(kind, body, force=False):
    """★ 0.36.5：降噪闸新增**「值守台此刻可见」**这一维 —— 根治右下角小泡泡。

    ★★★ 为什么这一维是关键（这是「泡泡又冒出来」的根治点，不是又一个补丁）：
      原降噪闸只有一条规则：**同类事件 30 分钟内不重复**。
      这条规则**完全不看窗口** ⇒ 于是出现这个组合：
        「值守台窗口正开着，正显示这条急事」 ＋  「系统又弹一个气泡」
      而这两件事讲的是**同一件事**（有急事，你该去看）。
      ⇒ 用户被迫二选一：看窗 或 消泡。**这是设计缺口，不是偶发故障。**

    ★ 判据（一句话）：**同一件事不许用两种方式同时通知用户。**
      窗口已可见 ⇒ 弹窗是**重复**，一律不弹。
      ⚠️ 判不出窗口状态（返回 None）⇒ **照弹**。
        方向必须往严的一边偏：漏报会把真失守藏起来，多弹只是多一次打扰。
        ——这与本仓「查不出来 ≠ 查出来是好的」是同一条纪律。

    ★ `force=True`（用户主动要求"马上告诉我"）**不豁免**：
      那是用户显式要的，不属于"重复通知"。
    """
    try:
        if force:
            _notify("Antinel 门闸", body, *_click_args())
            return
        # ★ 窗口已可见 ⇒ 同一件事已用更完整的方式呈现 ⇒ 不再弹泡
        if console_is_visible():
            # 留痕：不是"没通知"，是"已用窗口通知过了"。链上照样记。
            try:
                st = load_state()
                st.setdefault("notify_shown_in_window", {})[kind] = time.time()
                save_state(st)
            except Exception:                                  # noqa: BLE001
                pass
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
        _notify("Antinel 门闸", body, *_click_args())
    except Exception:
        pass


def _click_args():
    """点气泡要执行什么（`(argv, cwd)`；拿不到 ⇒ 空元组 ⇒ 气泡仍显示、只是不可点）。"""
    c = _console_open_cmd()
    return c if c else ()


def _ensure_pkg_on_path():
    """host_shield.py 所在目录 = 包根（session_dna.py / audit_chain.py 同目录）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def _hub_rollup_dir():
    return os.path.join(_hub_dir(), "rollup")


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
    """写一条门闸记录进链（`**kw` 原样进记录体）。

    ★ 可选结构化字段 `recovered=True`（0.35.3，见 docs/AUDIT_SCHEMA.md v1.10）：
      ＝"这条记录描述的事**已经自动愈合、没有留下后果**"。
      消费者（值守台分档 / 日报）**必须读这个字段**，不许解析 `reason` 文案 ——
      文案会改，按文案判档的判据会**静默失效**。
      字段缺省 ⇒ 语义＝"未知"，按"有后果"处理（方向收紧）。
    """
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
           "type": kind, "tool": "-", "session": "host-shield", "host": "generic",
           "decision": kw.pop("decision", "allow"), "severity": kw.pop("severity", "warning"),
           "reason": kw.pop("reason", "")}
    force = bool(kw.pop("alert_force", False))
    # ★ 0.35.3：`notify=False` 明确不要气泡。用于**由别的命令顺带产生**的状态记录
    #   （如 `zone add` 同步哨兵执法状态）——创始人 2026-10-06 明确说右下冒泡有问题，
    #   这类变更由值守台收件箱呈现即可，不再叠一个弹窗。
    want_notify = bool(kw.pop("notify", True))
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
    # ★★★ 0.35.3（创始人 2026-10-06「**不停地有弹窗，你要解决**」＋
    #   「尽可能少让人处理」）：**气泡只给"需要你动手"的事**。
    #   Antinel 自己已经处理掉的（自愈 = `host_shield_revived`；常规执法 =
    #   非 critical 的 `host_shield_zone_locked`）**不再弹** —— 它们仍然进链、
    #   仍然在值守台台账里翻得到，但不会来敲你。
    #   ★ 判据：**能自己解决的不敲门；只有你才能解决的才敲门。**
    _sev = str(rec.get("severity") or "").lower()
    _silent = (kind == "host_shield_revived"
               or (kind == "host_shield_zone_locked" and _sev != "critical")
               # ★ 明说的变更（有命令跑过 ⇒ `invoked_by` 有值）＝**当事人已知情**
               #   ⇒ 不敲门；无声变更（哨兵自己回写状态）＝必须敲门。
               or (kind == "host_shield_changed" and bool(rec.get("invoked_by"))))
    if want_notify and ((kind in _ALERT_KINDS and not _silent) or force):
        # ★ 0.35.2：气泡正文用**人话**（`_human_kind`），不再把内部类型名
        #   `host_shield_breach` 直接摆给创始人看（黑话）。
        _notify_throttled(kind,
                          "%s：%s" % (_human_kind(kind),
                                      str(rec.get("reason", ""))[:150]),
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


def _sha_hex(v):
    """把 `sha256:<hex>` 或裸 `<hex>` 统一成裸 hex —— **比较口径唯一**。

    ★ 为什么需要（**真缺陷**，本机实测 2026-10-06）：`antinel.py host-shield enable`
      曾把**裸 hexdigest** 写进 `state["hook_registration"]["sha256"]`，而哨兵比对
      用的是 `_file_sha256()`（返回 **`sha256:<hex>`**）⇒ 两者**永不相等**
      ⇒ 哨兵每 5 分钟记一条 `hook_registration_changed`（"钩子注册文件被改"）
      ⇒ 一天 288 条 ＋ 每 30 分钟一次弹窗，**永远不停**，而文件其实一字未动。
      写侧已统一（`antinel.py` 改用 `_file_sha256`）；本函数保证**旧件**
      （state 里已存裸 hex 的机器）升级后**不会被误报一次**。
    """
    s = str(v or "")
    return s.split(":", 1)[1] if s.startswith("sha256:") else s


def _installed_version():
    """**打包清单** `psl/manifest.json` 登记的版本（如 `0.35.3`）；取不到 ⇒ None。

    ★★ 认准是**哪一个** manifest（本机实测踩过）：
      · `psl/manifest.json`   —— **打包清单**，`version` 字段 ＝ **随包代码**的版本。
        `self_check()` 的哈希就是跟它比（见 `_manifest_hash`）⇒ 版本必须读它。
      · `.psl/manifest.json`  —— **安装登记**（装到哪台机器、哪些钩子、
        策略文件在哪）。它的 `skill_version` 记的是**装的那一刻**的版本，
        跟"盘上的代码现在是哪一版"**不是同一件事**。
      ★ 读错的后果是实测出来的：第一版读 `.psl/manifest.json` 的
        `skill_version`（= 0.33.1，是 10-03 装的），而自检比的是打包清单 ⇒
        `is_dev_build()` 拿到 None，判定不出研发态，「存疑」照旧。
        ⇒ **结论：凡是"跟自检对齐"的判断，必须读自检用的那个文件。**
    """
    mp = os.path.join(_pkg_root(), "psl", "manifest.json")
    try:
        with open(mp, encoding="utf-8") as f:
            return (json.load(f) or {}).get("version")
    except Exception:                                       # noqa: BLE001
        return None


def _code_version():
    """当前代码版本（读 `antinel.py` 的 `VERSION`，**不 import** 它 —— 避免循环）。

    ★ 为什么要取"代码版本"而不是"文件哈希"：研发态的判据必须是
      **可复算的事实**，不是"文件看起来变过了"。版本号是发布流程里
      唯一的身份来源，比哈希更接近"这版是不是已出厂"。
    """
    p = os.path.join(_pkg_root(), "antinel.py")
    try:
        with open(p, encoding="utf-8") as f:
            m = re.search(r'^VERSION\s*=\s*"([^"]+)"', f.read(), re.M)
        return m.group(1) if m else None
    except Exception:                                       # noqa: BLE001
        return None


def _ver_lt(a, b):
    """`a < b`（版本号）？按**点分段数值**比，不是字符串比。

    ★★★ 为什么必须逐段比（**真缺陷，判据 R06 实测抓出来的**）：
      第一版我写的是"两个版本**不相等**就算研发态"，于是
      `登记 0.99.0 / 代码 0.1.0`（登记版**更新**）也会被判成研发态 ——
      而这个方向的错误**会掩盖真正的篡改**（新装的包比登记的旧，
      恰恰要按"存疑"处理，不是研发）。
      理由串还会打出「0.99.0 ＜ 0.1.0」—— **它在说谎**，
      因为字符串比较 `"0.99" > "0.1"`，我却没比。
      ★ 这与本仓 F51（常识冒充发现）同族：**说了一个没算过的结论**。
      ⇒ 现在逐段比数字；段数不同时**按短的那个对齐**，
        缺的段当 0（`0.36` 与 `0.36.0` 视为同版）。
      ⇒ 比不了（非数字段）时返回 `None`，由调用方**当"不是研发态"**处理
        （方向往严的一边偏）。
    """
    try:
        pa = [int(x) for x in str(a).strip().split(".")]
        pb = [int(x) for x in str(b).strip().split(".")]
    except (ValueError, TypeError, AttributeError):
        return None
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb


#: ★★★ 0.36.4 **研发态的豁免边界**（创始人 2026-10-07：
#:   「研发中只是状态之一，如哨兵发现状况了，该出现的状态，还是要出现」）。
#:
#: **实测抓到的真缺陷（0.36.3 的 `is_dev_build()` 只看版本号）**：
#:   它的判据是「登记版本 ＜ 代码版本」——**一个版本号比较**，
#:   完全不问「**到底哪些文件对不上**」。于是我实测把下面三个文件各追加一行
#:   注释（改哈希、语义不变，验完逐字节还原），`is_dev_build()` **三次全部
#:   仍返回 True**：
#:     · `hooks/pre_tool_use.py`  —— 判定与拦截**入口**（"门"本身）
#:     · `tools/enforce_probe.py` —— 自检**探针**（门坏没坏就靠它）
#:     · `rules/hosts/autoclaw.json` —— 宿主**登记表**（可被毒化）
#:   ⇒ 「我正在写代码」这个理由，**同时被用来豁免了改门、改探针、改登记表**。
#:     这不是"多了一个状态"，是**开了一个洞** —— 它让 `guard_posture()`
#:     在最该报警的时候返回蓝色"研发中"。
#:
#: **⇒ 0.36.4 改判据：从「比版本号」改成「逐条看不符的是什么」。**
#:   `is_dev_build()` 现在要求**每一条**自检问题都能被归因为
#:   「本次迭代的代码产物」，判据是**可复算的清单**，不是感觉：
#:     · 只有**代码类**文件不符 ⇒ 可归因研发（我在改的就是代码）
#:     · **告警链路**文件（hooks / 探针 / 记账）不符 ⇒ **一律不豁免**
#:     · **登记表**（`rules/hosts/*.json`）不符 ⇒ **一律不豁免**
#:   ★ 为什么这两类不豁免（理由要说清，否则后人会当成洁癖又放开）：
#:     · 改**门**：门不是"代码风格问题"，改它只有一个动机 ——
#:       让门不再响。"我在写代码"**不构成**任何理由去改门。
#:     · 改**登记表**：登记表是**数据**（谁被监管），不是代码。
#:       迭代代码不该动它；它变了就是**投毒面**，正是 R0 的定义。
#:   ⇒ 方向明确：**研发态只能豁免"我自己在写代码"这件事，不能豁免"动了门"。**
#:   ★ 取不到清单 / 清单解析不了 ⇒ **不豁免**（往严的一边偏，与全仓一致）。
#: ★ 明确**不**可被研发态豁免的一类：**哈希对不上**。
#:
#: ★★★ 0.36.4 修正（本机实测：**我上一版把 dev 判成了永不出现**）：
#:   这两个标记的第一版写成 `"告警链路文件可能被改"` / `"登记表可能被毒化"`
#:   —— 而 `"告警链路文件可能被改"` **恰好是"缺登记"那条问题串里的说明文字**
#:   （`"…却没登记进 manifest（告警链路文件可能被改而查不出；重新打包即可补上）"`）
#:   ⇒ 子串匹配把它**误判成篡改** ⇒ `is_dev_build()` 在本机恒为 `False`
#:   ⇒ dev 态**一次都没出现过** ⇒ 创始人要的「研发中」这个状态等于没做。
#:     实测：`is_dev_build()` → `(False, '…有 1 条不是代码迭代产物…')`。
#:   ⇒ **教训（本仓老纪律的第四次同型）：处置相反的两类，绝不能用同一段文字当标记。**
#:
#: ★★ 0.36.4 定下的**分类原则**（按处置方式分，不按字面分）：
#:   · **哈希对不上**（文件在 manifest 里、内容变了）⇒ **真可疑，永不豁免**。
#:     无论它属于代码还是门 —— "我在写代码"不构成改门的理由。
#:   · **压根没登记**（manifest 里没有这个文件）⇒ **打包遗漏，重新打包就好**。
#:     它是**构建缺陷**，不是篡改证据 ⇒ 研发态**可以**豁免，
#:     但**必须照旧报进 `problems`**（自检绝不放松，只是归因不同）。
#:     根因已修：`tools/enforce_probe.py` 已登记进 `scripts/build_package.py`
#:     的 `_LAYOUT`（它一直随包发布、却从未进 manifest ⇒ 自检对它完全失明）。
#:   · **登记表被投毒**（`rules/hosts/*.json` 哈希不符）⇒ 永不豁免。
#:     登记表是**数据**（谁被监管），迭代代码不该动它。
#:
#: 标记取**完整且互斥**的片段，确保每条只命中自己那一条：
DEV_NEVER_EXEMPT_MARKS = (
    "与 manifest 不符（告警链路文件可能被改）",   # 改门：哈希不符
    "与 manifest 不符（登记表可能被毒化）",       # 登记表被投毒
)


def _dev_exempt_problems(problems):
    """把自检问题分成「可归因研发」与「一律不豁免」两堆。

    返回 `(可豁免的, 不可豁免的)`，两个都是**原始问题串**的列表。

    ★★ 为什么必须**逐条**判、而不是看版本号（**0.36.3 的真缺陷**）：
      0.36.3 的 `is_dev_build()` 只比「登记版本 ＜ 代码版本」，
      不问「**谁对不上**」。实测把 `hooks/pre_tool_use.py`（判定入口）、
      `tools/enforce_probe.py`（自检探针）、`rules/hosts/autoclaw.json`
      （登记表）各改一行，`is_dev_build()` **三次全为 True**
      ⇒ 「我在写代码」被用来豁免了**改门/改探针/改登记表**。
      ⇒ 现在：只要有**任何一条**落在 `DEV_NEVER_EXEMPT_MARKS` 里，
        整堆就**不豁免**（方向往严的一边偏）。
    ★ 为什么用**字符串标记**而不是给 `self_check()` 加返回类型：
      `self_check()` 的返回值被 CLI、日报、判据等多处消费，
      改它的结构会波及一片（0.35.3 已因扩保护范围动过一次）。
      ⇒ 这里做**纯消费侧**的分类，不改上游契约（改动面最小、可测）。
      ★ 代价与对冲：标记若将来改文案，这里会**失配**。
      对冲：判据真跑验住「`self_check()` 的问题串确实含这些片段」。
    """
    never, ok = [], []
    for p in (problems or []):
        s = str(p)
        if any(mark in s for mark in DEV_NEVER_EXEMPT_MARKS):
            never.append(s)
        else:
            ok.append(s)
    return ok, never


def is_dev_build():
    """★ 是不是**研发态**（代码比登记的新 ⇒ 这一版还没出厂）。

    返回 `(是否研发态, 人话原因)`。

    ★★★ 为什么必须有这个（创始人 2026-10-07 定性）：
      原来的「存疑」判据是"自检不符 = 守门的代码可能被改过"。但**研发迭代
      期间每个版本都在改代码**，而 `psl/manifest.json` 里登记的版本
      **停在发版那一刻**（本机实测：登记 `0.33.1`／`installed_at 2026-10-03`，
      代码已到 `0.36.3`）⇒ **自检必然不符** ⇒ 界面长期挂「存疑」。
      ★ 这是一个**范畴错误**：研发期**根本不存在"出厂"这件事**，
        拿"是不是出厂那份"去质疑正在被我们自己迭代的代码，
        等于问"这张草稿是不是最终版"——它当然不是。
        ⇒ 不是发现了篡改，是**在研发期问了一个没有意义的问题**。

    ★ 判据必须**可复算**，所以用「版本号对比」而不是「文件变没变」：
      · 登记版本 < 代码版本 ⇒ 研发态（这版还没发出去）
      · 登记版本 >= 代码版本 ⇒ **不是**研发态 ⇒ 自检不符按真篡改报
      · 版本取不到（manifest 缺失 / 解析失败）⇒ **不是**研发态
        （取不到就当"不是"，方向是往严的一边偏，不是往松的一边）

    ★★★ 0.36.4：研发态**必须自动收敛**（创始人 2026-10-07
      「研发中可能只是初始状态，过很短的时间，还是要变成值守中」）——
      这里把**收敛机制定义死**，因为"过很短的时间"有两种截然不同的实现，
      差别是**是否说谎**：

      · ✗ **靠时间自己好**（"研发态最多挂 N 分钟，之后自动回值守中"）
        ⇒ 这是**撒谎**：代码与登记仍然不一致，却报"一切正常"。
          恰是本仓铁律「查不出来 ≠ 查出来是好的」的反面 ——
          查出来不一致，却报成一致。
      · ✓ **靠事实追平**（发版 ⇒ `psl/manifest.json` 的 `version` 更新
        ⇒ 与代码版本相等 ⇒ 本函数立即返回"已出厂"）
        ⇒ **收敛的那一刻是真的**（登记确实追上了），且**无需任何人工动作**。

      ★ 实测（`_p_dev_converge_probe.py` Q1，改前/改后同一探针对照）：
        登记 0.35.3／代码 0.36.3 ⇒ dev=True；
        把登记改成 0.36.3 ⇒ dev=False，理由"已出厂，不算研发态"。
      ★ 实测（`_p_dev_shipped_probe.py`）：**已发版 + 码被改 ⇒ dev=False**，
        同一份代码在"登记版本落后"时才 dev=True
        ⇒ 收敛判据**方向正确**：发版后任何改动都立刻回到"按篡改报"，
          「我在写代码」**永远无法**给已发版的包免责。
      ⇒ 所以 dev 的性质是：**它是"版本落差"的可复算投影，不是"时间过去"的投影。**
        只要落差还在，它就成立；落差一消失，它就消失，中间没有任何状态缓存。

    ★ 为什么 dev 还要**第二道闸**（版本落差只是必要条件，不是充分条件）：
      实测把 `hooks/pre_tool_use.py`（判定入口）、`rules/hosts/*.json`（登记表）
      各改一行，0.36.3 的 `is_dev_build()` **三次全为 True**
      ⇒ 「我在写代码」被用来豁免了**改门/改登记表**。
      ⇒ 现在逐条分类（`_dev_exempt_problems`）：哈希不符的链路文件与
        被毒化的登记表**永不豁免**，方向往严的一边偏。
    """
    try:
        inst, code = _installed_version(), _code_version()
        if not inst or not code:
            return False, ("取不到版本对照（登记 %r／代码 %r）"
                           " ⇒ 不按研发态处理" % (inst, code))
        if inst == code:
            return False, "登记版本与代码版本一致（%s）⇒ 已出厂，不算研发态" % code
        newer = _ver_lt(inst, code)
        if newer is None:
            return False, ("版本号比不了（登记 %r／代码 %r）"
                           " ⇒ 不按研发态处理" % (inst, code))
        if not newer:
            # ★ 登记版本**不低于**代码版本（实测曾漏这一支：0.99.0 vs 0.1.0）
            #   ⇒ 不是"这一版还没发出去"，而是"装的比登的还新/一样" ——
            #   方向是往严的一边偏，按真篡改报 `warn`，不研发态。
            return False, ("登记版本 %s 不低于代码版本 %s ⇒ 这不是迭代产物"
                           "（按可能被改过处理）" % (inst, code))
        # ★★ 0.36.4 新增第二道闸：版本落差**只是必要条件**，不是充分条件。
        #   0.36.3 只比版本号 ⇒ 实测把 hooks/pre_tool_use.py（判定入口）、
        #   tools/enforce_probe.py（自检探针）、rules/hosts/*.json（登记表）
        #   各改一行，is_dev_build() **三次全为 True** ⇒「我在写代码」被用来
        #   豁免了改门/改探针/改登记表。现在逐条分类：不可豁免的有一条就整体不豁免。
        _ok_self, _probs = self_check()
        _fine, _never = _dev_exempt_problems(_probs)
        if _never:
            # ★ 方向往严的一边偏：哪怕**其余**问题确实是迭代产物
            #   （改门 + 改代码同时发生），也不能拿"我在写代码"把"改门"一起吞掉。
            return False, ("登记版本 %s ＜ 代码版本 %s（版本落差成立），但自检里"
                           "有 %d 条**不是代码迭代产物**（%s）"
                           " ⇒ 不按研发态处理，按可能被改过报"
                           % (inst, code, len(_never), _never[0]))
        return True, ("登记版本 %s ＜ 代码版本 %s ⇒ 这一版还没发出去；"
                      "且 %d 条自检不符全部是代码迭代产物"
                      "（改门/改探针/改登记表一律不在此列）"
                      % (inst, code, len(_fine)))
    except Exception as e:                                   # noqa: BLE001
        return False, "判研发态时出错（%s）⇒ 不按研发态处理" % (type(e).__name__,)


def self_check():
    """0.28.3（B4e/B4f）：自身脚本与登记表对 psl/manifest.json 哈希。
    返回 (ok, problems)。manifest 缺失 → (True, [])（无法校验，如实不谎报）。

    ★★ 0.35.3 修（结构性缺口，本轮实测发现）：
      原实现**只校验自己（host_shield.py）与 rules/hosts 登记表**——
      也就是说：**改 `hooks/pre_tool_use.py` 不用重刷 manifest，`self_check()`照样绿**。
      而 `pre_tool_use.py` 正是**整个告警系统的入口**（判定、拦截、气泡都在里面）。
      ⇒ 旁路极短：改掉入口 → 告警不再触发 → 自检说"一切正常"。
      这不是"多查一个文件"的洁癖问题，是**保护范围与被保护对象不匹配**。

      修法：把**参与告警链路的关键文件**一并纳入校验（唯一真源仍是manifest，
      不自己算第二套哈希）：
        · `hooks/pre_tool_use.py`、`hooks/post_tool_use.py` —— 判定与留痕入口
        · `tools/enforce_probe.py` —— 自检探针（它一失效就没人知道门失效了）
        · `egress.py` —— 出口记账
      ★ 判据方向：宁可多报。manifest 里没有的文件（`_manifest_hash` 返回空）
        **跳过**而不是判红 —— 否则每次加文件都会误报，那会让人开始无视这条告警。

    ★★★★ 0.36.4 **修这条"跳过"规则自身的盲区**（实测抓到的真缺陷，
      创始人「主动根治潜在问题」）：
      上面那条"manifest 里没有就跳过"的规则，**对保护名单本身不适用** ——
      而实测本机 `tools/enforce_probe.py`（**自检探针本身**，它一失效就没人
      知道门失效了）**根本不在 `psl/manifest.json` 里**（实测 `in` 为 False，
      该 manifest 共 101 项；`hooks/pre_tool_use.py`/`hooks/post_tool_use.py`/
      `egress.py` 都在，只有它不在）。
      ⇒ 后果实测复现：把它整行改掉，`self_check()` 的 problems **一条都不多**
        （探针实测 `hash 变化 d8a1e3d948a7 → 216dd551dccf`，problems 仍是那一条
        `host_shield.py` 不符）⇒ **改掉自检探针，零报警**。
      ⇒ 这是**自检对自己失明**：0.35.3 想修的正是"保护范围要匹配被保护对象"，
        但它给保护名单加的四个文件里有一个从未被真正保护 ⇒ 那一轮的修复
        在这个文件上是**空的**，而它偏偏是最关键的那个（探针失效 = 没人知道门失效）。
      ⇒ **修法**：`self_check()` 对**保护名单内的文件**改为 **fail-closed** ——
        manifest 里查不到它的登记 ⇒ **判红**（"在保护名单里却没登记"本身就是问题）。
        名单**之外**的文件仍按"跳过"处理（保持 0.35.3 的原意：不误报）。
      ★ 方向说明：这条比"哈希不符"更早触发，且**只能靠重新打包修好**
        （`scripts/build_package.py` 生成 manifest）⇒ 用户照提示走即可，
        不需要理解哈希。
    """
    problems = []
    root = _pkg_root()
    me = _manifest_hash("host_shield.py")
    live = _file_sha256(os.path.join(root, "host_shield.py"))
    if me and live and me != live:
        problems.append("host_shield.py 与 manifest 不符（运行代码可能被改）")
    # ★ 0.36.4：**保护名单里的文件必须都有登记**（fail-closed）。
    #   实测 `tools/enforce_probe.py` 不在 manifest 里 ⇒ 改它零报警。
    #   ★ 问题串里**必须带** `DEV_NEVER_EXEMPT_MARKS` 的标记 ——
    #     否则这条"没登记"会被研发态当代码迭代产物豁免掉（那等于把
    #     "自检对自己失明"重新藏起来，正是 0.36.3 那个洞的同型）。
    for rel in _GUARDED_CHAIN_FILES:
        if not _manifest_hash(rel):
            problems.append(
                "%s 在告警链路保护名单里，却没登记进 manifest"
                "（告警链路文件可能被改而查不出；重新打包即可补上）" % rel)
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
    # ★ 告警链路上的关键文件（改它们 = 改"门怎么响"）
    for rel in _GUARDED_CHAIN_FILES:
        mh = _manifest_hash(rel)
        lv = _file_sha256(os.path.join(root, rel.replace("/", os.sep)))
        if mh and lv and mh != lv:
            problems.append("%s 与 manifest 不符（告警链路文件可能被改）" % rel)
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


def _kill_stale(pid):
    """结束一个**已判僵死**的哨兵进程。失败只返回，不抛。

    ★ 必须带 `_CREATE_NO_WINDOW` + System32 绝对路径：这正是闪窗的成因之一
      （`taskkill` 是控制台程序；不带这个 flag 就会在桌面上闪一个黑窗）。
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        subprocess.run([_TASKKILL, "/PID", str(pid), "/T", "/F"],
                       timeout=20, capture_output=True,
                       creationflags=_CREATE_NO_WINDOW)
        return True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def spawn_sentinel(pkg_root, python_exe=None):
    """拉起哨兵：优先脱离当前作业对象/会话（breakaway）——宿主会话结束不再连带杀。
    幂等：已有**活着的**哨兵直接返回。自检不过（B4e/f：脚本/登记表被改）→ 拒绝拉起
    被改过的代码，如实返回原因。成功把 pid 登记进 state。

    ★★ 0.35.3 修（本机实测抓到的真缺陷，不是推演）：
      原来的幂等判断只问 `sentinel_alive()`——**只看进程还在不在**。
      实测本机：pid 3748 进程**确实活着**，但心跳已断档 **452 分钟**
      （`guard_posture()` 因此一直报 `down / 疑似挂起/僵死`）。
      于是一条"已经僵死"的哨兵会让 `spawn_sentinel` 永远返回
      `already-running` ⇒ **任何修复动作都被这条幂等挡住**，
      页面上的「马上修复」按钮点了等于没点。
      ⇒ 幂等条件收紧为「进程活 **且** 心跳新鲜」；进程活但心跳陈旧 ⇒
        先如实杀掉，再拉新的（这本来就是 `_STALE_AFTER` 的原意，
        只是 `spawn_sentinel` 从没执行它）。
    """
    if os.name != "nt":
        return False, 0, "unsupported-platform"
    st = load_state()
    if sentinel_alive(st):
        age, _ts = sentinel_heartbeat_age()
        if age is not None and age <= _STALE_AFTER:
            return True, st.get("sentinel_pid"), "already-running"
        # 进程在、心跳断了 ⇒ 它已经不算在岗。清掉登记并结束它，
        # 否则它会一直占着 pid，也让新哨兵起不来。
        _kill_stale(st.get("sentinel_pid"))
        st = load_state()
        st["sentinel_pid"] = None
        save_state(st)
    ok_self, problems = self_check()
    if not ok_self:
        # ★★★ 0.36.3：**研发态不拦住哨兵启动**（实测发现的连带缺陷）。
        #   原实现无条件 `return False` —— 而研发迭代期自检**必然**不符
        #   （登记版本停在发版那一刻），实测：
        #     `spawn_sentinel()` → `False, "self-check-failed: …"`
        #   ⇒ 用户点「马上修复」得到的是"修不了"，而哨兵**根本没被试着起**。
        #     这就是研发态最该被支持的时候，功能反而被门禁挡住了。
        #   ⇒ 现在：研发态**放行**，但①原因照旧逐字打印、②哨兵启动时会
        #     照旧记一条 `host_shield_tamper` 审计（见 `run_sentinel`）——
        #     **不放松自检，只是承认"这一版还没发出去"**。
        #   ★ 已出厂（版本一致/更高）时**仍然硬拦** —— 那才是真篡改，
        #     拦住是对的（见 R06 判据）。
        _is_dev, _dev_why = is_dev_build()
        if not _is_dev:
            return False, 0, "self-check-failed: " + "；".join(problems)[:120]
        print("[spawn] 研发态：自检不符属迭代产物，仍启动哨兵（%s）" % _dev_why,
              file=sys.stderr)
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
            if not _prefilter_ok(line):
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


# ==================== 链背书（0.35.3：按字段判定，去子串过滤）====================
# ★★ 修的是什么（2026-10-06，盘上证据）：全链 12 条 `host_shield_tamper` +
#    field="state"，**每一条都紧跟一次「哨兵被重新拉起」**，且全部带
#    "已回写恢复" —— 也就是**防线自己愈合了、根本没出事，却记成失守**。
#    真因：`_ChainTail.new_records()` 用 `'"host_shield_' not in line` 做前置过滤，
#    而**改 state 的三个入口里有两个写的不是 host_shield_* 类型**：
#      · `antinel zone add`  → 链上写 `policy_changed`（field=zones）
#      · 放行窗到期           → 链上写 `host_shield_window_closed`
#    这两类整行被前置过滤挡掉 ⇒ `saw_changed=False` ⇒ 宽限 2 拍 ⇒ 判篡改
#    ⇒ `save_state(last_good)` **把用户刚设的 zones / 刚过期的窗口回滚回去**。
#    ★ 这是「**卡词面不卡结构**」在本仓第 4 次复发（前 3 次见
#      `.workbuddy-ai/skills/guard-real-path/SKILL.md`）。
#
# ★ 为什么必须**按字段**判定（不能只判"有没有链记录"）：
#   只按"本拍有没有链记录"给宽限，等于开了一条绕过路 ——
#   先跑一条合法命令（留下任意一条链记录），再在窗口内直接改 state 加白名单。
#   ⇒ 背书必须**对得上字段**：改 zones 要有 zones 的背书，改 workspaces 要有
#     workspaces 的背书。
#
# ★ 为什么还要一个**时间窗回看**（不能只看"本拍新到的记录"）：
#   CLI 是「先写链、后同步 state」，链记录在本拍被消费掉，下一拍 state 才变
#   ⇒ 只看本拍必然误判。回看窗口把这段时序差覆盖掉。
#   残差（诚实登记）：回看窗内的**同字段**二次修改会被一起采纳。收紧方向是
#   把"链记录里的内容"与"state 的新值"逐字比对，但那要求链记录带上结构化
#   新值（属于链 schema 变更，另案）。当前窗口 120s，且高风险的 workspaces
#   背书只能由**交互终端里人本人**跑 unlock/decide 产生（Agent 非 TTY 被拒）。
_FP_KEY_FIELD = {"w": "workspaces", "z": "zones", "win": "windows"}
_BACKING_WINDOW = 120.0

#: 能做背书的记录类型（**唯一真源**）。前置过滤必须是它的真超集，
#: 由 `ci/inbox_guards.py::c_chain_prefilter_superset` 守卫（漏放＝整类事件消失）。
_BACKING_TYPES = ("host_shield_changed", "policy_changed",
                  "host_shield_window_closed")
#: 便宜前置过滤的标记串。**只放行、不判定** —— 真判定一律走 `_backing_field()`
#: 的结构化字段。这两个串必须覆盖 `_BACKING_TYPES` 的每一种（见上面的守卫）。
_PREFILTER_MARKERS = ('"host_shield_', '"policy_changed"')


def _prefilter_ok(line):
    """便宜前置过滤：只把**可能**相关的行放进去做结构化判定。

    ★ 宁可多放，不可漏放 —— 漏放一类记录，那一类事件就整类消失（0.35.3 的真缺陷）。
    """
    for m in _PREFILTER_MARKERS:
        if m in line:
            return True
    return False


def _backing_field(rec):
    """这条链记录授权了 state 的哪个安全字段？没有 ⇒ None。

    ★★ 只认**结构化字段**（type / field），绝不认文案子串。
    """
    t = rec.get("type")
    f = str(rec.get("field") or "")
    if t == "policy_changed":
        return f if f in ("zones", "workspaces", "windows") else None
    if t == "host_shield_changed":
        if f.startswith("workspace"):
            return "workspaces"
        if f.startswith("window"):
            return "windows"
        return f if f in ("zones", "workspaces", "windows") else None
    if t == "host_shield_window_closed":
        return "windows"
    return None


def _ts_age(ts, now=None):
    """ISO ts 距现在多少秒；解析不了 ⇒ None。"""
    if not ts:
        return None
    try:
        t = datetime.fromisoformat(str(ts))
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.astimezone()
    return (now if now is not None else time.time()) - t.timestamp()


def _backing_fields_of(recs, window=_BACKING_WINDOW, now=None):
    """记录列表 → 其中**在时间窗内**的背书字段集合。

    ★ 时间窗必须在这里也过一遍：`_ChainTail` 在 reset（换日/重启）时会一次性
      吐出**当日全部**记录，若不做时效过滤，今天早上一条合法 zones 变更会替
      今天下午的任意 zones 篡改背书。
    """
    out = set()
    now = time.time() if now is None else now
    for rec in recs or ():
        fld = _backing_field(rec)
        if not fld or fld in out:
            continue
        age = _ts_age(rec.get("ts"), now)
        if age is not None and -60 <= age <= window:
            out.add(fld)
    return out


def chain_backing_fields(audit_dir, window=_BACKING_WINDOW, max_files=3):
    """最近 window 秒内，链上**授权过**的安全字段集合（zones/workspaces/windows）。

    ★★ 为什么读**两个**目录（0.35.3，盘上证据）：门闸记录此前散在三个地方 ——
      哨兵自己写的在 `<包根>/.psl/audit/`，CLI 的 `unlock`/`decide` 写的在
      `~/.antinel/rollup/`，策略改写 `policy_changed` 在 `<项目根>/.psl/audit/`。
      哨兵的背书判定若只看自己那一条，**另外两条里的授权它一条也看不见**。
      这里补上个人中枢 rollup（`unlock`/`decide` 的落点）；
      `zone add/remove` 的授权记录由 `antinel._sync_zone_state()` 直接写进哨兵自己的链。

    ★ 只读最近 max_files 天；解析不出的行跳过（跳过≠没有，由调用方按"没有背书"
      走保守分支 —— 保守分支是**判篡改**，方向是收紧，不会放跑）。
    """
    dirs = []
    for d in (audit_dir, _hub_rollup_dir()):
        d = d or _hub_rollup_dir()
        nd = os.path.normpath(d)
        if nd not in dirs:
            dirs.append(nd)
    recs = []
    for d in dirs:
        try:
            names = sorted((f for f in os.listdir(d) if f.endswith(".jsonl")),
                           reverse=True)[:max_files]
        except OSError:
            continue
        for name in names:
            try:
                with open(os.path.join(d, name), "r", encoding="utf-8",
                          errors="replace") as f:
                    for line in f:
                        if not _prefilter_ok(line):
                            continue
                        try:
                            recs.append(json.loads(line))
                        except Exception:
                            continue
            except OSError:
                continue
    return _backing_fields_of(recs, window=window)


def _fp_changed_fields(fp_old, fp_new):
    """两个指纹之间**哪些字段变了**（返回 state 字段名集合）。"""
    try:
        a, b = json.loads(fp_old or "{}"), json.loads(fp_new or "{}")
    except Exception:
        return set(_FP_KEY_FIELD.values())      # 解析不了 ⇒ 当作"全都变了"
    return {_FP_KEY_FIELD[k] for k in _FP_KEY_FIELD if a.get(k) != b.get(k)}


def _state_guard_step(fp2, fp, last_good, grace, state, backed_now, audit_dir,
                      armed, changed_txt=""):
    """state 安全字段守卫的**唯一实现**（从 `run_sentinel` 内联块提取，行为等价）。

    返回 `(fp, last_good, grace, state, tamper_reason)`：
      · tamper_reason 非空 ⇒ 调用方须写 `host_shield_tamper` 记录，
        并且本函数**已经**把 state 回写成 last_good（返回的 state 就是回写后的）。
      · backed_now：本拍链上看到的背书字段集合（由调用方从 `recs` 算）。
    """
    if fp2 == fp:
        return fp2, json.loads(json.dumps(state)), 0, state, ""

    need = _fp_changed_fields(fp, fp2)
    have = set(backed_now or ())
    if not need <= have:
        have |= chain_backing_fields(audit_dir)     # 回看窗口（覆盖 CLI 写入时序差）
    if need and need <= have:
        return fp2, json.loads(json.dumps(state)), 0, state, ""

    grace += 1
    if grace < 2:
        # 宽限期内按基线执法（不采纳未背书的变化）
        st = json.loads(json.dumps(last_good))
        st["enabled"] = armed
        return fp, last_good, grace, st, ""

    reason = ("state 文件的 %s 在无链背书下被修改%s，已回写恢复"
              "（疑似加白名单/开窗绕过）"
              % ("/".join(sorted(need)) or "workspaces/zones/windows",
                 changed_txt))
    st = json.loads(json.dumps(last_good))
    st["enabled"] = armed
    return _state_fp(last_good), last_good, 0, st, reason


def _fp_diff_txt(fp_old, fp_new, limit=120):
    """把"哪个字段从什么变成什么"写成一句话（供 tamper 记录诊断用）。

    ★ 为什么要有它：旧记录的 reason 只说"workspaces/zones/windows 被修改"，
      **不说改了哪个、改成什么** ⇒ 事后无法定位真因（2026-10-06 就是靠翻
      全链邻居记录才认出来是"改 state 的两个入口写的不是 host_shield_* 类型"）。
    """
    try:
        a, b = json.loads(fp_old or "{}"), json.loads(fp_new or "{}")
    except Exception:
        return ""
    parts = []
    for k, fld in _FP_KEY_FIELD.items():
        if a.get(k) != b.get(k):
            parts.append("%s %s → %s" % (fld, a.get(k), b.get(k)))
    return ("（" + "；".join(parts) + "）")[:limit] if parts else ""


class _ChainTail(object):
    """增量跟读当日链文件：sentinel 每轮取新增记录（changed→armed 更新；
    执法证据→armed=True）。换日/文件变小→全量重扫（由调用方做 chain_armed_scan）。

    ★ 0.35.3：前置过滤改 `_prefilter_ok()`（含 policy_changed），
      并把"有背书"从 `type == host_shield_changed` 放宽到 `_backing_field()`
      **按字段**判定 —— 见本文件「链背书」段的说明。
    """

    def __init__(self, audit_dir):
        self.audit_dir = audit_dir
        self.day = None
        self.size = 0

    def new_records(self):
        """返回 (records, saw_changed, reset)。reset=True 表示发生过换日/截断，
        调用方应全量重扫 chain_armed_scan。reset 时 saw_changed=True（给指纹
        宽限：跨午夜落在昨日文件里的 changed 记录不应触发误回写）。

        saw_changed 现在是**按字段**算的（`_backing_field`），调用方若需要
        精确字段集合，请自己遍历 records 调 `_backing_field()`。
        """
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
                if not _prefilter_ok(line):
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                recs.append(rec)
                if _backing_field(rec):
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
            # ★★ 0.35.3 修（真缺陷，创始人报障「右下又在冒泡」）：
            #   旧代码写 `heartbeat_age(audit_dir)` —— 而 `heartbeat_age` 的入参是
            #   **包根**。传审计目录 ⇒ 回退到中枢 rollup ⇒ 读到几小时前的老心跳 ⇒
            #   刚起来的哨兵立刻被判"僵死" ⇒ 杀掉重拉 ⇒ `host_shield_revived` 刷屏
            #   （在弹窗名单里）⇒ 右下角一直冒泡。
            #   实测：同一时刻 `heartbeat_age(pkg_root)`=87s（真），
            #          `heartbeat_age(audit_dir)`=34454s（错）。
            #   ⇒ 直接读**手里这个** audit_dir（`_heartbeat_age_in`），不再绕包根。
            try:
                age = _heartbeat_age_in(audit_dir)[0]
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
                               capture_output=True, timeout=30,
                               creationflags=_CREATE_NO_WINDOW)
                time.sleep(1)
            ok, pid, mode = spawn_sentinel(pkg_root)
            if ok:
                record(audit_dir, "host_shield_revived", decision="allow", severity="critical",
                       reason="哨兵无心跳（%s，疑似挂起/僵死），已强制重启"
                              "（旧 pid=%s，mode=%s）" % (age_txt, old_pid, mode),
                       pid=pid, cause=cause, spawn_mode=mode)
                return "stale-revived"
            record(audit_dir, "host_shield_spawn_failed", decision="deny", severity="critical",
                   subkind="spawn_failed",
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


# ==================== 当前态势（0.35.3：失守＝现在，不是历史）====================
# ★★ 修的是什么（创始人 2026-10-06 拍板）：
#   「是否失守，应该是**当前的状态**；如果当前确实是失守状态，应该有地方可以
#     马上解决问题」。
#   旧口径＝把**历史上攒下来的**未处理项取最高级 ⇒ 8 天前一条已经自愈的记录，
#   让今天永远顶着红灯。后果是"用户看到的都是失守，但又不是真正的事实"——
#   创始人原话：**很快就没人用了，因为太假**。
#   ⇒ 新口径：灯色由**现探**决定，红必须满足「防线**此刻确实不在岗**」。
POSTURE_OFF = "off"             # 未启用（产品第一原则：默认全关）
POSTURE_GUARDING = "guarding"   # 值守中
POSTURE_DOWN = "down"           # 失守：缺岗 **且**有可指认的后果（真损失）
POSTURE_INTERRUPTED = "interrupted"  # 中断：缺岗，但此刻**没有监管对象** ⇒ 无损失
POSTURE_WARN = "warn"           # 在守，但**守门的这份代码我认不出**（可信性存疑）
POSTURE_DEV = "dev"             # 研发态：在守，代码比登记的新 ⇒ 尚未发版（非故障）
POSTURE_UNKNOWN = "unknown"     # 查不到（★ 必须与"没问题"长得不一样）

#: ★★ 姿态**封闭集合**（0.36.3 新增）—— 全部合法姿态，一个不多一个不少。
#:
#: ★ 为什么要有这张清单（创始人 2026-10-07「状态都是计划内的，不允许计划外状态」）：
#:   改造之前，`light()` 用一串 `if` 逐个比对姿态，**最后一条都没有兜底** ⇒
#:   任何没被列进 `if` 的值（打错的、以后新增的、None）都会**穿过全部 if
#:   落到函数末尾**，被当成"当前值守中"⇒ 返回**绿灯**。实测：
#:   `light("banana")` → `ok`，`light(None)` → `ok`。
#:   ⇒ **新增任何一个状态而忘了改 `light()`，UI 会安静地显示"一切正常"。**
#:     这是最坏的形状：**状态机出错时，界面替你撒谎。**
#:   ⇒ 现在改成：**集合外一律落到 `POSTURE_UNKNOWN`（黄灯·盲区）**，
#:     绝不打绿。判据 `c_light_rejects_unknown_posture` 真跑验这条。
POSTURE_ALL = frozenset((
    POSTURE_OFF, POSTURE_GUARDING, POSTURE_DOWN,
    POSTURE_INTERRUPTED, POSTURE_WARN, POSTURE_DEV, POSTURE_UNKNOWN,
))

# ★★ 0.35.3「失守」重定义（创始人 2026-10-06）：
#   「如果现在的『真失守』跟假失守没啥区别，不会带来明显不利后果，
#     那就跟假失守没啥区别。」
#   ⇒ **失守必须说得出损失**。缺岗但无监管对象时，只配叫「中断」——
#     它仍然黄灯、仍然给「马上修复」，但**不许**冒充"防线失守"。
#     红/黄的分界＝`_outage_consequences()` 是否为空（可复算，不是感觉）。
POSTURE_LABEL = {POSTURE_OFF: "未启用", POSTURE_GUARDING: "值守中",
                 POSTURE_DOWN: "失守", POSTURE_INTERRUPTED: "中断·无损失",
                 POSTURE_WARN: "存疑", POSTURE_DEV: "研发中",
                 POSTURE_UNKNOWN: "查不到"}


#: ④ 号后果的扫描上限：受监管落点多到离谱时**不许**把页面拖死（超限只报数不列全）。
_OUTAGE_SCAN_CAP = 200


def _outage_consequences(state, pkg_root=None):
    """门闸**缺岗**这件事，有没有**可指认的后果**。返回清单（空 = 可证明没损失）。

    ★★ 为什么需要它（创始人 2026-10-06 原话）：
      「如果现在的『真失守』跟假失守没啥区别，不会带来明显不利后果，
        那就跟假失守没啥区别。」
      ⇒ **一个说不出损失的"失守"，就是一个假失守。**
      所以缺岗这件事必须先量后果，再决定它是红（失守）还是黄（中断）。

    ★ 后果判据全部来自**盘上/链上可复算的事实**（不是猜）：
      · 放行窗已到期却没关 —— 关窗是哨兵的活，它不在 ⇒ 门还开着（真损失）
      · 有安全区却没人上锁 —— 那些目录此刻可被改（真损失）
      · 有受监管工作区却没人看着 —— 监管中断（真损失）
      · **有受监管落点**（登记表 watch / findings）却没人巡检 —— 哨兵在时会一直
        盯着这些落点、有写入就报；它不在 ⇒ 这段时间**发现不了外传**（本产品的核心职能）
      · **以上都没有** ⇒ 门闸此刻**没有监管对象** ⇒ 缺岗期间不可能"放过什么"
        ⇒ 可指认：**无损失**（这时它只配叫"中断"，不配叫"失守"）

    ★★ 盲区纪律：**查不出落点清单 ⇒ 按"有"算**（红），不许当作"没有"。
      本仓铁律：「查不出来 ≠ 查出来是好的」——把读失败降级成"无损失"就是假失守。

    ★★ 落点一路为什么必须加：本函数第一版只查 state 的 windows/zones/workspaces，
      而 `iter_gate_targets` 遍历的是**全部宿主**登记表 ⇒ 装了 zcode 的机器上，
      `~/.zcode/v2/checkpoints/*/pending` 一直在门闸职责内，只查 state 会**误判
      "无监管对象"**——那就是本仓最恨的「假守卫」：判据漏了一路，还报绿。
    """
    cons = []
    now = time.time()
    # ① 放行窗：到点了却没关 —— 最硬的一条（门确实还开着）
    for p, exp in (state.get("windows") or {}).items():
        try:
            if float(exp) < now:
                cons.append({"kind": "window_open", "text":
                             "放行窗已到期却没关：%s（本该由哨兵关上，此刻门还开着）" % p})
        except (TypeError, ValueError):
            cons.append({"kind": "window_open", "text":
                         "放行窗记录读不出到期时间：%s（读不出 ⇒ 按最坏算）" % p})
    # ② 安全区：有区，但此刻没人上锁
    zs = state.get("zones") or []
    if zs:
        cons.append({"kind": "zone_unlocked", "text":
                     "有 %d 个安全区，此刻没人给它们上锁：%s"
                     % (len(zs), "、".join(str(z) for z in zs[:3]))})
    # ③ 受监管工作区：用户已经裁决过 ⇒ 门闸有在管的对象
    ws = state.get("workspaces") or {}
    if ws:
        cons.append({"kind": "workspace_unwatched", "text":
                     "有 %d 个受监管工作区，此刻没人看着它们" % len(ws)})
    # ④ 受监管落点：登记表 watch + findings —— 本产品的核心职能就是盯这些落点。
    try:
        root = pkg_root or os.path.dirname(os.path.abspath(__file__))
        base_line = state.get("lock_mtime_baseline") or {}

        def _scan():
            cands, evid = [], 0
            for base, lock_dirs, _gate, _src in iter_gate_targets(root):
                if not base or not os.path.isdir(base):
                    continue
                for dirpath, dirnames, _f in os.walk(base):
                    for dn in dirnames:
                        t = os.path.join(dirpath, dn)
                        if os.path.basename(t).lower() not in lock_dirs:
                            continue
                        cands.append(t)
                        if _has_write_evidence(t, base_line):
                            evid += 1
                        if len(cands) >= _OUTAGE_SCAN_CAP:
                            return cands, evid
            return cands, evid

        cands, evid = _scan()
        if cands:
            cons.append({"kind": "landing_unwatched", "text":
                         "有 %d 个受监管落点，此刻没人巡检（哨兵在时会一直盯着它们、"
                         "有写入就报）%s"
                         % (len(cands), ("；其中 %d 个相对上次记录有变动" % evid) if evid else "")})
    except Exception as e:                                   # noqa: BLE001
        cons.append({"kind": "landing_unknown", "text":
                     "查不出受监管落点清单（%s）——这是**盲区**，不能当作「没有」"
                     % type(e).__name__})
    return cons


def guard_posture(pkg_root=None):
    """**现探**当前态势。返回 dict（页面只排版，判定全在这里）。

    字段：`state` / `label` / `why` / `evidence` / `can_fix` / `fix` / `fix_hint`。

    ★ 判定规则（五条，缺一不可）：
      ① `armed`（链权威）为假 ⇒ **未启用**。这不是"失守" —— 默认全关是产品第一
         原则，把"没开"渲染成"坏了"会把红灯变成噪音。
      ② armed 且哨兵进程在岗、心跳新鲜、自检通过 ⇒ **值守中**。
      ③ armed 且哨兵在岗、心跳新鲜，但**自检不符** ⇒ **存疑（黄）**。
         "我认不出守门的是不是出厂那份" ≠ "此刻没在守"（查不出来 ≠ 查出来是坏的）。
      ④ armed 但哨兵不在岗 / 心跳断档超 `_STALE_AFTER` ⇒ 按后果分两档：
         · 有可指认的后果（`_outage_consequences` 非空）⇒ **失守（红）**
         · 无任何监管对象 ⇒ **中断·无损失（黄）**（★ 说不出损失的失守＝假失守）
      ⑤ 任一探针抛错 ⇒ **查不到**（绝不返回"值守中"——把盲区读成清白是本仓
         明令禁止的形状）。
    """
    try:
        st = load_state()
        audit_dir = _shield_audit_dir(pkg_root)
        armed = armed_state(audit_dir, st)
        if not armed:
            return {"state": POSTURE_OFF, "label": POSTURE_LABEL[POSTURE_OFF],
                    "why": "护盾默认关闭。开启后才会拦、才会记账。",
                    "evidence": {"armed": False}, "can_fix": False, "fix": None,
                    # ★ 0.35.3：**不给按钮**。开启要装一个开机自启任务（要管理员权限），
                    #   值守台点一下**做不到** —— 给个点了没用的按钮，就是"假按钮"
                    #   （创始人最恨的形状）。所以只如实说"去哪儿开"。
                    "fix_hint": "要开启，在终端执行一次：antinel host-shield enable"
                                "（需要管理员权限；装一次后开机自启）"}
        alive = bool(sentinel_alive(st))
        # ★★ 0.35.3 修（本机实测）：原来这里写 `heartbeat_age(pkg_root)`。
        #   页面调用 `guard_posture()` **不传参** ⇒ `pkg_root=None`
        #   ⇒ `_shield_audit_dir(None)` ⇒ 走**中枢 rollup**（实测最后心跳停在 09-29）。
        #   而哨兵写的是**包审计**（`_shield_audit_dir(_pkg_root())`）。
        #   本机实测同一时刻：`sentinel_heartbeat_age()` = **160 秒**（哨兵好好的），
        #   `heartbeat_age(None)` = **27202 秒**（读到 7 天前的老链）。
        #   ⇒ 页面因此长期显示「心跳断档 452 分钟 · 疑似挂起/僵死」并把灯打红，
        #     而**哨兵一直是好的**；页面还给出「马上修复」按钮，一点就撞上
        #     `spawn_sentinel` 的 `already-running` 幂等 ⇒ 点了没反应。
        #   这与本文件已记的 0.35.3 那条是**同一类错**（包根/审计目录搞混），
        #   只是漏了 `guard_posture` 这个调用点 —— 修法仍是同一条纪律：
        #   **消灭副本**，报心跳一律走 `sentinel_heartbeat_age()`。
        age, last_ts = sentinel_heartbeat_age()
        uptime = _sentinel_uptime(st)
        ok_self, problems = self_check()
        fresh = ((age is not None and age <= _STALE_AFTER)
                 or (age is None and uptime is not None and uptime <= _STALE_AFTER))
        ev = {"armed": True, "sentinel_alive": alive,
              "heartbeat_age": (round(age, 1) if age is not None else None),
              "heartbeat_ts": last_ts,
              "sentinel_uptime": (round(uptime, 1) if uptime is not None else None),
              "sentinel_pid": st.get("sentinel_pid"),
              "self_check_ok": ok_self,
              # 技术细节留在 evidence 里供诊断（页面上只说大白话）
              "self_check_problems": list(problems)}
        _code_untrusted = not ok_self
        if alive and fresh:
            if _code_untrusted:
                # ★★★ 0.36.3：**先问"这是不是研发态"**，再谈"存疑"。
                #   实测本机：登记 0.33.1／代码 0.36.3 ⇒ 自检必然不符 ⇒
                #   原实现长期挂「存疑」。但研发期**不存在"出厂"**，
                #   拿"是不是出厂那份"质疑正在迭代的代码是**范畴错误**。
                #   ⇒ 研发态单独一档（不点红灯、也不谎称"值守中"）。
                _is_dev, _dev_why = is_dev_build()
                if _is_dev:
                    # ★★★ 0.36.4 三处收紧（全部由实测定型，不是设计偏好）：
                    #
                    # ① **不再返回空 `consequences`**（实测 `_p_dev_mask_probe.py`）。
                    #    原实现 `"consequences": []` 是**硬编码的空**——它与
                    #    "量过了，确实没有后果"**长得一模一样**，而后者是可复算的事实、
                    #    前者是我偷懒写死的。消费方无法区分，且一旦哨兵真发现状况，
                    #    这个空列表会**把状况藏起来**。
                    #    ⇒ 现在照走 `_outage_consequences()`，和下面缺岗分支同一口径。
                    #
                    # ② **文案不再说"属正常"**（F55：对外强度 ≤ 内部最保守定性）。
                    #    研发态**不代表**没有故障：哨兵发现状况时该报的照报
                    #    （`inbox_model.light()` 侧已修：dev 不再吞掉 24 小时后果账，
                    #    实测 dev + 两件 R0 ⇒ `attention` 橙灯，不再是 `dev` 蓝灯）。
                    #
                    # ③ **收敛写成机制**（创始人「过很短的时间要变成值守中」）：
                    #    收敛靠**发版**（登记版本追平），不靠时间自己好 ——
                    #    靠时间就是撒谎（代码仍不符却报正常）。实测已验证：
                    #    登记追平 ⇒ dev 立刻消失，无需人工动作。
                    #
                    #    ★★ 但**不给修复按钮**（`can_fix=False`），这是**实测查出来的**：
                    #      我第一版写了 `can_fix=bool(_cons)` + `fix="fix-posture"`，
                    #      随后查消费方 `inbox_server.py:450` 发现——全仓 `fix` 只有
                    #      **一个**合法值 `"revive"`（重新拉起哨兵），
                    #      `"fix-posture"` **根本不存在** ⇒ 按钮点了没有动作，
                    #      正是创始人最恨的形状：**假按钮**。
                    #      而且更根本：dev 态下哨兵**正在正常放哨**（`alive and fresh`
                    #      是进入本分支的前提）⇒ 给它"重新拉起"按钮本身就没意义 ——
                    #      点它等于把一个健康进程杀掉再拉起来。
                    #      ⇒ 正确的做法：**报后果，不给假动作**。
                    #        真需要动作时，24 小时后果账那一层（`inbox_model.light()`
                    #        已修：dev 不再吞掉它）会显示橙灯并指向具体事项。
                    _cons = _outage_consequences(st, pkg_root)
                    return {"state": POSTURE_DEV, "label": POSTURE_LABEL[POSTURE_DEV],
                            "why": "研发迭代中：这一版还没发出去，"
                                   "守门代码与上次登记的不一致是改出来的，不是被改的。"
                                   "哨兵仍在正常放哨；它发现状况时该报的一样会报。",
                            "evidence": ev, "consequences": _cons,
                            "can_fix": False, "fix": None,
                            "fix_hint": ("正在开发中。这一版发出去之后会自动回到"
                                         "「值守中」——不需要你手动做什么。"
                                         if not _cons else
                                         "正在开发中；下面这些是哨兵实际发现的，"
                                         "按它们各自的提示处理即可。"),
                            "dev_why": _dev_why}
                # ★★ 0.35.3：**在守，但身份存疑 ⇒ 单独一档（黄），不点红灯。**
                #   "我认不出守门的是不是出厂那份" ≠ "此刻没在守"。
                #   本仓纪律：**查不出来 ≠ 查出来是坏的**；把"认不出"渲染成"失守"，
                #   就是创始人说的"跟假失守没区别"—— 红灯很快就没人看了。
                #   ★ 绝不为了消红灯而放松自检：自检照旧跑、照旧报，只是**换了档位**。
                return {"state": POSTURE_WARN, "label": POSTURE_LABEL[POSTURE_WARN],
                        "why": "哨兵在岗，但这份守门的代码我认不出是不是出厂那份"
                               "——可能被改动过，也可能是这次没装好。",
                        "evidence": ev, "consequences": [], "can_fix": False,
                        "fix": None,
                        "fix_hint": "就地核对不了：请重新安装当前版本"
                                    "（重装会自动重新登记，装完这里就恢复）。"}
            return {"state": POSTURE_GUARDING,
                    "label": POSTURE_LABEL[POSTURE_GUARDING],
                    # ★ 0.36.1 文字修订（创始人截图一「出现一些类似英文变量的词」）：
                    #   删掉 `（pid %s）` —— 进程号是**实现细节**，
                    #   用户既看不懂也不能拿它做任何事，纯属噪音。
                    #   它仍然留在 `evidence` 里（要查的人查得到）。
                    "why": "哨兵在岗，最后心跳 %s"
                           % ((("%.0f 分钟前" % (age / 60.0)) if age is not None
                               else "刚布防（首拍未到）")),
                    "evidence": ev, "consequences": [], "can_fix": False,
                    "fix": None, "fix_hint": ""}
        # ★★ 缺岗：**先量后果，再决定它是红（失守）还是黄（中断·无损失）**。
        #   红必须说得出损失；说不出 ⇒ 不许冒充"防线失守"（创始人 2026-10-06）。
        cons = _outage_consequences(st, pkg_root)
        if not alive:
            why = "护盾开着，但哨兵进程不在岗——门闸此刻没人守。"
        else:
            why = ("护盾开着，哨兵进程在，但心跳断档 %s（应 ≤10 分钟）——疑似挂起/僵死。"
                   % (("%.0f 分钟" % (age / 60.0)) if age is not None else "（查不到心跳）"))
        if _code_untrusted:
            why += " 另外，这份守门的代码我也认不出是不是出厂那份。"
        if not cons:
            # ★ 缺岗但**没有任何监管对象** ⇒ 缺岗期间不可能放过什么 ⇒ 只叫「中断」。
            #   仍然黄灯、仍然给「马上修复」——**不隐藏**，只是不冒称"失守"。
            return {"state": POSTURE_INTERRUPTED,
                    "label": POSTURE_LABEL[POSTURE_INTERRUPTED],
                    "why": why + " 不过此刻门闸**没有监管对象**"
                                 "（无放行窗、无安全区、无受监管工作区、无受监管落点），"
                                 "所以这段时间没有放过任何东西。",
                    "evidence": ev, "consequences": [], "can_fix": True,
                    "fix": "revive", "fix_hint": "马上修复（重新拉起哨兵）"}
        return {"state": POSTURE_DOWN, "label": POSTURE_LABEL[POSTURE_DOWN],
                "why": why, "evidence": ev, "consequences": cons,
                "can_fix": True, "fix": "revive",
                "fix_hint": "马上修复（重新拉起哨兵）"}
    except Exception as e:                                   # noqa: BLE001
        return {"state": POSTURE_UNKNOWN, "label": POSTURE_LABEL[POSTURE_UNKNOWN],
                "why": "探不到门闸状态：%r" % (e,), "evidence": {},
                "consequences": None, "can_fix": False, "fix": None,
                "fix_hint": "这是**盲区**，不等于「没问题」"}


def guard_fix(pkg_root=None, action=None):
    """就地修好当前态势（值守台上那个"马上修复"按钮的落地）。

    返回 `(ok, msg)`。★ 修不了就**如实说修不了**，不许回一个"已修复"。
    """
    try:
        p = guard_posture(pkg_root)
        action = action or p.get("fix")
        if action == "revive":
            r = ensure_alive(pkg_root, cause="console")
            if r in ("revived", "stale-revived", "alive"):
                p2 = guard_posture(pkg_root)
                return (p2["state"] == POSTURE_GUARDING,
                        "已重新拉起哨兵（%s）——%s" % (r, p2["why"]))
            return False, "没拉起来（%s）——门闸仍无人值守，请看运行状态页" % (r,)
        if action == "enable":
            return False, ("开启值守要写 ACL 与自启项，请在终端由你本人执行："
                           "antinel host-shield enable")
        return False, "当前态势没有可就地修复的动作（%s）" % (p.get("why") or "")
    except Exception as e:                                   # noqa: BLE001
        return False, "修复动作出错：%r" % (e,)


def _heartbeat_age_in(d):
    """(age_seconds|None, last_ts|None)：**按审计目录**算心跳年龄（唯一实现）。

    ★★ 0.35.3 拆出来的原因（真缺陷，创始人报障「右下又在冒泡」）：
      此前 `heartbeat_age(pkg_root)` 是本函数**唯一**入口，参数语义是"包根"。
      而 `ensure_alive` 里写成 `heartbeat_age(audit_dir)` —— 把**审计目录**当包根传。
      于是 `_shield_audit_dir(<audit>)` 在 `<audit>/.psl` 找不到东西 ⇒ **回退到
      中枢 rollup** ⇒ 读到的是几小时前的老心跳。
      本机实测（同一时刻）：`heartbeat_age(pkg_root)` = **87 秒**（真），
      `heartbeat_age(audit_dir)` = **34454 秒**（错）。
      后果：刚起来的哨兵立刻被判"僵死（574 分钟前）" ⇒ **杀掉重拉** ⇒ 每次重拉都发
      `host_shield_revived`（在 `_ALERT_KINDS` 弹窗名单里）⇒ **右下角一直冒泡**。
      ⇒ 修法＝**消灭副本**：心跳读取只此一处、入参就是审计目录（没有"包根还是目录"
      这个二义性）；`heartbeat_age(pkg_root)` 退化成它的包装。
    """
    best_ts = None
    try:
        files = sorted((f for f in os.listdir(d) if f.endswith(".jsonl")), reverse=True)[:3]
    except OSError:
        files = []
    for name in files:
        try:
            with open(os.path.join(d, name), "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not _prefilter_ok(line):
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


def heartbeat_age(pkg_root=None):
    """(age_seconds|None, last_ts|None)：最近一条 host_shield_* 记录的年龄。

    ★ 入参是**包根**（不是审计目录）。跨进程只能用墙钟（记录 ts 是墙钟）。
    ★ 手上已经有审计目录时，请直接调 `_heartbeat_age_in(audit_dir)` —— 别再让
      包根/目录在这里互相冒充（0.35.3 那个重启死循环就是这么来的）。
    """
    return _heartbeat_age_in(_shield_audit_dir(pkg_root))


def sentinel_audit_dir():
    """哨兵**实际写入**的那条链的目录（唯一口径）。

    ★★ 为什么需要它（**真缺陷**，本机实测 2026-10-06）：
      哨兵由 `spawn_sentinel(_pkg_root())` 拉起，`run_sentinel(root)` 写的是
      `_shield_audit_dir(root)`。本包根带 `.psl` ⇒ 写**包审计**
      （实测 22:05 还在写心跳）。
      而 `antinel host-shield status` 调的是 `heartbeat_age()`（**无参**）
      ⇒ `_shield_audit_dir(None)` ⇒ **中枢 rollup**（停 09-29）
      ⇒ 把 21:05 起活着、心跳正常的哨兵报成「最后心跳 693 分钟前」。
      这与 0.35.3 修过的那条是**同一类错**（把"包根/审计目录"搞混 ⇒ 读老心跳 ⇒
      误判僵死 ⇒ 重拉 ⇒ 冒泡），只是换了个调用点。
      ⇒ 修法同一条纪律：**消灭副本** —— 报心跳的地方一律用这个目录。
    """
    return _shield_audit_dir(_pkg_root())


def sentinel_heartbeat_age():
    """哨兵心跳年龄 `(age_seconds|None, last_ts|None)` —— **唯一口径**。

    在 `sentinel_audit_dir()`（哨兵真正写的那条链）上算。
    ★ 报心跳一律用它，**不许**再用无参 `heartbeat_age()`（那会走中枢 rollup）。
    """
    return _heartbeat_age_in(sentinel_audit_dir())


# ------------------------------------------------------- 哨兵主循环 ----
_BREACH_TIMES = []                               # 拉锯判定滑动窗（B6，monotonic）
_DIVERGE_LAST = [0.0]                            # enabled 发散 tamper 的上报节流（wall）


def _task_watchdog(state, audit_dir, now):
    """#6 任务哨卫：登录自启存在性（三态）。返回 touched(bool)。

    ★ 三态（2026-09-24 修复）：True=在 / False=不在 / None=查不出来。
      "查不出来"与"查到了是坏的"是两件事。

    ★★ 0.35.3：**同一条事实不许每 5 分钟记一次**（创始人报障「右下一直冒泡」）。
      原实现：`_ti is False` 时**每次巡视**都 record 一条**完全相同**的 breach
      ⇒ 一天 288 条同样的链记录 ＋ 每 30 分钟一次弹窗，**永远不停**。
      这正是本仓明令禁止的「长期红的守卫＝没守卫」——红灯很快就没人看了。
      改法（**不隐藏，只降噪**，与 `lock_attempts`「同一落点只在首次留痕」同一形状）：
        · 状态**转变**（在→不在）⇒ 立刻留痕 + 弹窗一次；
        · 状态**持续**不变 ⇒ 不重复留痕，但每 `_TASK_MISSING_REANNOUNCE`
          再提醒一次（免得"没声了"被读成"好了"）；
        · 状态本身在值守台常驻显示（`guard_posture` / 运行状态页），**不隐藏**。
    """
    _ti = task_installed()
    _prev_ti = state.get("_task_installed_last", "unset")
    state["_task_installed_last"] = _ti
    if _ti is True:
        return False
    # ★★ 0.35.3：**False（确定没有）与 None（查不出来）都要降噪** ——
    #   同一条事实不许每 5 分钟记一次。旧版 `None` 分支**没有去重**
    #   （每次巡视无条件 record）⇒ schtasks 被拦的机器上一天 288 条
    #   `host_shield_task_unknown`。两个分支现在共用同一套「转变 or 超期」判定。
    _key = "_task_missing_announced_at" if _ti is False else "_task_unknown_announced_at"
    try:
        _last_ann = float(state.get(_key) or 0)
    except (TypeError, ValueError):
        _last_ann = 0.0
    if _prev_ti is _ti and (now - _last_ann) < _TASK_MISSING_REANNOUNCE:
        return False                          # 状态没变、也没到再提醒点 ⇒ 安静
    state[_key] = now
    if _ti is False:
        record(audit_dir, "host_shield_breach", decision="deny",
               severity="warning", subkind="autostart_missing",
               reason="登录自启缺失（计划任务与启动文件夹均无）"
                      "——哨兵不会随登录自启（#6）")
    else:
        record(audit_dir, "host_shield_task_unknown", decision="alert",
               severity="warning", subkind="task_unknown",
               reason="无法确认自启状态（schtasks 不可用或被策略拦截）"
                      "——门闸是否随登录自启，这台电脑查不出来（#6）")
    return True


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
        if _task_watchdog(state, audit_dir, now):
            touched = True
        save_state(state)
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
                    elif _sha_hex(_cur) != _sha_hex(_reg.get("sha256")):
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

    ★ 三态：True=在 / False=不在 / None=查不出来。

    ★★ 0.35.3 修（**真缺陷**，本机实测 2026-10-06）：
      旧版**先**跑 `schtasks /Query`，**异常就 `return None`** ⇒ 启动文件夹那条
      回退**永远到不了** —— 0.28.2 写下的意图（"schtasks 被拦时回退到启动文件夹
      shim"）在代码里是**死代码**。
      本机实测：`schtasks.exe` 被程序黑名单拦死（`PermissionError`）
      ⇒ `task_installed()` **恒为 None** ⇒ 哨兵每次都记 `host_shield_task_unknown`、
      「自启缺失」这条检测在本机**永远不会响**（＝假守卫）；而启动项明明就在那儿
      （实测 `state.autostart=startup-folder` 且文件存在）。
      ⇒ 修法：**文件系统事实优先**（启动项在就是在，不必问 schtasks）；
        schtasks 只是补充证据；两者都查不出来才回 None。
    """
    shim = None
    try:
        appdata = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        shim = os.path.join(appdata, "Microsoft", "Windows",
                            "Start Menu", "Programs", "Startup",
                            "antinel-shield.cmd")
        if os.path.isfile(shim):
            return True                      # ★ 文件系统事实优先：在就是在
    except Exception:                                                # noqa: BLE001
        shim = None
    try:
        if subprocess.run([_SCHTASKS, "/Query", "/TN", "AntinelHostShield"],
                          capture_output=True, timeout=20,
                          creationflags=_CREATE_NO_WINDOW).returncode == 0:
            return True
    except Exception:
        # schtasks 起不来、启动项也不在 ⇒ **无法确认**（≠"确定没有"），如实上抛未知
        return None
    return False                             # schtasks 能查、说没有，启动项也没有


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
               field="self-check", subkind="self_check",
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
            #    ★ 0.35.3：判定与回写全部走 `_state_guard_step()`（唯一实现，
            #      可单测；旧版内联在这里，谁都测不到 —— 这正是 12 条假失守
            #      能悄悄上线的结构原因）。
            fp2 = _state_fp(state)
            if fp2 != fp:
                _backed_now = _backing_fields_of(recs)
                fp, last_good, grace, state, _tamper = _state_guard_step(
                    fp2, fp, last_good, grace, state, _backed_now, audit_dir,
                    armed, _fp_diff_txt(fp, fp2))
                if _tamper:
                    record(audit_dir, "host_shield_tamper", decision="deny",
                           severity="critical", field="state", reason=_tamper,
                           recovered=True)
                    save_state(state)
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
