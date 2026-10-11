# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel · 机器唯一码（machine identity）

★ 定位（创始人 2026-10-09 交办）：
    「刚开始没有开放注册 ⇒ 先与**机器**绑定；等开放注册后，再跟**用户**绑定。」
  因此本模块是 **Phase 1 的绑定键**：它只回答一件事——
    「**这台机器是哪一台**」，
  不回答「这是谁」。账号绑定是 Phase 2 的事，本模块**不引入任何用户概念**。

★ 三层结构（必须分清，混了就会丢余额）
    ┌─ 层 1 · install uuid ── 随机 uuid4，首次运行生成，存 `~/.antinel/machine.json`
    │    作用：**认"这份安装"**。稳定、唯一、离线可算、不泄露任何硬件信息。
    │    ⇒ `uid` 与 `code` **只由 uuid + salt 决定**（★ 不含硬件指纹）。
    │      ★ 为什么不含：硬件一变（换主板/重装系统）就会换 uid，**余额会凭空归零**。
    │        绑定键必须"人不变则键不变"，硬件指纹不是这个角色。
    ├─ 层 2 · 硬件指纹 ── 从若干稳定源派生，**只存摘要，不存原文**
    │    作用：**认"这台机器"**。唯一用途＝发现「machine.json 被复制到别的机器」。
    └─ 层 3 · 校验 ── uuid 与指纹**两者都吻合**才算同机；指纹失配 ⇒ 报"疑似迁移"，**降级处理而非封禁**

★ 硬约束（照抄即可，别改）
    1. **纯标准库**（`winreg`/`ctypes`/`hashlib`/`secrets`）——不起子进程、不要管理员、不联网。
       理由：要快（进程启动即算）、要稳（子进程可能被策略禁）、要能在沙箱里跑。
       ⇒ 因此**不用** `wmic`／PowerShell CIM／`ioreg`（都要起子进程）。
    2. **不上传、不落盘任何原始硬件值**。注册表 MachineGuid、卷序列号等**只进哈希，不出本函数**。
       本模块自己也**不联网**；即便将来上报，报出去的也只是 `uid`/`code`。
    3. **失败必须可降级**：某个源读不到 ⇒ 跳过它，**不退化为报错**，只用剩下的源算。
       全部读不到 ⇒ 仅靠 uuid 也能给出稳定的 `code`（此时"复制检测"能力为 0，如实标注）。

★ 与既有模块的关系
    - `hub.py`：per-user 的 `~/.antinel/`（registry/rollup）。本模块**住同一个 hub 目录**，
      但**不是** per-user——它是 per-machine。二者**不合并**。
    - `ledger.py`：值守台本地账本。`granary.py`（粮，待建）将用本模块的 `code` 作记账键。
    - ⚠️ 与 `antinel credits` **无关**：那个记的是**宿主 AI 工具**烧的积分，是另一本账。

★ Phase 边界（不藏）
    - **Phase 1（现在，未开放注册）**：本模块只作**本地记账键**。此时复制 `machine.json`
      没有实际收益（粮纯本地），故**不需要防伪**；本模块只保证「稳定 + 唯一 + 离线」。
    - **Phase 2（开放注册后）**：`code` 升为**服务端绑定键**，那时才需要
      ① 指纹软绑定（本模块已备）② 账号绑定（`code → account`）③ 反刷量（同指纹簇限流）。

stdlib only, no network, no subprocess. Python 3.10+.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import time
import uuid

SCHEMA = 1
_HUB_ENV = "ANTINEL_HUB_DIR"
FILE_NAME = "machine.json"

# ---------------------------------------------------------------- 硬件源表 ----
# (源名, 权重, 说明)。权重只用于"是不是同一台机器"的加权比对；
# ★ 权重设计的判据：**越稳定、越唯一、越难伪造 ⇒ 越高**。
#   machine_guid  = 装 Windows 时生成，重装系统才变，且全球唯一 ⇒ 3
#   os_machine_id = Linux 的 /etc/machine-id，同级稳定            ⇒ 3
#   volume_serial = 系统盘卷序列号，格式化即变                     ⇒ 2
#   hostname      = 用户可随时改，且同名极多 ⇒ 只作**弱证据**      ⇒ 1
SOURCES = (
    ("machine_guid", 3.0, "Windows 装机 GUID（注册表，纯 stdlib）"),
    ("os_machine_id", 3.0, "Linux /etc/machine-id"),
    ("volume_serial", 2.0, "系统盘卷序列号（ctypes，纯 stdlib）"),
    ("hostname", 1.0, "主机名（弱证据）"),
)
_WEIGHT = {name: w for name, w, _ in SOURCES}

# 判定阈值（按加权命中率）。★ 取值理由：见文件头「降级而非封禁」——
# 门槛刻意**偏松**，"疑似"只提示不处罚；宁可漏判一台，不可错判一个人。
SAME_AT = 0.75        # >= 0.75 ⇒ 同一台机器
NEW_AT = 0.25         # <  0.25 ⇒ 换机器；中间 ⇒ 疑似迁移

# 显示用字母表：Crockford Base32（去掉 I/L/O/U，防 0/O、1/I/l 看错）
_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


# ---------------------------------------------------------------- 路径 ----
def hub_dir():
    return os.path.expanduser(os.environ.get(_HUB_ENV) or "~/.antinel")


def machine_path(root=None):
    return os.path.join(root or hub_dir(), FILE_NAME)


# ---------------------------------------------------------------- 归一化 ----
def _norm(v):
    """只留字母数字并转小写。去掉分隔符/空白/大小写差异——
    否则 'ABC-123' 与 'abc123' 会被当成两台机器。"""
    return "".join(ch for ch in str(v).strip().lower() if ch.isalnum())


def _digest(salt, name, raw):
    """单项摘要。★ 加盐 + 加源名，使两份不同机器的同值项也不可跨机比对。
    返回 32 位十六进制（128 bit），**不可反推原文**。"""
    h = hashlib.sha256(("%s|%s|%s" % (salt, name, _norm(raw))).encode("utf-8"))
    return h.hexdigest()[:32]


# ---------------------------------------------------------------- 各源读取 ----
def _read_machine_guid():
    """Windows：HKLM\\SOFTWARE\\Microsoft\\Cryptography 的 MachineGuid。
    ⚠️ 必须带 KEY_WOW64_64KEY：32 位 Python 在 64 位系统上读会被重定向到
    WOW6432Node，可能读不到（本仓实测过同类坑）。"""
    if platform.system() != "Windows":
        return None
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Cryptography", 0,
                           winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        with k:
            v, _ = winreg.QueryValueEx(k, "MachineGuid")
        return v or None
    except Exception:
        return None


def _read_os_machine_id():
    """Linux：/etc/machine-id（回退 /var/lib/dbus/machine-id）。
    ⚠️ 只读，不建、不改——改机器标识要 root，不是我们的权限也不该做。"""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                v = f.read().strip()
            if v:
                return v
        except OSError:
            continue
    return None


def _read_volume_serial():
    """Windows：系统盘卷序列号，走 ctypes 直调 kernel32，**不起子进程**。
    ⚠️ 用 GetVolumeInformationW（宽字符版）；`root` 必须带尾反斜杠，
    否则函数对 'C:' 会去查当前目录所在的卷（经典坑）。"""
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        root = (os.environ.get("SystemDrive") or "C:") + "\\"
        vol = wintypes.DWORD(0)
        maxlen = wintypes.DWORD(0)
        flags = wintypes.DWORD(0)
        fsname = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            root, None, 0, ctypes.byref(vol), ctypes.byref(maxlen),
            ctypes.byref(flags), fsname, 261)
        if not ok:
            return None
        return "%08X" % vol.value
    except Exception:
        return None


def _read_hostname():
    try:
        return platform.node() or None
    except Exception:
        return None


_READERS = {
    "machine_guid": _read_machine_guid,
    "os_machine_id": _read_os_machine_id,
    "volume_serial": _read_volume_serial,
    "hostname": _read_hostname,
}


# ---------------------------------------------------------------- 指纹 ----
def fingerprint(salt=""):
    """本机硬件指纹：{源名: 摘要 或 None}。★ **只返回摘要，永不返回原文。**
    读不到的源记 None（跳过），不抛错。"""
    out = {}
    for name, _w, _d in SOURCES:
        raw = None
        try:
            raw = _READERS[name]()
        except Exception:
            raw = None
        out[name] = _digest(salt, name, raw) if raw else None
    return out


def sources_present(fp):
    return sorted(k for k, v in (fp or {}).items() if v)


# ---------------------------------------------------------------- uid / code ----
def compute_uid(salt, install_uuid):
    """★ 绑定键。**只吃 salt + install_uuid**（不吃硬件指纹，见文件头层 1）。
    ⇒ 硬件更换不换键 ⇒ 余额不丢。"""
    return hashlib.sha256(("antinel-machine-v1|%s|%s" % (salt, install_uuid))
                          .encode("utf-8")).hexdigest()


def _b32(raw_hex, nchars):
    """十六进制 → Crockford Base32（按 5 bit 取，够用即可，不做位流严格打包）。"""
    val = int(raw_hex[:32], 16)
    chars = []
    for _ in range(nchars):
        chars.append(_B32[val & 31])
        val >>= 5
    return "".join(chars)


def machine_code(uid, groups=3, per=5):
    """对外**显示**的机器码，如 `H7K2M-9QX4T-3B8NW`（默认 15 字符 ≈ 75 bit）。
    ★ 用户看得见、报得出、抄不错（Crockford 无易混字符）。"""
    s = _b32(uid, groups * per)
    return "-".join(s[i:i + per] for i in range(0, len(s), per))


# ---------------------------------------------------------------- 落盘 ----
def load(root=None):
    """读 machine.json。文件不存在/损坏 ⇒ 返回 None（由 ensure 生成新的）。"""
    p = machine_path(root)
    try:
        with open(p, "r", encoding="utf-8") as f:
            rec = json.load(f)
        if not isinstance(rec, dict) or not rec.get("uuid") or not rec.get("salt"):
            return None
        return rec
    except (OSError, ValueError):
        return None


def _save(rec, root=None):
    p = machine_path(root)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)          # 原子替换：中途断电不会留半个文件
    return p


def ensure(root=None, now=None):
    """幂等：无则生成、有则**原样返回**（绝不改写 uuid/salt）。
    返回记录；`_path` 标出落盘位置。"""
    rec = load(root)
    if rec:
        return rec
    salt = secrets.token_hex(16)
    install_uuid = str(uuid.uuid4())
    fp = fingerprint(salt)
    rec = {
        "schema": SCHEMA,
        "uuid": install_uuid,
        "salt": salt,
        "uid": compute_uid(salt, install_uuid),
        "code": machine_code(compute_uid(salt, install_uuid)),
        "fp": fp,                       # ★ 只存摘要
        "created_at": now or time.strftime("%Y-%m-%dT%H:%M:%S"),
        "last_seen": now or time.strftime("%Y-%m-%dT%H:%M:%S"),
        "notes": "层1认'这份安装'(uuid/salt)，层2认'这台机器'(fp)。改硬件不会换 uid。",
    }
    _save(rec, root)
    return rec


def touch(root=None, now=None):
    """更新 last_seen（不触碰 uuid/salt/uid）。"""
    rec = load(root)
    if not rec:
        return ensure(root, now=now)
    rec["last_seen"] = now or time.strftime("%Y-%m-%dT%H:%M:%S")
    _save(rec, root)
    return rec


# ---------------------------------------------------------------- 校验 ----
def verify(root=None):
    """返回 (state, detail)。state ∈
        SAME        同机（uuid 吻合 + 指纹吻合）
        MIGRATED    疑似迁移（uuid 吻合但指纹失配 —— 文件可能被复制到别的机器）
        NO_FP       同机但无法校验（本机一个硬件源都读不到）
        NEW         本机无 machine.json（首次，需 ensure）
    ★ 本函数**只判定，不动作**：怎么处置（提示/降级/封禁）由调用方定，
      且 Phase 1 的处置是「提示 + 记一笔」，不是封禁。"""
    rec = load(root)
    if not rec:
        return "NEW", {"reason": "本机尚无 machine.json"}
    cur = fingerprint(rec.get("salt") or "")
    saved = rec.get("fp") or {}
    w_match = w_total = 0.0
    hits = {}
    for name, w, _d in SOURCES:
        a, b = saved.get(name), cur.get(name)
        if not a or not b:
            hits[name] = "n/a"
            continue
        ok = (a == b)
        hits[name] = "match" if ok else "MISS"
        w_total += w
        if ok:
            w_match += w
    if w_total <= 0:
        return "NO_FP", {"hits": hits, "reason": "两轮都读不到同一硬件源，无法校验"}
    ratio = w_match / w_total
    detail = {"hits": hits, "ratio": round(ratio, 3),
              "uuid": rec.get("uuid"), "code": rec.get("code")}
    if ratio >= SAME_AT:
        return "SAME", detail
    return "MIGRATED", detail


def reset(root=None, now=None):
    """换一份新身份（新 uuid、新 salt ⇒ 新 uid/code）。
    ★ 用途：用户要"把机器转手/重置标识"时。
    ★ 注意：本函数**不碰余额**——余额的迁移由 granary 决定；
      否则"重置即可刷粮"。这里只换身份。"""
    old = load(root) or {}
    salt = secrets.token_hex(16)
    install_uuid = str(uuid.uuid4())
    uid = compute_uid(salt, install_uuid)
    rec = {
        "schema": SCHEMA,
        "uuid": install_uuid,
        "salt": salt,
        "uid": uid,
        "code": machine_code(uid),
        "fp": fingerprint(salt),
        "created_at": old.get("created_at") or (now or time.strftime("%Y-%m-%dT%H:%M:%S")),
        "last_seen": now or time.strftime("%Y-%m-%dT%H:%M:%S"),
        "prev_uuid": old.get("uuid"),
        "notes": "reset 换身份、不换余额（余额迁移由 granary 决定）。",
    }
    _save(rec, root)
    return rec


# ---------------------------------------------------------------- CLI ----
def _main(argv):
    """`python machine_id.py [show|verify|reset|json]`
    ★ 输出**永不包含**原始硬件值。"""
    cmd = (argv[1] if len(argv) > 1 else "show").lower()
    if cmd == "reset":
        rec = reset()
        print("已换新机器码：%s" % rec["code"])
        return 0
    if cmd == "json":
        print(json.dumps(ensure(), ensure_ascii=False, indent=1, sort_keys=True))
        return 0
    rec = ensure()
    if cmd == "verify":
        state, detail = verify()
        print("状态：%s" % state)
        print("加权命中率：%s" % detail.get("ratio", "n/a"))
        for k, v in sorted((detail.get("hits") or {}).items()):
            print("  %-14s %s" % (k, v))
        return 0
    print("机器码：%s" % rec["code"])
    print("uid   ：%s" % rec["uid"])
    print("可用硬件源：%s" % (", ".join(sources_present(rec.get("fp"))) or "（无）"))
    print("落盘  ：%s" % machine_path())
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv))
