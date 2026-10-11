# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 配置（**默认全关，用户显式开**）。

★ 安全默认值（不许改）：
  - `sound` / `overlay`（强调层）**默认关**（创始人拍板：默认关，但用户能开）；
  - `email` / `webhook`（兜底层）**默认关**；
  - `heartbeat`（匿名计数）**默认关**。

★ 免打扰时段（`quiet_hours`）**永不静默 R0** —— 防线失守必须能叫醒人。

落盘：`<hub>/console/config.json`（0600）。读坏 ⇒ 退回**安全默认**并留痕，不崩。
"""
from __future__ import annotations

import copy
import json
import os

import inbox_model as M

_HUB_ENV = "ANTINEL_HUB_DIR"

DEFAULTS = {
    "schema": 1,
    "touch_level": "L1",                       # 这一级及以上才弹通知
    "sound": False,                            # 强调层：分级声音（默认关）
    "overlay": False,                          # 强调层：桌面浮层角标（默认关）
    "quiet_hours": {"start": "", "end": ""},   # 免打扰（HH:MM，空＝不启用）
    "email": {"enabled": False, "host": "", "port": 587, "user": "",
              "password": "", "to": "", "tls": True},
    "webhook": {"enabled": False, "url": ""},
    "heartbeat": False,                        # 匿名计数（默认关）
    "heartbeat_endpoint": "",                  # 哑计数器地址（Cloudflare Worker），空＝不发
}


def hub_dir():
    return os.path.expanduser(os.environ.get(_HUB_ENV) or "~/.antinel")


def console_dir(root=None):
    return os.path.join(root or hub_dir(), "console")


def config_path(root=None):
    return os.path.join(console_dir(root), "config.json")


def load(root=None):
    """读配置。缺文件 ⇒ 默认值；坏文件 ⇒ **默认值 + `_corrupt` 标记**（不崩、不静默）。"""
    cfg = copy.deepcopy(DEFAULTS)
    p = config_path(root)
    try:
        with open(p, encoding="utf-8") as f:
            got = json.load(f)
        if not isinstance(got, dict):
            raise ValueError("配置根不是对象")
        for k, v in got.items():
            cfg[k] = v
        cfg["_corrupt"] = False
    except FileNotFoundError:
        cfg["_corrupt"] = False
    except Exception:                           # noqa: BLE001
        cfg["_corrupt"] = True                  # ★ 明确标记，不假装读到了
    return cfg


def save(cfg, root=None):
    p = config_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    data = {k: v for k, v in cfg.items() if not k.startswith("_")}
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return data


def _hm(s):
    """'HH:MM' -> 分钟数；非法 ⇒ None。"""
    try:
        h, m = str(s).split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h * 60 + m
    except Exception:                           # noqa: BLE001
        pass
    return None


def in_quiet_hours(cfg, now_min):
    """`now_min` ＝ 当天第几分钟（0..1439）。未配置/非法 ⇒ 不在免打扰。"""
    q = cfg.get("quiet_hours") or {}
    a, b = _hm(q.get("start")), _hm(q.get("end"))
    if a is None or b is None:
        return False
    if a <= b:
        return a <= now_min < b
    return now_min >= a or now_min < b         # 跨零点


def should_touch(level, cfg, now_min=None):
    """该不该弹通知。★ 免打扰时段**永不静默 R0**。"""
    if level not in M.PRIORITY:
        return False
    gate = cfg.get("touch_level") or "L1"
    if M.PRIORITY.get(level, 0) < M.PRIORITY.get(gate, 3):
        return False
    if level == "R0":
        return True                            # ★ R0 穿透免打扰
    if now_min is not None and in_quiet_hours(cfg, now_min):
        return False
    return True
