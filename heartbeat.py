# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""值守台 · 匿名计数心跳（第 8 阶段 · 方案 B）。**默认关。**

★★ 三条不许松的纪律：
  1. **默认关**（`config["heartbeat"]` 为 False）—— 关闭时**一个网络请求都不发**；
  2. **只发固定字段**，一个不多（见 `TOP_FIELDS`）；
  3. **不发**：规则名、路径、内容、IP、用户名、机器名、时间戳到秒。
     本机编号 `install_id` 是**随机 UUID v4，与身份无关**，关掉统计就**删掉**。

★ 诚实纪律：这个数**只能叫"开启了统计的安装数"，不能叫"用户数"**。

★ 端点＝一个**哑计数器**（Cloudflare Worker，见 `tools/heartbeat_worker.js`）：
  只做 install_id 去重 + 按日累加，**不存 IP、不存 UA**。
"""
from __future__ import annotations

import json

import inbox_config as C
import inbox_model as M
import inbox_store as S
import ledger as L

SCHEMA = 1

# ★ 报文**只准**有这几个顶层字段（J9 守的就是"一个不多"）
TOP_FIELDS = frozenset({"install_id", "date", "version", "buckets", "schema"})
BUCKET_FIELDS = frozenset({"r0", "l2", "l1", "ls"})

LEVEL_TO_BUCKET = {"R0": "r0", "L2": "l2", "L1": "l1", "Ls": "ls"}


def enabled(root=None, cfg=None):
    cfg = cfg or C.load(root)
    return bool(cfg.get("heartbeat"))


def endpoint(root=None, cfg=None):
    cfg = cfg or C.load(root)
    return str(cfg.get("heartbeat_endpoint") or "").strip()


def _version():
    try:
        import antinel
        for attr in ("VERSION", "__version__"):
            v = getattr(antinel, attr, None)
            if v:
                return str(v)
    except Exception:                           # noqa: BLE001
        pass
    return "unknown"


def build(root=None, items=None, day=None, version=None):
    """构造心跳报文。**只含固定字段**；构造后立刻自检字段集（多一个就抛错）。"""
    import datetime
    day = day or datetime.date.today().isoformat()
    items = S.load_items(root=root) if items is None else items
    buckets = {k: 0 for k in sorted(BUCKET_FIELDS)}
    for it in items:
        if it.state in M.OPEN_STATES and str(it.ts)[:10] == day:
            b = LEVEL_TO_BUCKET.get(it.level)
            if b:
                buckets[b] += 1
    payload = {
        "install_id": L.ensure_install_id(root),
        "date": day,
        "version": version or _version(),
        "buckets": buckets,
        "schema": SCHEMA,
    }
    _assert_shape(payload)                      # ★ 构造即自检
    return payload


def _assert_shape(payload):
    keys = set(payload)
    if keys != set(TOP_FIELDS):
        raise M.InboxError("心跳报文顶层字段不对：%s（只准 %s）"
                           % (sorted(keys), sorted(TOP_FIELDS)))
    if set(payload.get("buckets") or {}) != set(BUCKET_FIELDS):
        raise M.InboxError("buckets 字段不对：%s" % (sorted(payload.get("buckets") or {}),))
    if not isinstance(payload.get("schema"), int):
        raise M.InboxError("schema 必须是整数")
    return True


def _default_poster(url, payload):
    import urllib.request
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    # ★ 2026-10-06 实测：必须自报家门。Cloudflare 的浏览器签名封禁（error 1010）会把
    #   默认 UA「Python-urllib/x」当机器人拦掉（HTTP 403），而任何非该默认串都放行
    #   （浏览器 UA / 自报家门 UA / 空 UA 实测全过）。⇒ 用产品自己的 UA：诚实、可审计，
    #   且不去关用户域名的防护（Bot Fight Mode / Browser Integrity Check 保持开着）。
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "antinel-heartbeat/%s" % _version()})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:   # noqa: S310
            return (200 <= r.status < 300), "HTTP %s" % r.status
    except Exception as e:                      # noqa: BLE001
        return False, "%s: %s" % (type(e).__name__, e)


def send_once(root=None, poster=None, payload=None, cfg=None):
    """发一次心跳。**未启用 / 无端点 ⇒ 直接返回 (False, 原因)，不发任何请求。**"""
    cfg = cfg or C.load(root)
    if not cfg.get("heartbeat"):
        return False, "未启用"
    url = str(cfg.get("heartbeat_endpoint") or "").strip()
    if not url:
        return False, "未配置端点"
    p = payload if payload is not None else build(root=root)
    _assert_shape(p)                            # 发之前再自检一次
    fn = poster or _default_poster
    return fn(url, p)


def forget(root=None):
    """关闭统计时**删除本机编号**（承诺过的事要兑现）。"""
    return L.forget_install_id(root)
