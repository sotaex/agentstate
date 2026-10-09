# -*- coding: utf-8 -*-
"""值守台 · 本地账本（**纯本地，零外传**）。

★ 与现有 `antinel credits` **不是一回事**，必须分开命名、分开显示
  （《Antinel 值守台（便签）方案 v1.0（2026-10-05）》§10.6「与现有 antinel credits
  的关系（别搞混）」）::

    antinel credits …   = 追踪**宿主 AI 工具烧了多少积分**（只读账本）
    本模块的"账本"       = 值守台本机**可核对事件的按日摘要**（拦截/注意/防护缺口/处理状态）

  两个账本、两个名字，绝不混用 —— 混了会污染两边口径。
  本模块不证明值守进程全天在线、不计算积分余额，也不承诺可兑换价值。

★ 合规红线（《Antinel 值守台（便签）方案 v1.0（2026-10-05）》§10.5
  「合规红线（现在就要定死，免得将来踩雷）」），现在就定死：
  积分**不可转让 / 不可兑换 / 不承诺任何收益**。
  本模块只负责**记账**，不产生任何价值承诺。

★ 0.38.0 修订（创始人 2026-10-09 拍板「邀请返粮按注册即发」）：
  原句里的「**不与拉人头挂钩**」**已删** —— 它与邀请返粮正面矛盾。
  删的是这一条口号，**不是**三条铁律：`不可转让 / 不可兑换 / 不承诺收益`
  一条不动。邀请机制的如实披露搬到**「粮」词条**
  （`glossary.py` 的 `granary` 项）与 `granary.py`；本模块（值守账本）
  本来与邀请无关，因此这里只留三条。
  风险登记见《Antinel·粮（积分）方案 v1.2（2026-10-09）》§八.3。

★ 落盘：`<hub>/ledger/daily.jsonl`，一天一行，**追加写**（不改写旧行）。
  同一天出现多行 ⇒ 取**最后一行**（追加即更正，旧行留档）。

★ 文档引用更正（0.35.3，本轮实测）：模块头原写「详细设计 §10.5／§10.6」。
  已逐份核对工作区文档，`§10.5`（合规红线）与 `§10.6`（与 credits 的关系）
  **实际出自《值守台（便签）方案 v1.0》**，不在《值守台·详细设计 v1.0》里
  —— 后者第十章是「待创始人拍板」，`§5.6` 才是账本页的界面规范。
  指向错的章节号比不写更坏：照着错的引用会找不到出处。
  （另注：主规格《Antinel 升级规格与全球爆款方案》各版本的 `§10.5/§10.6`
  是「丙表：不与谁为敌」与「本章的检查方式」，与此无关。）
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import date, datetime, timedelta

_HUB_ENV = "ANTINEL_HUB_DIR"


def hub_dir():
    return os.path.expanduser(os.environ.get(_HUB_ENV) or "~/.antinel")


def ledger_dir(root=None):
    return os.path.join(root or hub_dir(), "ledger")


def daily_path(root=None):
    return os.path.join(ledger_dir(root), "daily.jsonl")


def meta_path(root=None):
    return os.path.join(ledger_dir(root), "meta.json")


def _today():
    return date.today().isoformat()


def _append_line(path, line):
    """追加一行。优先用产品自带的加锁追加（与审计链同一把锁）。"""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    try:
        import audit_chain
        audit_chain.append_locked(path, line)
        return
    except ImportError:
        pass
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(line)
        f.flush()


# ------------------------------------------------------------ 记账 ----
def append_day(entry, root=None):
    """追加一条当日账目。`entry` 至少含 `date`。"""
    e = dict(entry)
    e.setdefault("date", _today())
    _append_line(daily_path(root),
                 json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
    return e


def load_days(root=None):
    """读账本 → `{date: entry}`（同日多行取**最后一行**）。"""
    out = {}
    p = daily_path(root)
    try:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:               # noqa: BLE001
                    continue
                if isinstance(e, dict) and e.get("date"):
                    out[str(e["date"])] = e
    except FileNotFoundError:
        return {}
    return out


def _streak(days_set, today=None):
    """连续天数：从今天（或昨天）往前数，不断档。"""
    if not days_set:
        return 0
    d = date.fromisoformat(today) if today else date.today()
    if d.isoformat() not in days_set:
        d = d - timedelta(days=1)
        if d.isoformat() not in days_set:
            return 0
    n = 0
    while d.isoformat() in days_set:
        n += 1
        d = d - timedelta(days=1)
    return n


def summary(root=None, today=None):
    """账本汇总。★ 页面/报告一律调它，不许自己再加一遍。"""
    days = load_days(root)
    keys = ["blocked", "noticed", "breached", "acked"]
    tot = {k: 0 for k in keys}
    for e in days.values():
        for k in keys:
            try:
                tot[k] += int(e.get(k) or 0)
            except (TypeError, ValueError):
                pass
    tot["days"] = len(days)
    tot["streak_days"] = _streak(set(days), today)
    tot["today"] = days.get(today or _today(), {})
    return tot


# ------------------------------------------------------------ 身份 ----
def load_meta(root=None):
    try:
        with open(meta_path(root), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:                           # noqa: BLE001
        return {}


def ensure_install_id(root=None):
    """生成/取回本机匿名编号（UUID v4，**与身份无关**）。

    ★ 只在**开启心跳**时才调用 —— 不开统计就不该有这个编号。
    """
    m = load_meta(root)
    if not m.get("install_id"):
        m["install_id"] = str(uuid.uuid4())
        m.setdefault("created_at", datetime.now().astimezone().isoformat(timespec="seconds"))
        m["schema"] = 1
        p = meta_path(root)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump(m, f, ensure_ascii=False, indent=1, sort_keys=True)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    return m["install_id"]


def forget_install_id(root=None):
    """关闭心跳时**删除本机编号**（承诺过的事要兑现）。"""
    m = load_meta(root)
    m.pop("install_id", None)
    p = meta_path(root)
    if os.path.exists(p):
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump(m, f, ensure_ascii=False, indent=1, sort_keys=True)
    return True


# ------------------------------------------------------------ 导出 ----
def export(root=None):
    """导出账本（一个文件，将来可"认领合并"到账号）。"""
    days = load_days(root)
    return json.dumps({"schema": 1, "days": days, "summary": summary(root)},
                      ensure_ascii=False, indent=1, sort_keys=True)


def claim_payload(root=None):
    """**认领载荷**（将来上线账号后合并用）。现在只留接口，不做任何上传。"""
    m = load_meta(root)
    return {"schema": 1, "install_id": m.get("install_id") or "",
            "days": load_days(root), "summary": summary(root)}
