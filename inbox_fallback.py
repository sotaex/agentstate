# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Antinel 监理 · 兜底层（第 5 层）：人不在电脑前时的最后一招。**默认关。**

★ 两条纪律：
  1. **默认关**（`email.enabled` / `webhook.enabled` 都是 False）；
  2. **不经第三方服务** —— 邮件走**用户自备的 SMTP**，Webhook 发到**用户自己的地址**。
     本模块里**不写死任何外部地址**（有守卫扫这一条）。

★ 后端可注入（测试零副作用）：`sender` / `poster` 都是普通函数。
"""
from __future__ import annotations


def _result(ok, err=""):
    return {"ok": bool(ok), "error": err}


def _default_smtp_sender(host, port, user, password, to, tls, subject, body):
    """默认发信器：用标准库 `smtplib` 发到**用户自备**的 SMTP。"""
    import smtplib
    import ssl
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user or "antinel@localhost"
    msg["To"] = to
    msg.set_content(body)
    try:
        if tls:
            with smtplib.SMTP(host, int(port), timeout=20) as s:
                s.starttls(context=ssl.create_default_context())
                if user:
                    s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, int(port), timeout=20) as s:
                if user:
                    s.login(user, password)
                s.send_message(msg)
        return _result(True)
    except Exception as e:                      # noqa: BLE001
        return _result(False, "%s: %s" % (type(e).__name__, e))


def send_email(subject, body, cfg, sender=None):
    """按配置发一封兜底邮件。未启用 ⇒ **一个网络动作都不做**。"""
    e = (cfg or {}).get("email") or {}
    if not e.get("enabled"):
        return _result(False, "未启用")
    if not e.get("host") or not e.get("to"):
        return _result(False, "缺少 SMTP 主机或收件人")
    fn = sender or _default_smtp_sender
    return fn(e.get("host"), e.get("port", 587), e.get("user", ""),
              e.get("password", ""), e.get("to"), e.get("tls", True),
              subject, body)


def _default_webhook_poster(url, payload):
    """默认投递器：把 JSON POST 到**用户自己的**地址。"""
    import json
    import urllib.request

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310
            return _result(200 <= r.status < 300, "HTTP %s" % r.status)
    except Exception as ex:                     # noqa: BLE001
        return _result(False, "%s: %s" % (type(ex).__name__, ex))


def send_webhook(payload, cfg, poster=None):
    w = (cfg or {}).get("webhook") or {}
    if not w.get("enabled"):
        return _result(False, "未启用")
    if not w.get("url"):
        return _result(False, "缺少 Webhook 地址")
    fn = poster or _default_webhook_poster
    return fn(w.get("url"), payload)


def dispatch(level, title, body, cfg, root=None, sender=None, poster=None):
    """把一条告警分发到兜底层。**未启用 ⇒ 全部返回"未启用"，零副作用。**"""
    out = {}
    out["email"] = send_email("[Antinel] %s" % title,
                              "%s\n\n级别：%s" % (body, level), cfg, sender=sender)
    out["webhook"] = send_webhook({"level": level, "title": title, "body": body},
                                  cfg, poster=poster)
    return out
