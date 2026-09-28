#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.27.0 - Personal Hub (定稿方案 v1.2: 跨工具汇总).

Host-neutral per-user aggregation index at ~/.antinel/:
  registry.json          known project x host installations (auto-registered
                         by install.py, or `antinel hub register`)
  rollup/YYYY-MM.jsonl   chained aggregate snapshots (derived identity; the
                         per-project audit chains remain the ONLY facts)

Design rules (定稿方案 v1.2):
  - Evidence never moves: the hub stores rollups and chain-head hashes, never
    copies of project records. Federated digest reads projects read-only.
  - Unlike units are never summed (credits vs tokens vs USD stay separate).
  - The hub can DETECT tampering: rollups carry each project chain's day
    anchor (size + last hash), so a mutated project chain no longer matches.

stdlib only, no network. Python 3.10+.
"""
import json
import os
from datetime import datetime

HUB_DIR = os.path.join(os.path.expanduser("~"), ".antinel")
REGISTRY = "registry.json"
KNOWN_TOOL_HINTS = ("workbuddy", "zcode", "qoder", "trae", "doubao", "claude-code")


def hub_dir():
    d = os.environ.get("ANTINEL_HUB_DIR") or HUB_DIR
    os.makedirs(d, exist_ok=True)
    return d


def rollup_dir():
    d = os.path.join(hub_dir(), "rollup")
    os.makedirs(d, exist_ok=True)
    return d


def load_registry():
    p = os.path.join(hub_dir(), REGISTRY)
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("projects", [])
            d.setdefault("tools_declared", [])
            return d
    except Exception:
        pass
    return {"version": 1, "projects": [], "tools_declared": []}


def save_registry(reg):
    p = os.path.join(hub_dir(), REGISTRY)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)
    return True


def register(project_root, host, registered_by="user"):
    """Idempotent: one entry per root, hosts merged. Returns (registry, True)."""
    reg = load_registry()
    root = os.path.abspath(project_root).replace("\\", "/").rstrip("/")
    key = root.lower()
    old_hosts = set()
    for p in reg["projects"]:
        if str(p.get("root", "")).lower() == key:
            old_hosts.update(p.get("hosts") or [])
    old_hosts.add(host)
    projects = [p for p in reg["projects"] if str(p.get("root", "")).lower() != key]
    projects.append({"root": root, "hosts": sorted(old_hosts),
                     "registered_at": datetime.now().isoformat(timespec="seconds"),
                     "registered_by": registered_by})
    projects.sort(key=lambda p: p["root"].lower())
    reg["projects"] = projects
    save_registry(reg)
    return reg, True


def unregister(project_root):
    reg = load_registry()
    key = os.path.abspath(project_root).replace("\\", "/").rstrip("/").lower()
    before = len(reg["projects"])
    reg["projects"] = [p for p in reg["projects"]
                       if str(p.get("root", "")).lower() != key]
    save_registry(reg)
    return before - len(reg["projects"])


def set_tools_declared(tools):
    reg = load_registry()
    reg["tools_declared"] = sorted({t.strip().lower() for t in tools if t.strip()})
    save_registry(reg)
    return reg["tools_declared"]
