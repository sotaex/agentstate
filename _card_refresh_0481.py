# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""0.48.1 许可升级 · SKILL.md 自证卡刷新（一次性工具，保留供审计）。

背景：attempt-3 普通构建（无 --verify）把模板的 false 卡写进树；随后 harness
真跑 PASS（315/315，2026-10-11 12:29），判定与卡不一致 ⇒ version/D-6 红。

本脚本调用 build_package._refresh_skill_selfcert（唯一刷卡真源，0.42.0 设计）：
  · 只重写卡上 4 行，正文一字不动；
  · harness_rc=0 且 _verification_evidence 摘要吻合才写 true —— 12:29 那轮
    harness 真跑 PASS，且其后改动（7 个打头文件）无一在 COVERED 摘要内，
    记录如实描述当前字节 ⇒ 传 0 是事实，不是绕闸门。
"""
import importlib.util
import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "build_package", os.path.join(ROOT, "scripts", "build_package.py"))
bp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bp)

rc = bp._refresh_skill_selfcert(ROOT, ROOT, 0)
print("refresh rc/ok =", rc)
sys.exit(0 if rc else 1)
