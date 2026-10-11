# SPDX-License-Identifier: Apache-2.0

"""_host_detect.py -- 宿主归因的唯一来源（0.33.1）

为什么要有这个文件
------------------
0.33.0 的宿主归因有**两份独立实现**，而且口径不同：

  hooks/pre_tool_use.py  : env 优先（6 键，含 QODER_CN/TRAE_CN），目录其次
  hooks/post_tool_use.py : 目录优先，再被 env 覆盖（4 键，无 CN 变体）

同一个工具调用，pre 与 post 可能给出两个不同的宿主标签；post 侧对 CN 变体
完全没有识别。这是「同一常量被两处独立读取而漂移」的教科书形态。

更致命的是：两份实现**都没有 workbuddy/codebuddy**。本项目实际就跑在
WorkBuddy 里，而 WorkBuddy 设置的是 `CODEBUDDY_*` 系列环境变量，一个都不在
识别表里 ⇒ env 全落空 ⇒ 退回目录标记 ⇒ `D:\\2026\\PSL` 下 `.qoder` 先命中
⇒ 全链被标成 qoder。

判定顺序（0.33.1）
------------------
1. `ANTINEL_HOST`   —— 显式覆盖。宿主不配合时的兜底，人说了算。
2. 宿主实际设置的 env 键（按下列顺序）
3. 目录标记（`.workbuddy`/`.codebuddy` 排在 `.qoder`/`.trae` 之前）
4. `generic`        —— 什么都没命中；此时调用方必须写 host_tag_uncertain 事件

为什么目录标记要有顺序：多人多工具共用一个项目目录是常态（PSL 根目录同时有
`.qoder` `.trae` `.workbuddy`）。目录标记本身是**低可信证据**——它只说明"这个
工具曾在此项目里跑过"，不代表"当前这次调用来自它"。所以它排在 env 之后，且
必须把 `markers_seen` 全量记进证据，事后可复核。

★ 设计纪律：env 优先这条策略成立的前提是——**我方键表必须覆盖宿主实际会设的
键**。否则"env 优先"等价于"没有 env"，静默退回目录标记，而目录标记在共用
项目里必然错。这是 0.33.0 那个 bug 的真正根因，不是某行代码写错了。
"""

import os

# (env 键, 标签) —— 顺序即优先级。新增宿主时追加到末尾，不要插队
# （插队会改变既有宿主的判定结果，属于"照旧版动手会做错"的变更）。
_ENV_KEYS = (
    ("CLAUDE_CODE", "claude-code"),
    ("ZCODE_SESSION", "zcode"),
    ("QODER", "qoder"),
    ("QODER_CN", "qoder"),
    ("TRAE", "trae"),
    ("TRAE_CN", "trae"),
    # 0.33.1 新增：WorkBuddy / CodeBuddy 实测只设 CODEBUDDY_* 与
    # CLAUDE_PROJECT_DIR，不设 CLAUDE_CODE。这两个键是真机上唯一可命中的。
    ("CODEBUDDY_CONFIG_DIR", "workbuddy"),
    ("WORKBUDDY_HOST", "workbuddy"),
)

# (目录标记, 标签) —— 顺序即优先级。.workbuddy 排在 .qoder/.trae 之前：
# 在共用目录里，哪一个"先命中"决定了归因结果，必须显式定序而不是靠字典序。
_DIR_MARKERS = (
    (".workbuddy", "workbuddy"),
    (".codebuddy", "workbuddy"),
    (".claude", "claude-code"),
    (".zcode", "zcode"),
    (".qoder", "qoder"),
    (".qoder-cn", "qoder"),
    (".trae", "trae"),
    (".trae-cn", "trae"),
)

_GENERIC = "generic"


def _normalize_explicit(v):
    """ANTINEL_HOST 允许用户写常见别名，避免拼错导致静默失效。"""
    s = (v or "").strip().lower()
    alias = {
        "claude": "claude-code", "claudecode": "claude-code", "cc": "claude-code",
        "wb": "workbuddy", "workbuddy": "workbuddy", "codebuddy": "workbuddy",
        "qoder": "qoder", "qoder-cn": "qoder", "qodercn": "qoder",
        "trae": "trae", "trae-cn": "trae", "traecn": "trae",
        "zcode": "zcode", "zc": "zcode",
    }
    return alias.get(s, s or _GENERIC)


def detect(cwd=None):
    """返回 (tag, evidence)。evidence 必定可 JSON 序列化，且不含任何内容。"""
    ev = {"source": "none", "key": None, "markers_seen": [], "cwd": None,
          "confidence": "none", "detector": "_host_detect.py@0.33.1"}
    try:
        ev["cwd"] = os.path.abspath(cwd or os.getcwd())
    except Exception:
        ev["cwd"] = None

    # 1) 显式覆盖（人说了算；host_shield.py 也读同一个变量，口径一致）
    explicit = os.environ.get("ANTINEL_HOST")
    if explicit:
        tag = _normalize_explicit(explicit)
        ev.update(source="explicit", key="ANTINEL_HOST", confidence="high",
                  value=explicit)
        return tag, ev

    # 2) 宿主 env 键
    for k, tag in _ENV_KEYS:
        if os.environ.get(k):
            ev.update(source="env", key=k, confidence="high")
            return tag, ev

    # 3) 目录标记（低可信：只说明该工具曾在此项目跑过）
    base = ev["cwd"]
    if base:
        seen = []
        for d, tag in _DIR_MARKERS:
            try:
                if os.path.isdir(os.path.join(base, d)):
                    seen.append(d)
                    ev.update(source="dir", key=d, confidence="low")
                    ev["markers_seen"] = seen
                    return tag, ev
            except Exception:
                continue
        ev["markers_seen"] = seen
    return _GENERIC, ev


def host_tag(cwd=None):
    """只要标签的薄封装（保持与 0.33.0 的 detect_host_tag() 同签名）。"""
    return detect(cwd)[0]
