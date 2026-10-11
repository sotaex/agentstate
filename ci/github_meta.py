# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""把 GitHub 仓库的**可搜索元数据**落成一份可复核的清单。

★ 为什么需要这个文件（2026-10-03 实测）：
  `api.github.com/repos/sotaex/agentstate` 返回
      description = None      ← ★
      homepage    = None      ← ★
      topics      = []        ← ★
      stars 0 / forks 0 / watchers 0
  ⇒ **GitHub 的搜索排名与推荐几乎完全依赖这三项**。
    仓库代码再好，搜不到就等于不存在——这是"快速放量"的第一道闸门，
    且**与产品能力无关、与写代码无关，只与填三个字段有关**。

★ 本文件不自动改 GitHub（那需要凭据，且必须由创始人本人做）。
  它做的是：把"该填什么、为什么"固化成一份**可审阅、可版本化**的文件，
  随仓库入库 ⇒ 任何人 clone 都能核对，也能直接照着填。

填法见 --print-github-fields：它会输出可直接粘贴的三条命令。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

# ★ 三项的取值理由（每条都要能被第三方核对，不要写营销词）
META = {
    "description": (
        "Local-first audit chain and guardrails for AI coding agents. "
        "37 rules, 315 assertions, recomputable by anyone, offline. "
        "MIT."),
    "homepage": "https://antinel.com",
    "topics": [
        "ai-agents", "ai-security", "agent-security", "mcp", "claude-code",
        "audit-log", "supply-chain", "prompt-injection", "data-leak",
        "privacy", "local-first", "self-hosted", "security-tools",
    ],
}

# 短描述 ≤ 350 字符（GitHub 硬限制）；超了会被静默截断 ⇒ 自检
DESC_LIMIT = 350


def check():
    """自检：description 长度、topics 合法性。⇒ 返回问题列表（空 = 通过）。"""
    bad = []
    d = META["description"]
    if len(d) > DESC_LIMIT:
        bad.append("description %d 字符，超过 GitHub 的 %d 上限（会被静默截断）"
                   % (len(d), DESC_LIMIT))
    bad += [t for t in META["topics"]
            if not t.replace("-", "").replace("+", "").isalnum()]
    if len(META["topics"]) > 20:
        bad.append("topics %d 个，超过 GitHub 上限 20" % len(META["topics"]))
    if not META["homepage"].startswith("http"):
        bad.append("homepage 必须以 http 开头")
    return bad


def emit():
    print("=" * 70)
    print(" GitHub 仓库元数据 —— 这三项决定\"能不能被搜到\"")
    print(" 仓库：https://github.com/sotaex/agentstate")
    print("=" * 70)
    print("")
    print(" description（当前为空 ⇒ 搜索结果里没有一句话）")
    print("   长度 %d/%d" % (len(META["description"]), DESC_LIMIT))
    print("   %s" % META["description"])
    print("")
    print(" homepage（当前为空）")
    print("   %s" % META["homepage"])
    print("")
    print(" topics（当前为空 ⇒ 无法被 topic 检索）　%d 个" % len(META["topics"]))
    for t in META["topics"]:
        print("   - %s" % t)
    print("")
    print("=" * 70)
    print(" 填进去（三条命令，需要你的 GitHub 凭据，我们不代持）")
    print("=" * 70)
    print("")
    print("# 1) description + homepage")
    print("gh repo edit sotaex/agentstate \\")
    print("  --description %s \\" % json.dumps(META["description"]))
    print("  --homepage %s" % META["homepage"])
    print("")
    print("# 2) topics（topics 命令会**替换**整个列表，不是追加）")
    print("gh repo edit sotaex/agentstate --add-topic %s"
          % " --add-topic ".join(META["topics"]))
    print("")
    print(" 或用网页：仓库页右上角齿轮 ⚙ → Description / Website / Topics")
    print("")
    print(" ★ 顺带建议（同属\"被搜到\"这一件事）：")
    print("   - 把仓库从 sotaex 个人名下**转成组织**（sotaex/agentstate → 一个 Antinel 组织），")
    print("     搜索权重与可信度都更高，且显得不是\"个人玩具\"；")
    print("   - 开 Discussions：security 工具的争议/提问没有地方落，")
    print("     而 issue 只适合 bug ⇒ 现在是\"问无处问\"。")


def main():
    bad = check()
    if "--check" in sys.argv:
        if bad:
            for b in bad:
                print("FAIL %s" % b)
            return 1
        print("PASS 三项元数据自检通过（description %d 字符、topics %d 个）"
              % (len(META["description"]), len(META["topics"])))
        return 0
    emit()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
