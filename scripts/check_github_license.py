# SPDX-License-Identifier: Apache-2.0
# -*- coding: utf-8 -*-
"""M-C（核验报告 v1.0 §5）：远端与本地协议一致性对账 —— 推送后运行。

用法：
    python -m scripts.check_github_license            # 查 GitHub 识别结果
    python -m scripts.check_github_license --remote   # 连远端 LICENSE 内容一起对

判据（全部来自本轮实测）：
    ① API license.spdx_id == "Apache-2.0"（修复前实测是 NOASSERTION/Other）
    ② 远端根 LICENSE 与本地逐字节一致（防「修了源头没修发布实例」复发）
    ③ 远端根 LICENSE 不含 A6 附加段（G7-3 形态）

注意：GitHub 的 licensee 识别在推送后**不是即时**的，通常几分钟内刷新；
若 ① 迟迟不变，先确认 ②③ 已满足，再等一轮或联系平台。
"""
import io
import json
import os
import sys
import urllib.request

REPO = "sotaex/agentstate"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def http(url, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": "antinel-license-check/0.48.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    return data if raw else json.loads(data.decode("utf-8"))


def main():
    problems = []

    info = http("https://api.github.com/repos/%s" % REPO)
    lic = info.get("license") or {}
    spdx = lic.get("spdx_id")
    print("GitHub 识别：spdx_id=%r name=%r" % (spdx, lic.get("name")))
    if spdx != "Apache-2.0":
        problems.append("① GitHub 识别 %r != Apache-2.0（推送后识别有几分钟延迟）" % spdx)

    if "--remote" in sys.argv:
        local = open(os.path.join(ROOT, "LICENSE"), "rb").read()
        remote = http("https://raw.githubusercontent.com/%s/HEAD/LICENSE" % REPO, raw=True)
        if local != remote:
            problems.append("② 远端 LICENSE 与本地不一致（修了源头没修发布实例？）")
        else:
            print("远端 LICENSE 与本地逐字节一致")
        if "收入与中立性" in remote.decode("utf-8", "replace"):
            problems.append("③ 远端 LICENSE 仍含 A6 附加段（G7-3 形态）")

    if problems:
        print("\n".join("★ " + p for p in problems))
        return 1
    print("对账通过：远端身份与本地意图一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
