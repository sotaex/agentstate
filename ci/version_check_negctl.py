# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""判据 6（server.json stability.schema vs AUDIT_SCHEMA.md 抬头）的负控。

守「守卫先红后绿」：证明 `_stability_schema_fails()` 在漂移时**真会红**，
在一致时**是绿的**，在真源/对象缺失时**不静默通过**（假守卫防护）。
零删除：只在 tempfile 里造件，不碰真树。

用法：python ci/version_check_negctl.py     （退出码 0 = 负控全过）
"""
import importlib.util
import json
import os
import tempfile
from pathlib import Path

VC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version_check.py")
spec = importlib.util.spec_from_file_location("vc", VC)
vc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc)


def mk(root, doc_ver, srv_ver):
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "AUDIT_SCHEMA.md").write_text(
        "# AUDIT_SCHEMA.md — Antinel 审计记录模式 v%s（随 v0.34.1）\n" % doc_ver,
        encoding="utf-8")
    if srv_ver is None:
        (root / "server.json").write_text(json.dumps({}), encoding="utf-8")
    else:
        (root / "server.json").write_text(json.dumps(
            {"stability": {"schema": "AUDIT_SCHEMA v%s, changes registered append-only" % srv_ver}}),
            encoding="utf-8")


results = []
with tempfile.TemporaryDirectory() as td:
    root = Path(td)

    mk(root, "1.9", "1.2")
    vc.PKG = root
    r = vc._stability_schema_fails()
    results.append(("N1 漂移(doc 1.9 / srv 1.2) 必须红", bool(r), r))

    mk(root, "1.9", "1.9")
    vc.PKG = root
    r = vc._stability_schema_fails()
    results.append(("N2 一致(1.9/1.9) 必须绿", not r, r))

    mk(root, "1.9", None)   # server.json 无 stability 键
    vc.PKG = root
    r = vc._stability_schema_fails()
    results.append(("N3 被检对象缺 stability 必须红", bool(r), r))

    (root / "docs" / "AUDIT_SCHEMA.md").unlink()
    vc.PKG = root
    r = vc._stability_schema_fails()
    results.append(("N4 真源缺失 必须红", bool(r), r))

    mk(root, "1.9", "1.9")
    (root / "docs" / "AUDIT_SCHEMA.md").write_text("# 没有版本号的抬头\n", encoding="utf-8")
    vc.PKG = root
    r = vc._stability_schema_fails()
    results.append(("N5 抬头抽不到版本 必须红", bool(r), r))

bad = 0
for name, ok, out in results:
    print("%-40s %s  %s" % (name, "PASS" if ok else "FAIL", (out[:1] or [""])[0][:80]))
    if not ok:
        bad += 1
print()
print("NEGCTL %d/%d %s" % (len(results) - bad, len(results), "OK" if bad == 0 else "有失败"))
raise SystemExit(1 if bad else 0)
