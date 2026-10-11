# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""出件级守卫：`antinel verify` 承诺的每一条本地命令，在**用户装到的布局**里都必须存在。

★★ 为什么要有它（2026-10-06 真实用户验收实测的缺陷）
  `antinel verify` 在链干净时会打印「这条链**你可以自己复算**」并给出：
      python <site-packages>/challenge/verify.py
  而 `challenge/` **根本没进 wheel**（只进 sdist）⇒ pip 装到的用户照着敲，
  得到 `Errno 2 No such file or directory`。
  撞本项目铁律：「**页面上不许教跑不通的命令**」。
  更糟的是 `ci/drift_audit.py` 的 B4 当时查的是**源码树**（`PKG/challenge/verify.py`），
  于是**仓里永远绿** —— 一条**假守卫**（没对象的检查项）。

★ 本判据怎么做到"不写死路径、也不二次实现"
  它**读产品自己的登记表** `antinel._VERIFY_RECOMPUTE`（打印逻辑与它同源），
  然后把 wheel 解到一个临时目录，在**安装布局**下逐条问：
      `antinel._sibling(rel)` 到底解析不解析得出来？
  产品改登记表，本判据自动跟着变 —— 不存在"两处副本"。

★ 纪律
  · 先红后绿：`negative_control()` 把 `_HERE` 指到一个**没有 challenge 的**空目录，
    承诺必须**全部解析不出来**；解析得出来说明本判据是瞎的。
  · 退出码 0 = 全绿；1 = 有红。

用法：`python ci/verify_promises_guard.py`
"""
import glob
import importlib.util
import os
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
DIST = os.path.join(PKG, "dist")


def newest_wheel():
    ws = sorted(glob.glob(os.path.join(DIST, "*.whl")), key=os.path.getmtime)
    return ws[-1] if ws else None


def load_antinel(root):
    """从**解开的 wheel** 里加载 antinel.py（模块名与仓内那份不冲突）。"""
    path = os.path.join(root, "antinel.py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("_promise_probe_antinel", path)
    m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, root)
    spec.loader.exec_module(m)
    return m


def negative_control(m):
    """负控：`_HERE` 指到空目录 ⇒ 承诺必须**全部**解析不出来。"""
    empty = tempfile.mkdtemp(prefix="antinel_nopromise_")
    old = m._HERE
    try:
        m._HERE = empty
        miss = [rel for rel, _d, _u in m._VERIFY_RECOMPUTE
                if not os.path.isfile(m._sibling(rel))]
        return len(miss) == len(m._VERIFY_RECOMPUTE)
    finally:
        m._HERE = old


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                            # noqa: BLE001
        pass
    whl = newest_wheel()
    if not whl:
        print("★ FAIL：dist/ 里没有 wheel —— 本判据**没有对象**（假守卫，不许静默通过）")
        return 1
    print("=" * 78)
    print("出件级守卫：verify 承诺的本地命令，在安装布局里必须存在")
    print("被检出件：%s" % os.path.basename(whl))
    print("=" * 78)

    ex = tempfile.mkdtemp(prefix="antinel_wheel_x_")
    with zipfile.ZipFile(whl) as z:
        z.extractall(ex)
    m = load_antinel(ex)
    if m is None:
        print("★ FAIL：wheel 里没有 antinel.py —— 解出来的布局不对")
        return 1

    entries = list(getattr(m, "_VERIFY_RECOMPUTE", ()))
    if not entries:
        print("★ FAIL：产品里读不到 `_VERIFY_RECOMPUTE` 登记表 —— 本判据**没有对象**")
        return 1

    bad = []
    for rel, desc, url in entries:
        local = m._sibling(rel)
        ok = os.path.isfile(local)
        print("  %-34s %s" % (rel, "✔ 在" if ok else "★ 不在"))
        if not ok:
            bad.append(rel)
        if not (isinstance(url, str) and url.startswith("https://")):
            bad.append("%s 的回退链接不是 https（本地没有时用户就无处可去）" % rel)

    nok = negative_control(m)
    print("-" * 78)
    print("三个数： %d 绿 / %d 红 ｜ 活力证据 %d/1 ｜ 标本覆盖 %d 条承诺"
          % (len(entries) - len(bad), len(bad), 1 if nok else 0, len(entries)))
    if not nok:
        print("★ FAIL：负控没红 —— 本判据可能是瞎的（承诺在空目录里也「存在」？）")
        return 1
    if bad:
        print("★ FAIL：出件里缺这些承诺的落地件：")
        for b in bad:
            print("   - %s" % b)
        return 1
    print("★ PASS：verify 承诺的 %d 条本地命令，在 wheel 布局里全部存在。" % len(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
