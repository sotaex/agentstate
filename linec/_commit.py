# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""产物落盘：`output/` 下各线共用的唯一实现。

三条实测事实决定这里的写法（2026-11-03，本机 Windows + D 盘）：

1. `os.replace` 到「已存在的目标」会**偶发** WinError 5。连测 20 次 0 次失败，
   而一次真实跑里命中 1 次 ⇒ 属瞬时占用，必须重试，不能一次失败就放弃。
2. `shutil.copyfile` 覆盖不依赖 unlink，实测可用 ⇒ 重试用尽后的退路。
   代价写在这里：它**不是原子的**，断电时可能留下半个文件。
3. 「文件存在且非空」与「文件可用」在目录列表上完全一样 ⇒ 写完必须回读比对。

为什么收成一个文件：这四条（tmp、fsync、replace、回读）原先在 output/ 下各写一遍。
本机那次瞬时冲突只打中其中一处，其余四处照常 —— 同一件事有五个实现，
修一处等于没修。
"""
from __future__ import annotations

import json
import os
import shutil
import time

RETRIES = 6
BACKOFF = 0.05


def _replace_with_retry(tmp: str, path: str) -> str:
    """返回实际走的那条路。走过的路要能被调用方印出来，否则「原子」是空话。"""
    last = None
    for i in range(RETRIES):
        try:
            os.replace(tmp, path)
            return "replace"
        except OSError as exc:
            last = exc
            time.sleep(BACKOFF * (i + 1))
    try:
        shutil.copyfile(tmp, path)
    except OSError:
        raise last
    return "copyfile(winerror=%s)" % getattr(last, "winerror", type(last).__name__)


def write_text(path: str, text: str, *, newline: str = "\n") -> dict:
    """落盘 + 回读。回读不一致即抛，不许「写完了」这句话没有证据。

    返回三个口径，**别混用**：`chars` 是字符数，`bytes` 是磁盘字节数
    （中文一字三字节，两者不相等），`how` 是实际走的落盘路径。
    """
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline=newline) as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    how = _replace_with_retry(tmp, path)
    with open(path, encoding="utf-8", newline="") as fh:
        back = fh.read()
    if back != text:
        raise IOError("回读不一致：写入 %d 字符，读回 %d 字符（%s）"
                      % (len(text), len(back), path))
    return {"path": path, "chars": len(back), "bytes": os.path.getsize(path),
            "how": how}


def write_json(path: str, payload, *, indent: int = 1, sort_keys: bool = True) -> dict:
    """写 json。回读要求**能解析**，字节一致不够 —— 半截 json 也可能字节一致。"""
    text = json.dumps(payload, ensure_ascii=False, indent=indent, sort_keys=sort_keys)
    r = write_text(path, text)
    with open(path, encoding="utf-8") as fh:
        json.load(fh)           # 解析失败即抛，不把「文件在」当成「内容对」
    return r


# --------------------------------------------------------------------------- 自检
def _selfcheck() -> int:
    """五臂。**为什么要给原语自己配判据**（2026-11-03）：

    它是「五个落点各写一遍」收成的唯一实现。唯一实现最危险的状态不是写错，
    而是**悄悄退回简单写法**（直接 `open('w')`）—— 那种退化不会让任何一条
    业务判据变红，只会让六处保护同时消失，而且没人知道。

    所以这里的每一臂都造「该失败」的输入，不是复述实现现状：
    ② 必抛、③ 回读必抓、④ 退路必达。只有 ① 与 ⑤ 是正控。

    全部在系统临时目录里造。本机 `C:\\Temp` 不可删、D 盘不可删，
    只有 `%LOCALAPPDATA%\\Temp` 能清 —— 用 `tempfile.mkdtemp()` 让它自己挑。
    """
    import sys
    import tempfile

    root = tempfile.mkdtemp(prefix="commit_sc_")
    rows = []

    def ck(cond, name, detail=""):
        rows.append((bool(cond), name, detail))

    # ① 正常写：回读一致，且 chars 与 bytes 是两个口径（中文一字三字节）
    try:
        r = write_text(os.path.join(root, "a.txt"), "中文abc")
        ck(r["chars"] == 5 and r["bytes"] == 9,
           "① 正常写：chars=5／bytes=9（中文三字节，两个数不许混用）",
           "chars=%s bytes=%s how=%s" % (r["chars"], r["bytes"], r["how"]))
    except Exception as exc:                                   # noqa: BLE001
        ck(False, "① 正常写", "%s: %s" % (type(exc).__name__, exc))

    # ② 目标是目录 ⇒ 必须抛（负控：写不进去不许装作写完）
    adir = os.path.join(root, "adir")
    os.makedirs(adir, exist_ok=True)
    try:
        write_text(adir, "x")
        ck(False, "② 目标是目录 ⇒ 必须抛", "居然没抛，说明失败被吞了")
    except Exception as exc:                                   # noqa: BLE001
        ck(True, "② 目标是目录 ⇒ 必须抛", type(exc).__name__)

    # ③ 注入半截写 ⇒ 回读必须抓到（翻面腿：证明回读不是摆设）
    #    用纯 ASCII，避免截在多字节字符中间变成解码错 —— 那会掩盖
    #    「回读比对」这条判据本身是否有效。
    real_replace = globals()["_replace_with_retry"]

    def _half(tmp, path):
        with open(tmp, "r+", encoding="utf-8") as fh:
            s = fh.read()
            fh.seek(0)
            fh.truncate(max(1, len(s) // 2))
        return real_replace(tmp, path)

    globals()["_replace_with_retry"] = _half
    try:
        write_text(os.path.join(root, "b.txt"), "abcdefghijklmnopqrstuvwxyz0123")
        ck(False, "③ 注入半截 ⇒ 回读必须抓到", "字少了却没抛")
    except IOError as exc:
        ck("回读不一致" in str(exc), "③ 注入半截 ⇒ 回读必须抓到", str(exc)[:60])
    except Exception as exc:                                   # noqa: BLE001
        ck(False, "③ 注入半截 ⇒ 回读必须抓到", "%s: %s" % (type(exc).__name__, exc))
    finally:
        globals()["_replace_with_retry"] = real_replace

    # ④ replace 全失败 ⇒ 走 copyfile 退路，且内容正确（退路也要能到）
    real_osreplace = os.replace

    def _boom(a, b):
        raise OSError(13, "injected: replace 一律失败")

    os.replace = _boom
    try:
        r = write_text(os.path.join(root, "c.txt"), "退路内容")
        with open(r["path"], encoding="utf-8") as fh:
            same = fh.read() == "退路内容"
        ck(r["how"].startswith("copyfile") and same,
           "④ replace 全失败 ⇒ 走 copyfile 退路且内容正确", r["how"])
    except Exception as exc:                                   # noqa: BLE001
        ck(False, "④ replace 全失败 ⇒ 走 copyfile 退路", "%s: %s" % (type(exc).__name__, exc))
    finally:
        os.replace = real_osreplace

    # ⑤ 同路径覆盖写 ⇒ 内容必须是第二次的（防「两遍同尺寸就是覆盖成功」那种假绿）
    p5 = os.path.join(root, "d.txt")
    try:
        write_text(p5, "第一次写的旧内容")
        write_text(p5, "第二次")
        with open(p5, encoding="utf-8") as fh:
            got = fh.read()
        ck(got == "第二次", "⑤ 同路径写两次 ⇒ 内容是第二次的（覆盖不是追加）",
           "读到 %r" % got)
    except Exception as exc:                                   # noqa: BLE001
        ck(False, "⑤ 同路径写两次 ⇒ 覆盖", "%s: %s" % (type(exc).__name__, exc))

    bad = 0
    for ok, name, detail in rows:
        print("%s %s%s" % ("[PASS]" if ok else "[FAIL]", name,
                           ("  ← %s" % detail) if detail and not ok else ""))
        if not ok:
            bad += 1
    print("合计 %d 臂：通过 %d，失败 %d（临时目录 %s）"
          % (len(rows), len(rows) - bad, bad, root))
    return 0 if bad == 0 else 1


def main(argv=None) -> int:
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selfcheck" in argv:
        return _selfcheck()
    sys.stderr.write("用法：python _commit.py --selfcheck\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
