# -*- coding: utf-8 -*-
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
