# SPDX-License-Identifier: Apache-2.0
"""清扫 TMP 根里的历史临时目录（0.55.0 复核 F3 收口第二步）。

## 为什么要有这个脚本

`ci/tmpreg.py` 只管**本进程**建出来的目录（atexit 兜底）。它上线之前跑过的
几十次套件，每套 mkdtemp 十几次，累计七万项堆在 TMP 根里。

这些东西不是产品数据，是脚手架。但「不是产品数据」不等于「可以随手删」——
所以本脚本按三条纪律办：

  1. **默认不动手**。不带 `--apply` 只出清单（写 JSON，一行不删）。
  2. **归因两条路，都在清单里留痕**：
       A 前缀**派生自源码**（ast 扫 mkdtemp/tmpdir 的 prefix 常量）；
       B 命名形态（`<前缀>_` + 6~10 位小写随机串，即 mkdtemp 的产物形态）。
     两条都不沾的归 `foreign`，**永不删**，只列出来等人看。
  3. **年龄闸 + 忙闸**。`--min-age-minutes`（默认 30）以内的不碰；另外
     只要发现任何一项在 `--busy-minutes`（默认 5）内被改过，就**拒绝 --apply**
     ——那说明有东西正在写，此时动手可能删掉活着的目录。

## 用法

    python scripts/tmp_sweep.py                        # 只扫，出清单
    python scripts/tmp_sweep.py --apply                # 删 attributed 的目录
    python scripts/tmp_sweep.py --apply --with-logs    # 连运行日志一起删

## 清单在哪

`output/tmp_sweep_<时间戳>.json`：逐项 `{name, kind, why, mtime, newest, idle_min, size}`。
`why` 取值 `source:<前缀>` / `shape:` / `foreign` / `log`。删完再写一份
`*.done.json` 记哪些删成功、哪些失败。

## 一条盲区（别当成已验证）

`classify()` 里 `is_link` 那一支**在本机验不了**：`os.symlink(target_is_directory=True)`
在这台机器上返回成功，实际造出的是普通目录（属性 0x10，无 REPARSE 位），
`os.path.islink` / `stat.S_ISLNK` 全为 False。所以"链接不跟随"是防御性写法，
不是被实测确认过的行为。真要守这条，得在一台能造链接的机器上跑
`output/_sweep_selftest.py` 的 S8。

## 这台机器上删除很贵（实测，不是估算）

| 操作 | 单价 |
|---|---|
| `os.rmdir` 空目录 | 0.163 s/项 |
| `os.remove` 空文件 | 0.174 s/项 |
| `os.rename` | 0.012 s/项 |
| `shutil.rmtree`（含 1.2 个文件的目录） | 0.614 s/项 |

删除比改名贵 14 倍 ⇒ 有过滤驱动（杀软/沙箱）在**删除路径**上做扫描。
按 70,037 项、平均 1.2 个文件算，全量一遍约 **7 小时**。这不是算法慢，
换 `rd /s /q` 实测更慢（0.895 s/项且全失败）。所以：

- `--apply` 是**可反复执行**的（每次重算清单，断了没副作用），分批跑即可。
- 别指望它当构建步骤的收尾钩子用。
"""
import argparse
import ast
import json
import os
import re
import shutil
import stat
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 扫描面要裁干净：仓库里躺着打包暂存（out/）、历史归档（_archive_dist/）、
# 还有一份带了完整 venv 的 PyPI 装机仿真（_uxtest/）。不裁的话要 parse
# 4347 个 .py，实测 65 秒——三次调用就把工具超时打穿。
SKIP_DIRS = {
    "output", "docs", ".git", ".workbuddy", "__pycache__",
    "build", "dist", "node_modules", ".venv", "envs",
    "out", "_archive_dist", "_uxtest", "site-packages", "venv",
}
SKIP_PREFIX = ("_uxtest", "_archive", ".away")
# mkdtemp 的产物形态：前缀（以 _ 或 - 收尾）+ 6~10 位小写随机串。
# 与 CPython tempfile._RandomNameSequence 对齐（字符集 a-z0-9_）。
SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,40}[_\-][a-z0-9_]{6,10}$")
LOG_SFX = (".log", ".out", ".err")
# 永不删名单：别的工具留下的临时目录，不归我们管。
# ★ 手写「不删」是安全方向，手写「删」才是危险方向——所以这张表可以是死名单，
#   而上面那条 SHAPE 必须是从 mkdtemp 命名机制派生的。
NEVER = ("pip-", "python-", "pytest-")


# ---------------------------------------------------------------- 归因 A

def _call_name(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _const_str(node):
    """从调用参数里挖出字面前缀。

    三种写法都要认：
      prefix="g0490_hub_"          → Constant
      prefix="g0490_%s_" % tag     → BinOp(Mod) 的左半边
      "antinel-inbox-"（位置参数）  → Constant
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _const_str(node.left)
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value:
                return v.value
    return None


def source_prefixes():
    """扫仓库源码，收集所有 mkdtemp/tmpdir 的字面前缀。返回 {前缀: 出处}。"""
    out = {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")
                       and not d.startswith(SKIP_PREFIX)]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as f:
                    tree = ast.parse(f.read())
            except (OSError, SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if _call_name(node) not in ("mkdtemp", "tmpdir"):
                    continue
                pre = None
                for kw in node.keywords:
                    if kw.arg == "prefix":
                        pre = _const_str(kw.value)
                if pre is None and node.args:
                    pre = _const_str(node.args[0])
                if pre and len(pre) >= 2:
                    out.setdefault(pre, os.path.relpath(p, ROOT))
    return out


# ---------------------------------------------------------------- 扫描

def _scan_subtree(path, is_dir):
    """返回 (字节数, 子树里最新的 mtime)。

    ★ 为什么不用目录自身的 mtime 判年龄：目录 mtime 只在**直接子项增删**时变，
    把一批旧文件搬进新目录，父目录是"刚建的"而内容是陈年旧货。反过来，
    一个真正在跑的套件不停往里写文件，**子文件**的 mtime 才是活体证据。
    所以年龄一律按「子树最近一次写入」算——这是唯一和"还有人在动它"同源的量。
    """
    newest = 0.0
    if not is_dir:
        try:
            st = os.stat(path)
        except OSError:
            return 0, 0.0
        return st.st_size, st.st_mtime
    total = 0
    try:
        newest = os.stat(path).st_mtime
    except OSError:
        pass
    for dp, dns, fns in os.walk(path, onerror=lambda e: None):
        for name in dns + fns:
            try:
                st = os.stat(os.path.join(dp, name))
            except OSError:
                continue
            total += getattr(st, "st_size", 0)
            if st.st_mtime > newest:
                newest = st.st_mtime
    return total, newest


def classify(name, is_dir, is_link, name_prefixes):
    """返回 (kind, why)。kind ∈ tmpdir / log / foreign。"""
    if is_link:
        return "foreign", "link"          # 链接一律不碰，也不跟随
    for pre in NEVER:
        if name.startswith(pre):
            return "foreign", "other-tool"
    if not is_dir and name.endswith(LOG_SFX):
        for pre in name_prefixes:
            if name.startswith(pre):
                return "log", "source:" + pre
        if SHAPE.match(os.path.splitext(name)[0]):
            return "log", "shape:"
        return "foreign", "log-no-attrib"
    if is_dir:
        for pre in name_prefixes:
            if name.startswith(pre):
                return "tmpdir", "source:" + pre
        if SHAPE.match(name):
            return "tmpdir", "shape:"
        return "foreign", "no-attrib"
    return "foreign", "file-no-attrib"


def scan(tmp_root, prefix_map):
    """返回 (items, foreign_sample)。items 只含可删候选。"""
    names = sorted(os.listdir(tmp_root))
    keys = sorted(prefix_map, key=len, reverse=True)   # 长前缀优先，避免被短前缀抢走
    now = time.time()
    items, foreign = [], []
    for n in names:
        p = os.path.join(tmp_root, n)
        is_link = os.path.islink(p)
        try:
            st = os.lstat(p)
        except OSError as e:
            foreign.append({"name": n, "why": "stat-failed:%s" % type(e).__name__,
                            "mtime": 0, "newest": 0, "idle_min": -1.0, "size": 0})
            continue
        is_dir = not is_link and os.path.isdir(p)
        kind, why = classify(n, is_dir, is_link, keys)
        size, newest = _scan_subtree(p, is_dir)
        rec = {
            "name": n,
            "kind": kind,
            "why": why,
            "mtime": int(st.st_mtime),
            "newest": int(newest),
            "idle_min": round((now - newest) / 60.0, 1) if newest else -1.0,
            "size": size,
        }
        (foreign if kind == "foreign" else items).append(rec)
    return items, foreign


# ---------------------------------------------------------------- 删除

def _force(func, path, _exc):
    """Windows 上只读文件会让 rmtree 半途失败，先去掉只读位再试一次。"""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def do_delete(tmp_root, recs):
    ok, bad = [], []
    for r in recs:
        p = os.path.join(tmp_root, r["name"])
        try:
            if r["kind"] == "log":
                os.remove(p)
            else:
                shutil.rmtree(p, onerror=_force)
        except OSError as e:
            bad.append({"name": r["name"], "err": "%s: %s" % (type(e).__name__, e)})
            continue
        if os.path.exists(p):
            bad.append({"name": r["name"], "err": "删完仍在（回读不通过）"})
        else:
            ok.append(r["name"])
    return ok, bad


# ---------------------------------------------------------------- 主

def _fmt(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fG" % n


def main(argv=None):
    ap = argparse.ArgumentParser(description="清扫 TMP 根的历史临时目录")
    ap.add_argument("--root", default=os.environ.get("TMP") or "D:/_antmp",
                    help="TMP 根（默认取环境变量 TMP）")
    ap.add_argument("--apply", action="store_true", help="真的删（默认只出清单）")
    ap.add_argument("--with-logs", action="store_true", help="连运行日志一起删")
    ap.add_argument("--min-age-minutes", type=float, default=30.0,
                    help="比这更年轻的项不动（默认 30）")
    ap.add_argument("--busy-minutes", type=float, default=5.0,
                    help="有任何项比这更新则拒绝 --apply（默认 5）")
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "output"))
    a = ap.parse_args(argv)

    tmp_root = os.path.abspath(a.root)
    if not os.path.isdir(tmp_root):
        print("TMP 根不存在：%s" % tmp_root)
        return 2
    # 防呆：绝不允许把仓库根或盘根当 TMP 根
    if os.path.abspath(tmp_root) in (os.path.abspath(ROOT),
                                     os.path.splitdrive(tmp_root)[0] + os.sep):
        print("拒绝：--root 指向 %s，不像临时目录根" % tmp_root)
        return 2

    prefix_map = source_prefixes()
    print("源码派生前缀 %d 个（示例：%s）"
          % (len(prefix_map), "、".join(sorted(prefix_map)[:6])))
    items, foreign = scan(tmp_root, prefix_map)

    by_kind = {}
    for r in items:
        by_kind.setdefault(r["kind"], []).append(r)
    n_tmp = len(by_kind.get("tmpdir", []))
    n_log = len(by_kind.get("log", []))
    sz_tmp = sum(r["size"] for r in by_kind.get("tmpdir", []))
    sz_log = sum(r["size"] for r in by_kind.get("log", []))

    print("TMP 根：%s" % tmp_root)
    print("  临时目录 %d 项 / %s" % (n_tmp, _fmt(sz_tmp)))
    print("  运行日志 %d 项 / %s" % (n_log, _fmt(sz_log)))
    print("  归因不了 %d 项（永不删，只列清单）" % len(foreign))
    if foreign:
        for r in foreign[:15]:
            print("    · %-40s %s" % (r["name"], r["why"]))
        if len(foreign) > 15:
            print("    · …另有 %d 项，见清单" % (len(foreign) - 15))

    # 年龄闸：按子树闲置时长（见 _scan_subtree 的注释）
    young = [r for r in items if 0 <= r["idle_min"] < a.min_age_minutes]
    old = [r for r in items if r["idle_min"] >= a.min_age_minutes]
    unknown = [r for r in items if r["idle_min"] < 0]
    print("  年龄闸 %.0f 分钟：放行 %d 项，留下 %d 项，读数不明 %d 项"
          % (a.min_age_minutes, len(old), len(young), len(unknown)))

    # 忙闸：只盯**可归因的脚手架**。别人的临时文件（foreign）一直在写不算数，
    # 否则常驻进程每写一次就把闸卡死，闸就成了摆设。
    busy_items = [r for r in items if 0 <= r["idle_min"] < a.busy_minutes]
    busy = bool(busy_items)
    if busy:
        print("  忙闸：%d 项在 %.0f 分钟内被写过，拒绝删除——"
              % (len(busy_items), a.busy_minutes))
        for r in busy_items[:5]:
            print("    ! %-40s 闲置 %.1f 分钟" % (r["name"], r["idle_min"]))
        print("    （确认那是已知的后台写手，可加 --busy-minutes 0 越过）")

    todo = [r for r in old if r["kind"] == "tmpdir"]
    if a.with_logs:
        todo += [r for r in old if r["kind"] == "log"]

    os.makedirs(a.out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    man = os.path.join(a.out_dir, "tmp_sweep_%s.json" % ts)
    with open(man, "w", encoding="utf-8", newline="\n") as f:
        json.dump({
            "when": ts, "root": tmp_root, "apply": bool(a.apply),
            "with_logs": bool(a.with_logs),
            "min_age_minutes": a.min_age_minutes,
            "prefixes_from_source": prefix_map,
            "counts": {"tmpdir": n_tmp, "log": n_log, "foreign": len(foreign),
                       "old": len(old), "young": len(young),
                       "unknown": len(unknown), "busy": len(busy_items),
                       "planned": len(todo)},
            "items": items, "foreign": foreign,
        }, f, ensure_ascii=False, indent=1)
    print("清单：%s" % os.path.relpath(man, ROOT))

    if not a.apply:
        print("未动手（加 --apply 才删）。计划删 %d 项。" % len(todo))
        return 0
    if busy:
        print("拒绝删除：有 %d 项刚被写过。" % len(busy_items))
        return 3

    ok, bad = do_delete(tmp_root, todo)
    done = os.path.join(a.out_dir, "tmp_sweep_%s.done.json" % ts)
    with open(done, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"when": ts, "root": tmp_root,
                   "deleted": len(ok), "failed": bad}, f,
                  ensure_ascii=False, indent=1)
    print("已删 %d 项，失败 %d 项" % (len(ok), len(bad)))
    for b in bad[:10]:
        print("   ! %s  %s" % (b["name"], b["err"]))
    print("结果：%s" % os.path.relpath(done, ROOT))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
