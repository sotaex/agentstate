#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""重生仓内的 `references/ID_MAP.md` —— **与构建器同一个函数**，不另写一份生成逻辑。

为什么要有这个脚本：
  构建器只往 `pkg/`（暂存包）里写 `references/ID_MAP.md`；仓库树里那份是要被
  git 跟踪、给人看的。如果手写它、或者另写一段生成逻辑，两份必然漂
  （第一顽症：同一事实多处实现），而且**漂的方向不可知** —— 你无法判断
  仓库那份是旧数据还是新数据。

  ⇒ 本脚本只做一件事：import 构建器里的 `id_map_md()` 与
    `_write_generated_md()`，算正文、走**同一个写出点**写盘。
    没有第二处拼接，包括 SPDX 头。

用法：
    python output/_gen_idmap.py            # 写 references/ID_MAP.md
    python output/_gen_idmap.py --check    # 只比对不写；不一致 rc=1（可当判据用）

为什么给 `--check`：
  「文件存在」不是判据 —— 数据变了它不会红。要能回答的是
  「仓库里这份**是不是**当前数据的函数」，所以必须能算出来跟它比。
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # output/ 的上一级 = 项目根
BUILDER = ROOT / "scripts" / "build_package.py"
RULES = ROOT / "rules" / "default.json"
DEST = ROOT / "references" / "ID_MAP.md"


def _load_builder():
    """按路径加载 `scripts/build_package.py`，**不执行它的 main**。

    ★ 为什么用 importlib 而不是 `sys.path.insert` + `import`：
      后者会让 `build_package` 这个名字进入 sys.modules，可能与真的包名冲突；
      而且本脚本与被加载模块同在项目树里，按路径加载是最小假设。
    ★ 前提：该模块**模块级无副作用**（只定义常量与函数）。若它将来在模块级
      读文件或起进程，本脚本会连带受影响 —— 那时应该把那部分挪进函数，
      而不是在本脚本里规避。
    """
    if not BUILDER.is_file():
        raise SystemExit("找不到构建器：%s" % BUILDER)
    spec = importlib.util.spec_from_file_location("_bp_for_idmap", BUILDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv):
    bp = _load_builder()
    if not RULES.is_file():
        raise SystemExit("找不到规则表：%s" % RULES)

    body = bp.id_map_md(RULES)                  # 缺 legacy_id 时它自己会 raise
    want = bp._GENERATED_MD_SPDX + body

    if "--check" in argv:
        if not DEST.is_file():
            print("[idmap] 缺文件：%s" % DEST)
            return 1
        have = DEST.read_text(encoding="utf-8")
        if have != want:
            print("[idmap] 与当前数据不一致：%s" % DEST)
            print("        仓库 %d 字节 / 应为 %d 字节"
                  % (len(have.encode("utf-8")), len(want.encode("utf-8"))))
            return 1
        print("[idmap] 一致：%s（%d 字节）" % (DEST, len(have.encode("utf-8"))))
        return 0

    bp._write_generated_md(DEST, body)

    # ★ 写完必须回读自证 —— 不复读的「已写」只是「write_text 没抛异常」。
    #   要确认的是三件事：文件在、头在第一行、表行数等于规则条数。
    txt = DEST.read_text(encoding="utf-8")
    if not txt.startswith(bp._GENERATED_MD_SPDX):
        raise SystemExit("[idmap] 写出的文件缺 SPDX 头 —— 写出点被绕过了")
    import json
    n_rules = len((json.loads(RULES.read_text(encoding="utf-8")).get("rules") or []))
    n_rows = sum(1 for ln in txt.splitlines()
                 if ln.startswith("| `AN-"))
    if n_rows != n_rules:
        raise SystemExit("[idmap] 表行数 %d != 规则条数 %d —— 对照表不完整"
                         % (n_rows, n_rules))
    print("[idmap] 已写：%s（%d 字节，表 %d 行 = 规则 %d 条）"
          % (DEST, len(txt.encode("utf-8")), n_rows, n_rules))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
