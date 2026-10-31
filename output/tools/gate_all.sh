#!/usr/bin/env bash
# SPDX-License-Identifier: CC-BY-SA-4.0
#
# 三线共用的全量闸门唯一入口（A / B / C 三线，主工作区与所有 worktree 通用）。
#
# ★★★ 为什么必须有这个脚本（不是为了省打字，是为了修一个真实缺陷）：
#   闸门自己**已经有锁**（ci/delivery_gate.py 的 _acquire_lock，O_CREAT|O_EXCL、
#   三态判活、陈旧锁改名让开），但锁的路径是按「工作区根」算的：
#       _SNAP_DIR = ANTINEL_GATE_STATE_DIR or <工作区根>/.psl/gate
#   而 .psl/ 在 .gitignore 里 ⇒ **worktree 里没有 .psl** ⇒
#     · 主工作区跑闸门 ⇒ 锁在  D:/psl/poc/antinel-security/.psl/gate/run.lock
#     · a064 树跑闸门   ⇒ 锁在  .../.worktrees/a064/.psl/gate/run.lock
#   两把锁互不可见 ⇒ 两个闸门可以同时跑 ⇒ 基线快照与日志被交错写入。
#   这不是"可能"，是 2026-10-13 真实发生过的：两个闸门并发，日志被写成一行
#   "0481 RED"，追了 20 分钟幽灵红，最后靠基线快照才证明那次其实是全绿。
#
# ★ 修法：**不另造一把锁**（那是"一件事两处实现"），而是让三条线指向同一个
#   状态目录，用闸门自带的锁实现跨线互斥。这个脚本只做一件事：
#   把 ANTINEL_GATE_STATE_DIR 固定到「主仓根的 .psl/gate」，然后原地跑闸门。
#
# 用法（三条线完全一样，在主树或任意 worktree 里都行）：
#     bash output/tools/gate_all.sh              # 全量 34 套（25–34 分钟）
#     bash output/tools/gate_all.sh --hook       # 快道（提交钩子用的那个）
#     bash output/tools/gate_all.sh --only 0431  # 单套（调试用，秒级）
#     bash output/tools/gate_all.sh --quick      # 快跑
#     bash output/tools/gate_all.sh --status     # 只看锁有没有被占，不跑闸门
#
# ★ 参数以 `python ci/delivery_gate.py --help` 为准，别照抄这段注释。
#   （本脚本第一版把 `--dry` 写进来了，实际那是 S2-483 判据自己的参数，
#     闸门会报 unrecognized arguments —— 注释比实现更容易过期。）
#
set -u

# ---- 1. 定位：当前工作区（可能是 worktree）与三者共享的 .git ----
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "[FATAL] 不在 git 工作区里" >&2; exit 2; }

COMMON_REL="$(git rev-parse --git-common-dir 2>/dev/null)"
# 主树返回 ".git"（相对），worktree 返回绝对路径 —— 统一成绝对
COMMON_ABS="$(cd "$REPO_ROOT" && cd "$COMMON_REL" && pwd)"
MAIN_ROOT="$(dirname "$COMMON_ABS")"

# ---- 2. 状态目录：固定在主仓根，三线共享 ----
# 必须转成 Windows 路径：/d/psl/... 这种 MSYS 路径交给 Python 会被读成 \d\psl
STATE_DIR_WIN="$(cygpath -w "$MAIN_ROOT/.psl/gate")"
export ANTINEL_GATE_STATE_DIR="$STATE_DIR_WIN"
LOCK="$MAIN_ROOT/.psl/gate/run.lock"

# ---- 3. 本机硬约束：只有 %LOCALAPPDATA%\Temp 能删目录 ----
# C:\Temp 与 D 盘整盘都是 WinError 5（ACL 正常、单文件可删、整目录不可删）
: "${TMP:=C:\\Users\\大马\\AppData\\Local\\Temp}"
: "${TEMP:=$TMP}"
: "${TMPDIR:=$TMP}"
export TMP TEMP TMPDIR
export CODEBUDDY_SAFE_DELETE_BULK_STATE_DIR="$TMP\\codebuddy-safe-delete-bulk"
export CODEBUDDY_SAFE_DELETE_BULK_THRESHOLD=100000

# ---- 4. 解释器 ----
# 不要用裸 python：默认解释器不带 setuptools；若解析到 Windows Store 占位符
# 会静默返回 rc=0 且零输出（踩过）
PY="${ANTINEL_PY:-/c/Users/大马/.workbuddy/binaries/python/versions/3.13.12/python}"
if [ ! -x "$PY" ]; then
    echo "[FATAL] 解释器不存在: $PY（可用 ANTINEL_PY=... 覆盖）" >&2; exit 2
fi

echo "──────────────────────────────────────────────────────────────"
echo " 作用树    $REPO_ROOT"
echo " 共享状态  $STATE_DIR_WIN"
echo " 运行锁    $LOCK"
echo " 判据脚本  ci/delivery_gate.py"
echo "──────────────────────────────────────────────────────────────"

# ---- 5. --status：只看锁，不跑闸门（三条线开工前都该先看一眼）----
if [ "${1:-}" = "--status" ]; then
    if [ -f "$LOCK" ]; then
        echo "⚠ 锁存在 —— 可能有人正在跑全量闸门。"
        echo "  锁内 pid: [$(cat "$LOCK" 2>/dev/null)]"
        echo "  提醒：空内容 ≠ 没有锁（写 pid 有空窗，闸门把空串按「占用」处理）。"
        echo "  确认对方已结束（进程不在）后，闸门会自动把陈旧锁改名让开，不用手工删。"
        exit 3
    fi
    echo "✓ 空闲：没有 run.lock，可以跑。"
    exit 0
fi

# ---- 6. 原地跑闸门（闸门自带的锁会拒绝并发并给人话）----
cd "$REPO_ROOT" || exit 2
exec env PYTHONPATH= PYTHONIOENCODING=utf-8 "$PY" -E -X utf8 ci/delivery_gate.py "$@"
