# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""0.63.0 改名批次 · 唯一工具（五子命令：map / rules / plan / apply / verify）

★ 为什么是**一个**文件而不是三个脚本（九维第 1 条「入口唯一性」）：
  改名需要「映射表 / 排除面 / 严格边界 / 缩写组规则」四件事同时正确。
  写成三个脚本 ⇒ 三份 EXCLUDE、三份正则 ⇒ 同一事实三处实现 ⇒ 必然漂移。
  ⇒ 一个文件、一套常量、五个子命令。**排除面只在这里定义一次。**

★ 与作业单 v1.0 的关系：本工具是作业单「§9 颗粒度自检」里那个唯一缺口（脚本）的填法。
  作业单的每一步都能映射到一个子命令，例外是「步 3 结构收敛」（手改代码，不可自动化）。

用法（**默认不写盘**）：
    python output/_rn_tool.py map                 # 生成映射表 + 自校验，落 output/_rn_map.tsv
    python output/_rn_tool.py rules               # 结构化改名规则表（dry-run）
    python output/_rn_tool.py rules --yes         # 写盘：id:=an、an→legacy_id（含备份＋回读复验）
    python output/_rn_tool.py plan                # dry-run：落 _rn_plan.tsv / _rn_skip.txt，不写盘
    python output/_rn_tool.py apply --yes         # 按 plan 写盘（需 plan 先跑过且 seal 一致）
    python output/_rn_tool.py verify              # 14 条验收（只读；NOTE≠PASS；状态 A 直接 rc=2 不判）

★ **固定顺序**：手工 9 处收敛 → `rules --yes` → `plan` → `apply --yes`
   → `_gen_fallback.py` 重生（先改它的 ORDER_HEAD）→ `verify`
   `rules` 必须在 `plan` 之前：`plan` 的映射在状态 B（legacy_id→id）下同样成立，
   但 `legacy_id` 只有 `rules` 会写；先 plan 后 rules 会得到一份「验不过」的中间态。

★ 设计原则：**能判定的就不猜**。
  缩写组（`MCP-02/03/04`）的形态有 31 处、各不相同，本工具**不预设形态**——
  它把每个成员展开成完整旧号，逐个查映射表：
      · 全部命中 ⇒ 这是规则号缩写组 ⇒ 展开
      · 任一不命中 ⇒ 这不是规则号（是判据号/版本号/别的东西）⇒ **原样不动 + 进 skip.txt 报告**
  于是「31 处是什么形态」这个问题不需要答案，脚本自己判。
"""
import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "output"
MAP_TSV = OUT / "_rn_map.tsv"
RETIRED_TSV = OUT / "_rn_retired.tsv"
PLAN_TSV = OUT / "_rn_plan.tsv"
SKIP_TXT = OUT / "_rn_skip.txt"
PLAN_SEAL = OUT / "_rn_plan.seal"
FROZEN_BASE = OUT / "_rn_frozen_before.txt"
RULES = ROOT / "rules" / "default.json"
FALLBACK_GEN = OUT / "_gen_fallback.py"

# ★ 冻结面：改名期间**一个字节都不许变**。三处，各有理由：
#   · `challenge/chain/`  改了 rule_id 而不改 hash = 自证篡改（演练实测 26 行立刻失配）
#   · `.workbuddy/memory/` 改历史日记 = 伪造记录
#   · `psl/workspace_facts.json` 环境事实唯一真源，含 `_note_*` 历史叙述
# ★ `.psl/audit/`（账本）**故意不在这个清单里**——这是个必须说清的决定：
#   跑任何判据都会调 hook，hook 会写账本 ⇒ 把它算进「零改动」等于让第 12 条**恒红**，
#   而恒红的判据最后一定会被放宽。它对改名的保护由 `excluded()` 承担（目录前缀）。
#   **两处都要守，但只在一处设判据**——这就是「同一事实多处实现」的反面。
FROZEN_FACES = ("challenge/chain", ".workbuddy/memory", "psl/workspace_facts.json")


def _frozen_status():
    """冻结面的 `git status --porcelain`，**过滤未跟踪（`??`）**，按行排序。

    ★ 过滤 `??` 是必须的：未跟踪文件（临时产物、备份目录）怎么写都不算「改历史」。
      把它们算进来，判据就会因与改名无关的动作变红 ⇒ 然后被判据放宽掉。
    ★ 排序是为了让「基线」与「现在」可比：git 的输出顺序不保证稳定。
    """
    try:
        r = subprocess.run(["git", "status", "--porcelain", "--"] + list(FROZEN_FACES),
                           cwd=str(ROOT), capture_output=True, check=True)
    except Exception:
        return None
    lines = [ln for ln in r.stdout.decode("utf-8", "replace").splitlines()
             if ln.strip() and not ln.startswith("??")]
    return "\n".join(sorted(lines))


# ---------------------------------------------------------------- 排除面（唯一真源）
# ★ 这些面**改了就是伪造历史 / 当场蒸发**。作业单 §2 步 7 的七类 + 本轮新增两类。
EXCLUDE_DIR_PREFIX = (
    "challenge/chain/",        # 1 证据链：rule_id 变而 hash 不变 = 自证篡改（实测 26 行立刻失配）
    ".workbuddy/memory/",      # 2 历史日记：改历史 = 伪造记录
    "output/",                 # 9 本工具自己 + 全部评估/演练/作业单文档（通篇旧号，改了就是改写结论）
    ".psl/audit/",             # 10 账本：15 万条真实记录，改了比改证据链更严重
    "psl/ci_debug/",           # 11 跑测结果落盘
    ".git/",
    "node_modules/",
    "__pycache__/",
)
EXCLUDE_EXACT = (
    "psl/workspace_facts.json",       # 5 环境事实唯一真源，含 _note_* 历史叙述
    ".antinelignore",                 # 6 钩子链上不许写
    "references/RULES.md",            # 4 构建器整文件生成的产物
    "references/THREAT_MODEL.md",
    "SKILL.md",
    "psl/SKILL.md",
    # ★ 12 规则表必须**结构化**改写（`rules` 子命令），不许走文本替换。两条硬理由：
    #   ① 文本替换会把 `id` 改成新号，但 `an` 还在 ⇒ 得到 `id == an == AN-001` 的**半改**状态，
    #      而 `legacy_id` 永远不会被创建 ⇒ 映射退化成恒等式、旧账一条都读不出来；
    #   ② 改名后 `legacy_id` 的**值就是旧号**。若规则表仍在文本替换面内，第二次 `plan`
    #      会把 `legacy_id` 的值再换成新号 ⇒ **映射表被自己销毁**，且不报错。
    "rules/default.json",
    # ★ 13 对照表**按定义**就是「旧号 → 新号」的表。把它纳入替换面 = 把表清空，
    #   而且 verify 第 1 条会从此**恒红**（一张永真恒红的判据等于没有判据）。
    "references/ID_MAP.md",
)
EXCLUDE_SUFFIX = (
    ".bak", ".bak-",                 # 3 备份就是备份
    # ★ 0.63.0 实跑补：`.away-<ts>` 是"不要 rm、改名留档"这条纪律的产物
    #   （见 AGENTS.md 与开工清单 E2 的处置），**与 `.bak` 同一族**。
    #   演练卷漏了它：`docs/…夜间任务书 v1.0.md.away-20261019194350` 被 plan 列进
    #   待改清单（2 处），改了就是把留档改写一遍。
    ".away-",
)

# ★ 第 7 类（8 个判据号 SEC-04a/b/c、SEC-05a/b/c、DST-06b/c）**不需要文件级排除**：
#   下面的严格边界正则带 `(?![0-9A-Za-z])`，带小写后缀的号**天然不会被匹配**。
#   这是"用边界规则代替名单"——名单会漏，边界不会。

# ★ 去号的两条（0.63 必须与改名同批做，否则账本长期并行两套命名）。
#   工具**故意不自动替换**它们，因为"去号"不是文本替换：
#     · `GOV-01` 改的是「记到哪个面」——`rules_hit` 里移除、改走 `type:governance`；
#     · `BUDGET-01` 要整条移出 `rules_hit`（它已有专属 type `notice_budget_*`）。
#   这两件都是**带语义的代码改动**，正则做不对。工具只负责一件事：
#   **没做就必红**（verify 第 13 条）。「工具不做 + 判据守住」好过「工具半做」。
RETIRED_IDS = ("GOV-01", "BUDGET-01")
# 说明与「新号」的唯一真源（map 输出用；verify 只读 RETIRED_IDS 的键）
RETIRED_NOTE = {
    "GOV-01": ("DEV-01", "本批去号：改走 type:governance，移出 rules_hit"),
    "BUDGET-01": ("", "本批去号：已有专属 type notice_budget_*，永不回收"),
}
assert set(RETIRED_NOTE) == set(RETIRED_IDS), "RETIRED_NOTE 与 RETIRED_IDS 不同步"


def _read(p):
    """★ newline="" 是必须的，不是风格问题。

    `Path.read_text()` 底层是 `newline=None`（universal newlines），会把 CRLF **折成 LF**；
    而 `_write()` 用 `newline=""` 原样落盘 ⇒ 结果是**静默改 EOL**。
    本仓存在 `w/crlf` 的文件（`git ls-files --eol` 可查），一旦被折成 LF：
    整文件 git diff 重写、产物哈希漂移、`ci/version_check` 的九处承载件比对可能红。
    这个缺陷不会抛异常、不会有提示，只会让「改名」顺手变成「全仓换行符迁移」。
    """
    with open(p, "r", encoding="utf-8", errors="replace", newline="") as f:
        return f.read()


def _write(p, text):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as f:      # newline="" 保住原 EOL
        f.write(text)


# ---------------------------------------------------------------- 映射表
def load_map():
    """从 rules/default.json 得到 {旧号: 新号}，并断言**只有一种状态**。

    两种合法状态（改名前后各一种）：
      A 未改名：id=旧号, an=新号        ⇒ 映射 {id: an}
      B 已改名：id=新号, legacy_id=旧号 ⇒ 映射 {legacy_id: id}
    ★ 两种同时命中 ⇒ 数据半改 ⇒ **必须停**（这正是演练里 `AN-033/03/04` 那种半成品的形态）。
    """
    data = json.loads(_read(RULES))
    rules = data.get("rules") or []
    if not rules:
        raise SystemExit("[map] rules/default.json 里没有 rules 数组")
    have_an = sum(1 for r in rules if r.get("an"))
    have_legacy = sum(1 for r in rules if r.get("legacy_id"))
    n = len(rules)
    if have_an and have_legacy:
        raise SystemExit(
            "[map] 规则表同时存在 %d 条 an 与 %d 条 legacy_id ⇒ 改名只做了一半。拒绝继续。"
            % (have_an, have_legacy))
    if have_legacy:
        m = {r["legacy_id"]: r["id"] for r in rules if r.get("legacy_id")}
        state = "B(已改名: legacy_id→id)"
    elif have_an:
        m = {r["id"]: r["an"] for r in rules if r.get("an")}
        state = "A(未改名: id→an)"
    else:
        raise SystemExit("[map] 规则表既无 an 也无 legacy_id ⇒ 无映射来源")
    # 自校验：单射、唯一、位宽
    # ★ 这里原本用 `assert`。两条理由必须改掉：
    #   ① `python -O` 会**整体跳过** assert ⇒ 安全校验静默消失（最小可开工条件里没写不许 -O，
    #      那就等于没写）；
    #   ② 部分规则有 `an` 时（例如 30/37），assert 抛的是 AssertionError + traceback，
    #      而不是一句人能读懂的拒绝 ⇒ 明早第一眼看到的是红栈，不是原因。
    if len(m) != n:
        raise SystemExit("[map] 映射条数 %d != 规则条数 %d ⇒ 有规则缺 an/legacy_id（半改？）"
                         % (len(m), n))
    _vals = list(m.values())
    if len(set(_vals)) != n:
        _dup = sorted({v for v in _vals if _vals.count(v) > 1})
        raise SystemExit("[map] 新号有重复：%s" % _dup[:5])
    bad = [v for v in _vals if not re.fullmatch(r"[A-Z]{2,6}-\d{3}", v)]
    if bad:
        raise SystemExit("[map] 新号不符 AN-NNN 位宽：%s" % bad[:5])
    return m, state, n


def cmd_map(args):
    m, state, n = load_map()
    rows = sorted(m.items(), key=lambda kv: kv[1])
    _write(MAP_TSV, "".join("%s\t%s\n" % (o, w) for o, w in rows))
    # 已退役号（本批去号的两条）—— 唯一真源 RETIRED_IDS / RETIRED_NOTE，不在这里重写一遍
    retired = [(r,) + RETIRED_NOTE[r] for r in RETIRED_IDS]
    _write(RETIRED_TSV, "".join("%s\t%s\t%s\n" % r for r in retired))
    print("[map] 状态=%s  规则 %d 条  映射 %d 行 -> %s" % (state, n, len(rows), MAP_TSV))
    print("[map] 新号区间 %s .. %s" % (rows[0][1], rows[-1][1]))
    print("[map] 另需人工去号 %d 条（工具不自动做，verify 第 13 条守）：%s"
          % (len(retired), ", ".join(r[0] for r in retired)))
    return 0


# ---------------------------------------------------------------- 规则表结构化改名
def cmd_rules(args):
    """`id := an`、`an` → `legacy_id`。**只有这个子命令能写 rules/default.json。**

    ★ 为什么不用文本替换：见 EXCLUDE_EXACT 里 "rules/default.json" 那两条。
    ★ 为什么做**行级手术**而不是 json.dumps 重排：重排会把整个文件变成一次大 diff，
      审阅者看不出「哪些是改名、哪些是格式抖动」；行级手术每步断言「恰好 1 次」，
      多一次少一次都立刻停（形态变了就是形态变了，不猜）。
    """
    raw = _read(RULES)
    data = json.loads(raw)
    rules = data.get("rules") or []
    n = len(rules)
    if not n:
        raise SystemExit("[rules] rules 数组为空")
    n_an = sum(1 for r in rules if r.get("an"))
    n_lg = sum(1 for r in rules if r.get("legacy_id"))
    if n_lg == n and n_an == 0:
        print("[rules] 已是改名后状态（%d 条全有 legacy_id），无事可做" % n)
        return 0
    if n_lg or n_an != n:
        raise SystemExit("[rules] 半改状态：an=%d legacy_id=%d / 共 %d 条 ⇒ 拒绝（先人工判定）"
                         % (n_an, n_lg, n))
    olds = [r["id"] for r in rules]
    news = [r["an"] for r in rules]
    if len(set(olds)) != n:
        raise SystemExit("[rules] 旧号里有重复")
    if len(set(news)) != n:
        raise SystemExit("[rules] 新号里有重复：%s"
                         % [x for x in set(news) if news.count(x) > 1][:5])
    bad = [x for x in news if not re.fullmatch(r"[A-Z]{2,6}-\d{3}", x)]
    if bad:
        raise SystemExit("[rules] 新号不符位宽：%s" % bad[:5])
    inter = sorted(set(olds) & set(news))
    if inter:
        raise SystemExit("[rules] 新旧号有交集 %s ⇒ 不是平移位，拒绝" % inter[:5])

    if not args.yes:
        print("[rules] dry-run：%d 条将 id:=an、an→legacy_id；前 5 条：" % n)
        for r in rules[:5]:
            print("   %-10s -> %-8s (legacy_id=%-10s)" % (r["id"], r["an"], r["id"]))
        print("[rules] ★ 未写盘。确认后加 --yes")
        return 0

    body = raw
    eol = "\r\n" if "\r\n" in raw else "\n"      # 插行必须用文件自己的 EOL，否则 CRLF 文件里混进裸 LF
    for r in rules:
        o, w = r["id"], r["an"]
        # ★ `,[ \t]*$` 在 CRLF 文件里**匹配不到**，这是本工具最容易让明早当场卡住的一处：
        #   `(?m)$` 位于 `\r` 之后、`\n` 之前，而 `\r` 不属于 `[ \t]`
        #   ⇒ 整条正则 0 次命中 ⇒ 直接 SystemExit「id 行形态异常」，
        #     而人会去怀疑「规则表是不是被改坏了」，实际只是换行符。
        #   实测本仓存在 w/crlf 文件（`git ls-files --eol`），必须显式容 `\r`，
        #   并在替换时**把它带回去**（group(2)）——否则一次改名顺手把 CRLF 变 LF。
        p_id = re.compile(r'(?m)^([ \t]*)"id"[ \t]*:[ \t]*"%s"[ \t]*,([ \t]*\r?)$' % re.escape(o))
        p_an = re.compile(r'(?m)^[ \t]*"an"[ \t]*:[ \t]*"%s"[ \t]*,[ \t]*\r?\n' % re.escape(w))
        k_id, k_an = len(p_id.findall(body)), len(p_an.findall(body))
        if k_id != 1:
            raise SystemExit("[rules] id 行形态异常：%s 匹配 %d 次（应为 1）" % (o, k_id))
        if k_an != 1:
            raise SystemExit("[rules] an 行形态异常：%s 匹配 %d 次（应为 1）" % (w, k_an))
        body = p_an.sub("", body, count=1)                      # 先删 an 行，逗号结构不受影响
        body = p_id.sub(lambda mo: '%s"id": "%s",%s%s"legacy_id": "%s",%s'
                        % (mo.group(1), w, eol, mo.group(1), o, mo.group(2)), body, count=1)

    # 写盘前先验证**构造出来的文本**是合法 JSON 且语义到位（内存验证 → 落盘 → 回读复验）
    try:
        chk = json.loads(body)
    except Exception as e:
        raise SystemExit("[rules] 手术后的文本不是合法 JSON（%r）⇒ 未写盘" % (e,))
    cr = chk.get("rules") or []
    if len(cr) != n or any(r.get("an") for r in cr):
        raise SystemExit("[rules] 手术后校验失败（条数或 an 残留）⇒ 未写盘")
    if [r.get("legacy_id") for r in cr] != olds:
        raise SystemExit("[rules] 手术后 legacy_id 与旧号序列不一致 ⇒ 未写盘")

    bdir = OUT / "_rn_backup_20261031"
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "rules").mkdir(parents=True, exist_ok=True)
    if not (bdir / "rules" / "default.json").is_file():
        (bdir / "rules" / "default.json").write_bytes(RULES.read_bytes())
    _write(RULES, body)

    back = json.loads(_read(RULES))
    br = back["rules"]
    ok = (len(br) == n
          and all(r.get("legacy_id") and not r.get("an") for r in br)
          and all(re.fullmatch(r"[A-Z]{2,6}-\d{3}", r["id"]) for r in br))
    if not ok:
        print("[rules] ★ 回读复验失败 —— 立即用备份回滚：%s" % (bdir / "rules" / "default.json"))
        return 1
    print("[rules] 已写 %d 条：id:=an、an→legacy_id；回读复验通过" % n)
    print("[rules] 备份 %s" % (bdir / "rules" / "default.json"))
    print("[rules] ★ 还有三件工具管不到、但必红的事：")
    print("        ① `hardcoded_rules.declared_but_code_driven` 的键（SLOP-01）要跟着改名")
    print("        ② `hardcoded_rules.code_only` 的三个键（在 rules/default.json:24-34）：")
    print("           GOV-01／BUDGET-01 必须随去号消失；OUT-01 **保留旧号**（等 channel 落地）")
    print("        ③ `output/_gen_fallback.py` 的 ORDER_HEAD 要从 [\"id\",\"an\"] 改成 [\"id\",\"legacy_id\"]")
    print("       verify 的第 8、9 条会把它们判红，别放过。")
    return 0


# ---------------------------------------------------------------- 文件枚举
_FILES_CACHE = None


def tracked_files():
    """只枚举**已跟踪**文件。未跟踪的（账本、临时跑测产物）天然不在面内。

    ★ 加缓存不是为了快，是为了**一致性**：verify 里 4 条腿各遍历一次全仓，
      若中途树变了，四条腿会看到四份不同的文件表，红绿互相矛盾。
      一次枚举、四腿共用，才可能"四条腿说的是同一棵树"。
    """
    global _FILES_CACHE
    if _FILES_CACHE is not None:
        return _FILES_CACHE
    try:
        r = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT),
                           capture_output=True, check=True)
    except Exception as e:
        raise SystemExit("[files] git ls-files 失败（%r）—— 本工具只改已跟踪文件，"
                         "不接受猜路数" % (e,))
    names = [x for x in r.stdout.decode("utf-8", "replace").split("\0") if x]
    _FILES_CACHE = [n.replace("\\", "/") for n in names]
    return _FILES_CACHE


BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".whl", ".gz", ".zip",
              ".pdf", ".pkl", ".pyc", ".woff", ".woff2", ".ttf", ".eot"}


def excluded(rel):
    if rel in EXCLUDE_EXACT:
        return "面:" + rel
    for p in EXCLUDE_DIR_PREFIX:
        if rel.startswith(p):
            return "目录:" + p
    if os.path.basename(rel).startswith("_note_"):
        # 6 笔记类文件（历史叙述）：改了就是把当时的注记改成今天的说法
        return "笔记前缀:_note_"
    for s in EXCLUDE_SUFFIX:
        if s in os.path.basename(rel):
            return "备份后缀:" + s
    if Path(rel).suffix.lower() in BINARY_EXT:
        return "二进制"
    return None


# ---------------------------------------------------------------- 替换规则（唯一真源）
def _build_res(olds):
    alts = "|".join(re.escape(o) for o in sorted(olds, key=len, reverse=True))
    # 严格边界：前不许接标识符字符；后不许接字母数字
    #   · `SEC-05a` 后接小写 ⇒ 不匹配 ⇒ 判据号天然安全（第 7 类排除面自动成立）
    #   · `DST-02-BASH` 后接 `-` ⇒ 匹配 ⇒ 分桶键正确改成 `AN-010-BASH`
    strict = re.compile(r"(?<![A-Za-z0-9_])(%s)(?![0-9A-Za-z])" % alts)
    # 缩写组：PREFIX-02/03/04 （尾部至少一段 /NN）
    abbr = re.compile(r"(?<![A-Za-z0-9_])([A-Z]{2,6})-(\d{2})((?:/\d{2})+)(?![0-9A-Za-z])")
    return strict, abbr


def transform(text, m):
    """返回 (新文本, 替换次数, 跳过项[])。缩写组先于严格替换。"""
    strict, abbr = _build_res(m.keys())
    notes = []

    def _expand(mo):
        prefix, first, rest = mo.group(1), mo.group(2), mo.group(3)
        members = [prefix + "-" + first] + [prefix + "-" + x for x in rest.split("/")[1:]]
        news = [m.get(x) for x in members]
        if any(x is None for x in news):
            missing = [mm for mm, x in zip(members, news) if x is None]
            notes.append("缩写组未展开(非规则号) %s 缺 %s" % (mo.group(0), missing[:3]))
            return mo.group(0)                      # 原样不动
        return "/".join(news)                        # AN-033/AN-034/AN-035（每个都带前缀）

    text, n_abbr = abbr.subn(_expand, text)

    hits = []

    def _sub(mo):
        old = mo.group(1)
        hits.append(old)
        return m[old]

    text, n_strict = strict.subn(_sub, text)
    return text, (n_abbr, n_strict, hits), notes


def cmd_plan(args):
    m, state, n = load_map()
    files = tracked_files()
    plan, skips, per_old = [], [], {}
    skipped_faces = 0
    for rel in files:
        why = excluded(rel)
        if why:
            skipped_faces += 1
            skips.append("%s\t%s" % (rel, why))
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            orig = _read(p)
        except Exception as e:
            skips.append("%s\t读取失败:%r" % (rel, e))
            continue
        if not any(o in orig for o in m):
            continue
        new, stats, notes = transform(orig, m)
        n_abbr, n_strict, hits = stats
        if new == orig:
            continue
        # ★ 必须存**字节数**，不是字符数（`len(str)`）。这一处是典型的"单位错"：
        #   `apply` 的回读复验用 `os.path.getsize()`，那是**字节**；
        #   而 UTF-8 下中文占 3 字节 ⇒ 任何含中文的文件都 `len(str) != getsize`
        #   ⇒ `apply` 每次都报「字节数与 plan 预测不符」并 `return 1`。
        #   那不是"树变了"，是**判据自己的单位错了**；而 100% 必红的判据最后一定被放宽。
        plan.append((rel, n_abbr, n_strict,
                     len(orig.encode("utf-8")), len(new.encode("utf-8"))))
        for h in hits:
            per_old[h] = per_old.get(h, 0) + 1
        for nt in notes:
            skips.append("%s\t%s" % (rel, nt))
    # 落盘（plan 只写 output/）
    _write(PLAN_TSV, "file\tabbr\tstrict\tbytes_before\tbytes_after\n" +
           "".join("%s\t%d\t%d\t%d\t%d\n" % row for row in plan))
    _write(SKIP_TXT, "\n".join(skips) + ("\n" if skips else ""))
    # 封印：把 plan 的内容哈希写下来，apply 必须对得上（防"plan 与实际不同步"）
    seal = hashlib.sha256(
        (PLAN_TSV.read_text(encoding="utf-8") + str(len(files))).encode("utf-8")).hexdigest()
    _write(PLAN_SEAL, seal + "\n")

    print("[plan] 状态=%s 跟踪文件 %d｜排除 %d｜待改 %d" % (state, len(files), skipped_faces, len(plan)))
    print("[plan] 替换次数：缩写组 %d，严格 %d（合计 %d）"
          % (sum(r[1] for r in plan), sum(r[2] for r in plan), sum(r[1] + r[2] for r in plan)))
    print("[plan] 命中旧号 %d 种 / %d 次" % (len(per_old), sum(per_old.values())))
    miss = sorted(set(m) - set(per_old))
    print("[plan] 规则表里有但代码里没出现的旧号 %d 种（正常，纯数据列）：%s"
          % (len(miss), ",".join(miss[:8]) + (" ..." if len(miss) > 8 else "")))
    print("[plan] plan -> %s" % PLAN_TSV)
    print("[plan] skip -> %s（%d 行，**必须人工过目**）" % (SKIP_TXT, len(skips)))
    print("[plan] seal -> %s" % seal[:16])
    print("[plan] ★ 未写盘。核对 _rn_plan.tsv 与 _rn_skip.txt 后再 apply --yes")
    return 0


def cmd_apply(args):
    if not args.yes:
        raise SystemExit("[apply] 必须显式 --yes")
    if not PLAN_SEAL.is_file():
        raise SystemExit("[apply] 没有 plan 封印 ⇒ 先跑 plan")
    want = _read(PLAN_SEAL).strip()
    got = hashlib.sha256(
        (PLAN_TSV.read_text(encoding="utf-8") + str(len(tracked_files()))).encode("utf-8")
    ).hexdigest()
    if want != got:
        raise SystemExit("[apply] plan 封印不符（树在 plan 之后变过）⇒ 重跑 plan")
    # ★ 冻结面基线必须在**任何写盘动作之前**取。它记录的是「改名开始前，冻结面已经脏的
    #   那部分」——verify 要的是**增量**为零，不是「绝对干净」。这两件事差别很大：
    #   改名当晚日记本来就在写，若要求绝对干净，第 12 条会一上来就红，
    #   然后人开始「修红」，第一条判据就被放宽了。（这是判据退化的标准路径。）
    fz = _frozen_status()
    if fz is None:
        raise SystemExit("[apply] 取不到冻结面 git status ⇒ 无法记录基线，拒绝继续"
                         "（无基线的 verify 会把既有改动误判成改名污染）")
    _write(FROZEN_BASE, fz + "\n")
    print("[apply] 冻结面基线已记录（%d 行）-> %s"
          % (len(fz.splitlines()) if fz else 0, FROZEN_BASE))
    m, state, n = load_map()
    # 备份（作业单 §4 清单）：改之前，不是出事之后
    bdir = OUT / "_rn_backup_20261031"
    bdir.mkdir(parents=True, exist_ok=True)
    rows = [ln.split("\t") for ln in _read(PLAN_TSV).strip().splitlines()[1:] if ln.strip()]
    done = 0
    for rel, _a, _s, _b, _c in rows:
        src = ROOT / rel
        dst = bdir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.is_file():
            dst.write_bytes(src.read_bytes())        # 字节级复制，不经过文本模式
        orig = _read(src)
        new, _stats, _notes = transform(orig, m)
        if new == orig:
            continue
        _write(src, new)                             # newline="" ⇒ 保住原 EOL
        done += 1
    print("[apply] 已写 %d 个文件；备份在 %s" % (done, bdir))
    # ★ 写盘后必须回读复验（不许信写成功）。三条腿，缺一不可：
    #   ① 旧号零残留
    #   ② JSON 仍合法 —— 文本替换最常见的后果是把引号/逗号弄坏，而这一步不会报错
    #   ③ 字节数与 plan 预测一致 —— 不一致说明 apply 时树已经和 plan 不同（seal 之外的第二道）
    strict, _abbr = _build_res(m.keys())
    bad_resid, bad_json, bad_size = [], [], []
    for rel, _a, _s, before, after in rows:
        txt = _read(ROOT / rel)
        if strict.search(txt):
            bad_resid.append(rel)
        if rel.endswith(".json"):
            try:
                json.loads(txt)
            except Exception as e:
                bad_json.append("%s (%r)" % (rel, e))
        got = os.path.getsize(ROOT / rel)
        if got != int(after):
            bad_size.append("%s 实际 %d / 预期 %s" % (rel, got, after))
    if bad_resid:
        print("[apply] ★ 回读仍有旧号残留：%s" % bad_resid[:6])
    if bad_json:
        print("[apply] ★ 回读 JSON 已损坏：%s" % bad_json[:4])
    if bad_size:
        print("[apply] ★ 字节数与 plan 预测不符（树在 plan 之后变过？）：%s" % bad_size[:4])
    if bad_resid or bad_json or bad_size:
        return 1
    print("[apply] 回读三腿通过：零残留 / JSON 合法 / 字节数与预测一致")
    return 0


# ---------------------------------------------------------------- 验收
def cmd_verify(args):
    fails, oks, notes = [], [], []
    m, state, n = load_map()

    # ★ 状态门（不是判据，是"还没到该跑的时候"）
    #   状态 A 下跑 verify 会得到满屏红——那是**预期**，不是缺陷。
    #   不区分开，人会开始"修红"，然后第一条判据就被放宽了。
    if state.startswith("A"):
        print("[verify] 当前规则表处于**未改名**状态（id=旧号, an=新号）。")
        print("         verify 是改名后的验收器，此刻的红全部是预期，不要去修。")
        print("         正确顺序：手工 9 处收敛 → rules --yes → plan → apply --yes → verify")
        return 2

    # 1 严格边界旧号残留（排除面外）
    #   ★ 0.63.0 实跑补：`legacy_id` 的**值就是旧号**，它出现在 `_FALLBACK`（pre_tool_use.py
    #     里的硬编码副本）和 ID_MAP 里是**设计**，不是残留。不排除 ⇒ 第 1 条**恒红**
    #     （37 条 = 37 处），而恒红判据最后一定会被放宽。先把 `"legacy_id": "..."` 的值
    #     抹空再扫，抹的是"值"不是"字段名"，所以「字段丢了」照样能红（第 2 条守）。
    _LEGACY_ASSIGN = re.compile(r'"legacy_id"\s*:\s*"[^"]*"')
    strict, abbr = _build_res(m.keys())
    resid = {}
    for rel in tracked_files():
        if excluded(rel) or not (ROOT / rel).is_file():
            continue
        t = _read(ROOT / rel)
        k = len(strict.findall(_LEGACY_ASSIGN.sub('"legacy_id":""', t)))
        if k:
            resid[rel] = k
    (oks if not resid else fails).append(
        "1 旧号残留 = 0" if not resid else "1 旧号残留 %d 处 / %d 文件：%s"
        % (sum(resid.values()), len(resid), list(resid.items())[:5]))

    # 2 规则表字段
    data = json.loads(_read(RULES))
    rs = data["rules"]
    ids = [r.get("id") for r in rs]
    probs = []
    if not all(re.fullmatch(r"[A-Z]{2,6}-\d{3}", i or "") for i in ids):
        probs.append("存在非 NNN 位宽 id")
    if len(set(ids)) != len(ids):
        probs.append("id 重复")
    if any(r.get("an") for r in rs):
        probs.append("an 未删")
    if state.startswith("B") and not all(r.get("legacy_id") for r in rs):
        probs.append("legacy_id 不全")
    (oks if not probs else fails).append(
        "2 规则表 %d 条：id 全 NNN 位宽且唯一、an 已删、legacy_id 齐全" % len(rs) if not probs
        else "2 " + "；".join(probs))

    # 3 _FALLBACK 与规则表集合一致
    pt = _read(ROOT / "hooks" / "pre_tool_use.py")
    mo = re.search(r"^_FALLBACK = \[(.*?)^\]", pt, re.S | re.M)
    if not mo:
        fails.append("3 _FALLBACK 抠取失败（容器格式变了 ⇒ 静默失效）")
    else:
        try:
            fb = eval("[" + mo.group(1) + "]")
        except Exception as e:
            fails.append("3 _FALLBACK eval 失败 %r" % (e,))
            fb = None
        if fb is not None:
            fids = {r.get("id") for r in fb}
            if fids == set(ids):
                oks.append("3 _FALLBACK %d 条与规则表集合相同" % len(fb))
            else:
                fails.append("3 _FALLBACK 与规则表不符：多 %s 少 %s"
                             % (sorted(fids - set(ids))[:3], sorted(set(ids) - fids)[:3]))

    # 4 分桶键不带旧号（★ 0 命中 ≠ 通过：说明调用形态不是字面量 ⇒ 记 NOTE）
    keys = re.findall(r'notice_gate\(\s*"([^"]+)"', pt)
    bad_key = [k for k in keys if strict.search(k)]
    if not keys:
        notes.append("4 notice_gate 无字面量实参 ⇒ 本腿无法判定（不是通过）")
    elif bad_key:
        fails.append("4 分桶键仍是旧号：%s" % bad_key[:5])
    else:
        oks.append("4 notice_gate 分桶键 %d 个、无旧号" % len(keys))

    # 5 构建器闸门归属：0.63 只做**键换新号**（机械 2 行），改读 gate 字段留给 0.65
    bp = _read(ROOT / "scripts" / "build_package.py")
    if re.search(r'_GATE_OVERRIDE\s*=\s*\{[^}]*"[A-Z]{2,6}-\d{2}(?!\d)', bp):
        fails.append("5 _GATE_OVERRIDE 仍按旧号点名")
    elif re.search(r'_GATE_OVERRIDE\s*=\s*\{[^}]*"[A-Z]{2,6}-\d{3}"', bp):
        notes.append("5 _GATE_OVERRIDE 已换新号键（0.63 可接受）；改读 gate 字段排 0.65")
    else:
        oks.append("5 _GATE_OVERRIDE 已不按号点名")

    # 6 drift_audit 正则位宽
    #    ★ 这里原本是 `re.search(r"...\\\\d...") or re.search(r"...\\d...")`。
    #      前半段在 raw string 里是「四个反斜杠 + d」，匹配的是字面 `\\d`——**源码里不存在**，
    #      所以它是一条永远为假的死代码，被 `or` 遮住了：看着像双重保险，实际只有后半段在工作。
    #      只留一条，加 `(?!\d)` 防止 `\d{2}` 命中 `\d{2,3}` 的前缀。
    da = _read(ROOT / "ci" / "drift_audit.py")
    if re.search(r"\[A-Z\]\{3\}-\\d\{2\}(?!\d)", da):
        fails.append("6 drift_audit 仍是 [A-Z]{3}-\\d{2}（AN-001 匹配不上 ⇒ A10 空转）")
    else:
        oks.append("6 drift_audit 正则已放宽")

    # 7 排除面自证（这是"排除规则自己的正控"，也是唯一能抓「排除静默失效」的判据）
    #    ★ 为什么必须有：`excluded()` 是路径前缀匹配。目录改名、路径写错、大小写不符时
    #      它**静默返回 None**，于是那些文件进入替换面；而第 1 条「旧号残留」照样绿
    #      （因为文件已被改过、里面没有旧号了）——**排除失效与"改对了"长得一模一样**。
    #      所以要让"最危险的目录"各自报一个非零数：0 就是规则没生效。
    probe = {"challenge/chain/": 0, ".workbuddy/memory/": 0}
    for rel in tracked_files():
        for k in probe:
            if rel.startswith(k):
                probe[k] += 1
    dead = sorted(k for k, v in probe.items() if v == 0)
    if dead:
        fails.append("7 排除面失效：这些目录一个文件都没排到（路径已改名？）⇒ %s" % dead)
    else:
        oks.append("7 排除面自证：%s" % "，".join("%s=%d" % kv for kv in sorted(probe.items())))

    # 8 hardcoded_rules：两组**必须都查**
    #    ★ 原本只查 `declared_but_code_driven`（SLOP-01），把 `code_only` 漏了。
    #      而 `code_only` 的三个键（OUT-01 / GOV-01 / BUDGET-01）正是本批要去号的两条
    #      ＋ 一条必须保留的。四道口子同时漏，谁也抓不住：
    #        · 第 1 条「旧号残留」查不到 —— 它们不是 `m` 的键（`m` 只来自 rules 数组）
    #        · 第 13 条「去号残留」也查不到 —— `rules/default.json` 在 EXCLUDE_EXACT 里
    #      ⇒ 结果是：`GOV-01`/`BUDGET-01` 在 code_only 里原样留着，而全部判据绿。
    #    ★ `code_only` 的键**不能**要求「在 ids 里」：它们按定义就不在 rules 数组里。
    #      该查的是「退役号必须消失、未收编的 OUT-01 必须保留」。
    hr = (data.get("hardcoded_rules") or {})
    dc = (hr.get("declared_but_code_driven") or {})
    co = (hr.get("code_only") or {})
    probs8 = []
    orphan = sorted(set(dc) - set(ids))
    if orphan:
        probs8.append("code-driven 悬空键 %s（改名后必须跟着改）" % orphan)
    bad_co = sorted(set(co) & set(RETIRED_IDS))
    if bad_co:
        probs8.append("code_only 仍含已退役号 %s（去号必须同步这一处）" % bad_co)
    if "OUT-01" not in co:
        probs8.append("code_only 缺 OUT-01（它未收编，必须保留旧号到 channel 落地）")
    if probs8:
        fails.append("8 " + "；".join(probs8))
    else:
        keep = sorted(set(co) - set(RETIRED_IDS))
        oks.append("8 hardcoded_rules：code-driven 键一致、code_only 无退役号（保留 %s）"
                   % ",".join(keep))

    # 9 兜底生成器的字段顺序（不同步改 ⇒ j_fallback_matches_rules 必红，且是「数据错」不是「判据错」）
    gf = _read(FALLBACK_GEN)
    mo_h = re.search(r"ORDER_HEAD\s*=\s*\[(.*?)\]", gf, re.S)
    if not mo_h:
        notes.append("9 未找到 _gen_fallback.py 的 ORDER_HEAD ⇒ 本腿无法判定")
    else:
        head = [x for x in re.findall(r'"([^"]+)"', mo_h.group(1))]
        if "legacy_id" in head and "an" not in head:
            oks.append("9 兜底生成器 ORDER_HEAD = %s" % head)
        elif head == ["id", "an"]:
            fails.append('9 ORDER_HEAD 仍是 ["id","an"] ⇒ 重生兜底集必红')
        else:
            notes.append("9 ORDER_HEAD 形态未识别：%s" % head)

    # 10 升级判定不许再靠号前缀（这是 0.63 唯一一条「不收敛就静默降级」的点）
    if re.search(r'startswith\(\s*"NET"', pt):
        fails.append('10 仍有 startswith("NET") ⇒ 改名后 net_mode=block 静默失效')
    else:
        oks.append("10 升级判定不再靠号前缀")

    # 11 _compress_ids 的位宽
    #    ★ 先纠正一个说法：`%02d` **不会截断**三位号（`"%02d" % 100 == "100"`）。
    #      真实缺陷是**位宽不一致**：它把 1..37 格式化成 `01..37`，产出 `AN-01..37`，
    #      而真实 id 是 `AN-001..037` ⇒ 这个压缩串**拿回去反查会全部落空**，
    #      但它在报告里长得完全正常。所以判据要查「函数体里还在用 02d」，不是查某个字面格式串。
    mo_c = re.search(r"def _compress_ids\(.*?(?=\ndef |\Z)", bp, re.S)
    if not mo_c:
        notes.append("11 未找到 _compress_ids 定义 ⇒ 本腿无法判定（可能已改名或已删除）")
    elif re.search(r"%0?2d|:\s*0?2d", mo_c.group(0)):
        fails.append("11 _compress_ids 仍按两位补零 ⇒ 压缩产物 AN-01..37 与 AN-001..037 不一致"
                     "（反查全落空，报告里看不出来）")
    else:
        oks.append("11 _compress_ids 位宽已放宽")

    # 12 冻结面：相对 apply 前基线的**增量**必须为空
    #    ★ 原版是「git status 必须为空」。这个写法有一处必红的假阳：
    #      改名当晚日记正在写（本轮就是），`git status` 一上来就非空 ⇒ 判红，
    #      而红的是**与改名无关**的改动 ⇒ 人开始「修红」⇒ 判据被放宽。
    #    ★ 也不能与 HEAD 比：规则表、SKILL.md、RULES.md 本来就该变
    #      （前者是 rules 子命令改的，后两者要由构建器重生成）。
    #    正确做法：apply 时记基线，verify 只问「相对基线有没有增量」。
    now = _frozen_status()
    if now is None:
        notes.append("12 取不到 git status ⇒ 本腿无法判定")
    elif not FROZEN_BASE.is_file():
        notes.append("12 无冻结面基线（本次没跑过 apply --yes）⇒ 本腿无法判定")
    else:
        base = _read(FROZEN_BASE).strip()
        if now == base:
            oks.append("12 冻结面相对基线零增量（基线 %d 行：证据链／日记／环境事实）"
                       % (len(base.splitlines()) if base else 0))
        else:
            fails.append("12 冻结面在本次改名中有增量（相对基线）：\n%s" % now[:600])

    # 13 去号的两条必须消失（工具不自动做，所以必须由判据守）
    #    ★ 为什么单列一条：`GOV-01`/`BUDGET-01` 不在映射表里 ⇒ 第 1 条「旧号残留」**查不到它们**。
    #      没有这一条，「去号没做」会安静地通过全部 12 条判据，然后账本永久并行两套命名。
    code_ext = (".py", ".json", ".md", ".txt", ".html", ".toml", ".cfg", ".yml", ".yaml")
    leftover = {}
    for rel in tracked_files():
        if excluded(rel) or not rel.endswith(code_ext):
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        t = _read(p)
        got = [r for r in RETIRED_IDS if re.search(r"(?<![A-Za-z0-9_-])%s(?![0-9A-Za-z])"
                                                   % re.escape(r), t)]
        if got:
            leftover[rel] = got
    if leftover:
        fails.append("13 去号未做：%d 个文件仍引用 %s\n      %s"
                     % (len(leftover), list(RETIRED_IDS),
                        list(leftover.items())[:5]))
    else:
        oks.append("13 去号残留 = 0（GOV-01／BUDGET-01 已从代码面清除）")

    # 14 缩写组不许被错误展开
    #    ★ 演练里真实出现过 `MCP-02/03/04` → `AN-033/03/04`（后两个短号未展开），
    #      这种形态**不含任何旧号** ⇒ 第 1 条查不出来、第 2 条查不出来、十二条全绿。
    #      它是本批最典型的「改错了反而更干净」的形态。
    bad_abbr = {}
    # ★ 0.63.0 实跑补：只认**规则家族**的前缀。原实现扫 `[A-Z]{2,6}`，
    #   于是 `FZ-001/002`（窗口标题格式号，不是规则）被当成残缺展开报红。
    #   假红与真红长得一样，而假红的下场是把判据放宽 —— 所以按家族白名单收窄。
    _fams = set(i.rsplit("-", 1)[0] for i in ids if i)
    for rel in tracked_files():
        if excluded(rel) or not rel.endswith(code_ext):
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        t = _read(p)
        # 前面不能是 `/` 或标识符字符：否则 URL 路径（`.../ABC-001/2`）会误报
        hit = [h for h in re.findall(r"(?<![/\w-])[A-Z]{2,6}-\d{3}/\d{1,3}(?![\d])", t)
               if h.rsplit("-", 1)[0] in _fams]
        if hit:
            bad_abbr[rel] = hit[:5]
    if bad_abbr:
        fails.append("14 缩写组展开不完整（新号后面挂了短号）：%s" % list(bad_abbr.items())[:5])
    else:
        oks.append("14 缩写组无残缺展开（无 AN-NNN/NN 形态）")

    print("=" * 70)
    for o in oks:
        print("  PASS  " + o)
    for f in fails:
        print("  FAIL  " + f)
    for t in notes:
        print("  NOTE  " + t)
    print("=" * 70)
    print("结果：%d PASS / %d FAIL / %d NOTE（NOTE ≠ PASS：那是「本腿无法判定」）"
          % (len(oks), len(fails), len(notes)))
    return 0 if not fails else 1


def main():
    ap = argparse.ArgumentParser(description="0.63.0 改名唯一工具")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("map", help="生成映射表").set_defaults(fn=cmd_map)
    r = sub.add_parser("rules", help="结构化改名规则表（id:=an, an->legacy_id）")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(fn=cmd_rules)
    sub.add_parser("plan", help="dry-run，不写盘").set_defaults(fn=cmd_plan)
    a = sub.add_parser("apply", help="写盘（需 --yes）")
    a.add_argument("--yes", action="store_true")
    a.set_defaults(fn=cmd_apply)
    sub.add_parser("verify", help="14 条验收（NOTE≠PASS）").set_defaults(fn=cmd_verify)
    ns = ap.parse_args()
    return ns.fn(ns)


if __name__ == "__main__":
    sys.exit(main())
