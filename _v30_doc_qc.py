# -*- coding: utf-8 -*-
"""v3.0 方案件的交付前质检：结构四检 + 引用闭合 + 百分比自洽 + 异常字符 + 粘连。

用法：
    python _v30_doc_qc.py <file.md>        # 正常跑，退出码 0=绿
    python _v30_doc_qc.py --self           # 量具自检（阳性须红、阴性须绿）
"""
import io, os, re, sys, unicodedata

# ---------------- 基础读取 ----------------
def load(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        raw = f.read()
    return raw

def lines_of(raw):
    return raw.replace("\r\n", "\n").split("\n")

# ---------------- 结构抽取 ----------------
# ★ 本仓标题的实际写法是「## 2. 标题」：数字之后带一个点。
#   初版正则的分隔符写成了 [\s、]，不含点号 ⇒ 一级节号一个都没进编号空间 ⇒ 33 处假红。
#   ⇒ 量具界的既有纪律：正则的结束条件必须与标题的实际写法各取一份样本对齐。
HEAD_RE = re.compile(r"^(#{1,6})\s+([0-9]+(?:\.[0-9]+)*)\s*[.、：:]?\s*(.*)$")
SEC_RE  = re.compile(r"^\|\s*([0-9]+(?:\.[0-9]+)+)\s*\|")

def heads(raw):
    """本件的编号空间：标题里的节号 + 表格首格的节号。"""
    s = set()
    for ln in lines_of(raw):
        m = HEAD_RE.match(ln)
        if m:
            s.add(m.group(2))
        m2 = SEC_RE.match(ln)
        if m2:
            s.add(m2.group(1))
    return s

def table_blocks(lines):
    """返回 [(start_line, [row lines], ncols_header)]"""
    out, cur = [], None
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("|"):
            if cur is None:
                cur = [i, [], None]
            cur[1].append(ln)
            n = ln.count("|")
            if cur[2] is None:
                cur[2] = n
        else:
            if cur:
                out.append(cur); cur = None
    if cur:
        out.append(cur)
    return [(s + 1, rows, nc) for s, rows, nc in out]

# ---------------- 检查项 ----------------
def c_eol(raw):
    crlf = raw.count("\r\n")
    bare = raw.count("\n") - crlf
    bad = 0
    if crlf and bare:
        bad += 1
    return bad, "CRLF=%d 裸LF=%d" % (crlf, bare)

def c_table(lines):
    msgs = []
    for start, rows, nc in table_blocks(lines):
        if len(rows) < 2:
            msgs.append("行%d 只有一行，不成表" % start); continue
        if not re.match(r"^\s*\|[\s:\-\|]+\|\s*$", rows[1]):
            msgs.append("行%d 第二行不是分隔行" % (start + 1))
        for j, r in enumerate(rows):
            if r.count("|") != nc:
                msgs.append("行%d 竖线数 %d != 表头 %d" % (start + j, r.count("|"), nc))
        if nc - 1 > 6:
            msgs.append("行%d 表格列数 %d 超过建议上限" % (start, nc - 1))
    return msgs

def c_dup_head(lines):
    seen, msgs = {}, []
    for i, ln in enumerate(lines):
        m = HEAD_RE.match(ln)
        if not m: continue
        key = (len(m.group(1)), m.group(3).strip())
        if key in seen:
            msgs.append("重复标题 %r 于行 %d 与 %d" % (key[1], seen[key], i + 1))
        else:
            seen[key] = i + 1
    return msgs

def c_secgap(lines):
    hs = sorted({x for x in heads("\n".join(lines)) if re.match(r"^\d+$", x)},
                key=lambda s: int(s))
    msgs = []
    for a, b in zip(hs, hs[1:]):
        if int(b) - int(a) != 1:
            msgs.append("一级节号缺口 %s -> %s" % (a, b))
    return msgs

def c_xref(raw, known):
    """引用闭合。三条合法性（按既有体例，顺序不可换）：
       ① 同一行 14 字符内有版本前缀 ⇒ 跨版本引用，合法；
       ② 所在表格块内任意一行含版本前缀 ⇒ 表头已声明版本，合法；
       ③ 否则必须落在本件节号内。
    """
    msgs = []
    lines = lines_of(raw)
    tbl_ver = set()
    for start, rows, _nc in table_blocks(lines):
        if any(re.search(r"v\d+\.\d+", r) for r in rows):
            for k in range(start - 1, start - 1 + len(rows)):
                tbl_ver.add(k)
    for i, ln in enumerate(lines):
        for m in re.finditer(r"§\s*([0-9]+(?:\.[0-9]+)*)", ln):
            n = m.group(1)
            pre = ln[max(0, m.start() - 14):m.start()]
            if re.search(r"v\d+\.\d+", pre) or i in tbl_ver:
                continue
            if n not in known:
                msgs.append("行%d §%s 不在本件节号内" % (i + 1, n))
    return msgs

def fenced(lines):
    """返回与 lines 等长的布尔表：True 表示该行位于围栏代码块内部。

    ★ 初版只豁免了反引号行内代码，漏了围栏代码块 ⇒ 命令行示例里的每一个
      路径片段都被判成孤立英文（交接文件首跑 36 处假红中 34 处来自围栏）。
      这与 c_glue 曾经踩过的是同一类坑：「查少」型检查必须先把合法形态枚举全。
      代价（必须写明）：此后围栏内的英文一律不再报警 —— 围栏本就是给命令、
      路径、输出样本用的，这正是它该被豁免的地方；代价是围栏内真混入了
      外来字符时不会报，故 F 外来字符仍对围栏生效（F 不过滤围栏）。
    """
    out, on = [], False
    for ln in lines:
        if ln.lstrip().startswith("```"):
            out.append(False)
            on = not on
            continue
        out.append(on)
    return out

BAD_CHARS = re.compile(r"[\u0370-\u03FF\u0400-\u04FF\u0590-\u05FF\u0600-\u06FF\u0E00-\u0E7F]")
def c_badchar(lines):
    return ["行%d 含外来字符 %r" % (i + 1, ln[:60]) for i, ln in enumerate(lines) if BAD_CHARS.search(ln)]

CODE_SPAN = re.compile(r"`[^`]*`")
WORD_RE   = re.compile(r"[A-Za-z][A-Za-z\-]{2,}")
ALLOW = {"Antinel",          # 产品名，属合法内容；代价：此后本仓其他文档里的 Antinel 亦不再报警
         "python", "json", "jsonl", "git", "VCT", "check", "ignore", "hook", "paramedic",
         "OK", "AND", "OR", "print", "rm", "dist", "env", "tmp", "zzz", "src", "head",
         "II", "III", "IV", "Ia", "IIa",
         # 2026-10-10 增补（交接文件轮）：三个专有名词。
         # 代价须写明：此后正文中任何位置的 PSL / Windows / bash 都不再报警，
         # 若将来有人把某个新引入的英文术语写成这三个词之一，本检查看不见。
         "PSL",       # 项目名，与 Antinel 同类
         "Windows",   # 操作系统名，运行环境声明的固有内容
         "bash",      # 命令解释器名，命令行示例的固有内容
         }
def c_word(lines):
    msgs = []
    f = fenced(lines)
    for i, ln in enumerate(lines):
        if f[i]:
            continue
        s = CODE_SPAN.sub(" ", ln)
        for w in WORD_RE.findall(s):
            if w in ALLOW or w.lower() in {a.lower() for a in ALLOW}: continue
            msgs.append("行%d 孤立英文词 %r" % (i + 1, w))
    return msgs

LIST_RE = re.compile(r"^\s*(?:[-*+]\s|\d+[.)、]\s)")
def c_glue(lines):
    """段落粘连：两个正文行之间 0 空行。

    ★ 初版漏了两类合法的多行结构 ⇒ 37 处假红：① 列表项（连续的两行本来就紧贴）
      ② 围栏代码块内部（它的行不以任何 markdown 标记开头）。
      ⇒ 这两类必须显式排除，否则「查少」这一类检查会把自己没见过的合法形态全判成缺陷。
    """
    msgs = []
    fence = False
    for i in range(1, len(lines)):
        prev, cur = lines[i - 1], lines[i]
        if cur.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        if not cur.strip() or not prev.strip(): continue
        if cur.startswith(("#", "|", ">", "    ")) or prev.startswith(("#", "|", ">")): continue
        if LIST_RE.match(cur) or LIST_RE.match(prev): continue
        msgs.append("行%d 与上一行粘连" % (i + 1))
    return msgs

# ★ 分子分母允许千分位逗号（文档里写作 12,284 / 16,723），初版只认 \d+ ⇒ 1 处假红。
PCT_RE = re.compile(r"(\d+(?:\.\d+)?)%[（(]\s*([\d,]+)\s*/\s*([\d,]+)\s*[）)]")
def c_pct(raw):
    msgs = []
    for m in PCT_RE.finditer(raw):
        p = float(m.group(1))
        a = int(m.group(2).replace(",", ""))
        b = int(m.group(3).replace(",", ""))
        if b == 0:
            msgs.append("分母为 0：%s" % m.group(0)); continue
        if abs(a / b * 100 - p) > 0.15:
            msgs.append("百分比不自洽：%s（应为 %.1f%%）" % (m.group(0), a / b * 100))
    return msgs

BARE_PCT_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)%(?!\s*[（(]\s*[\d,]+\s*/)")

def c_bare_pct(raw):
    msgs = []
    for i, ln in enumerate(lines_of(raw)):
        for m in BARE_PCT_RE.finditer(ln):
            msgs.append("行%d 百分比无分母：%s%%" % (i + 1, m.group(1)))
    return msgs

# ---------------- 汇总 ----------------
def run(raw):
    lines = lines_of(raw)
    known = heads(raw)
    checks = []
    bad, note = c_eol(raw);                 checks.append(("A 行尾一致", ["混合行尾 " + note] if bad else []))
    checks.append(("B 表格结构", c_table(lines)))
    checks.append(("C 重复标题", c_dup_head(lines)))
    checks.append(("D 节号连续", c_secgap(lines)))
    checks.append(("E 引用闭合", c_xref(raw, known)))
    checks.append(("F 外来字符", c_badchar(lines)))
    checks.append(("G 孤立英文", c_word(lines)))
    checks.append(("H 段落粘连", c_glue(lines)))
    checks.append(("I 百分比自洽", c_pct(raw)))
    checks.append(("J 百分比分母", c_bare_pct(raw)))
    return checks, known

def report(raw, title="<目标>"):
    checks, known = run(raw)
    total = 0
    print("== 质检：%s ==" % title)
    print("   编号空间 %d 个：%s" % (len(known), " ".join(sorted(known, key=lambda s: [int(x) for x in s.split(".")]))))
    for name, msgs in checks:
        flag = "OK " if not msgs else "红 "
        print("  %s %-12s %d" % (flag, name, len(msgs)))
        for m in msgs[:8]:
            print("        - %s" % m)
        total += len(msgs)
    print("  合计 %d 项待处理" % total)
    return 1 if total else 0

# ---------------- 量具自检 ----------------
SELF = {
 "阳性": "# X\n## 1 甲\n\n| a | b |\n|---|---\n| 1 | 2 | 3 |\n\n重复 §9.9 引用\n\n## 1 甲\n\n百分之 50.0%（1 / 3）\n\n## 3 丙\n\n增长 30%\n\n一段\n紧接着的一段\n",
 "阴性": "# X\n## 1 甲\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n参见本件 §1，以及 v2.0 §4\n\n## 2 乙\n\n占比 50.0%（1 / 2）\n\n一段\n\n另一段\n",
 # 专测 F 外来字符与 G 孤立英文：这两道在上两份样本里从未被证明会变红
 "阳性二": "# X\n## 1 甲\n\n一段正常的中文说明用于对照。\n\n这里混入了外来字符 αβγ и да 以及一个 strayness 单词。\n",

 # 2026-10-10 增补（交接文件轮）：围栏豁免必须有双向证据。
 # 只加豁免不加这两份，等于没人证明过「围栏外的英文仍然会红」。
 "阴性二": ("# X\n## 1 甲\n\n"
            "```bash\n"
            "PY=\"C:/Users/name/.workbuddy/binaries/python/versions/3.13.12/python.exe\"\n"
            "cd /d/psl/poc/antinel-security\n"
            "git status --short\n"
            "```\n\n"
            "上面是命令行示例，其中的英文与路径不应报警。\n\n"
            "## 2 乙\n"),
 "阳性三": ("# X\n## 1 甲\n\n"
            "```bash\n"
            "echo some english words inside a fence\n"
            "```\n\n"
            "围栏之外出现了一个 strayness 这样的孤立英文词。\n\n"
            "## 2 乙\n"),
}

def self_test():
    print("== 量具自检 ==")
    rc_ok = True
    for kind, txt in (("阴性", SELF["阴性"]), ("阳性", SELF["阳性"]), ("阳性二", SELF["阳性二"]),
                      ("阴性二", SELF["阴性二"]), ("阳性三", SELF["阳性三"])):
        rc = report(txt, kind)
        want = 0 if kind.startswith("阴性") else 1
        ok = (rc == want)
        # ★ 分辨力核对：光验 rc 不够 —— 若把围栏豁免写成「全文豁免」，
        #   阴性二仍会绿，只有阳性三能抓到「围栏外的英文也不报了」这种过度豁免。
        if kind == "阳性三":
            checks, _k = run(txt)
            g = [m for name, msgs in checks if name.startswith("G") for m in msgs]
            if len(g) != 1:
                ok = False
                print("   分辨力不足：G 应恰好 1 项（只报围栏外那个词），实得 %d" % len(g))
        print("   %s 期望 rc=%d 实得 %d ⇒ %s" % (kind, want, rc, "通过" if ok else "失败"))
        if not ok: rc_ok = False
        print("")
    print("自检结论：%s" % ("通过" if rc_ok else "失败"))
    return 0 if rc_ok else 1

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--self":
        sys.exit(self_test())
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    raw = load(sys.argv[1])
    sys.exit(report(raw, os.path.basename(sys.argv[1])))
