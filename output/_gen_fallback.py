# SPDX-License-Identifier: CC-BY-SA-4.0
"""一次性量具：从 `rules/default.json` 重新生成 `hooks/pre_tool_use.py` 的 `_FALLBACK`。

为什么要有这个文件（0.57.0 立、0.62.0 重建）：
  兜底集是「规则文件被篡改/读不出」那一刻唯一还在的保护。它不是手抄件，**必须与主表全等**。
  0.57.0 之前它是 17 条手工副本，漏了 20 条、还缩水 47 个 pattern，而判据只查单向子集 ⇒ 天天绿。
  0.62.0 给每条规则加了 `an` 字段（AN-001..037），兜底集没跟 ⇒ `j_fallback_matches_rules`
  立刻红：「SEC-01 与主表不等（1 个字段）：['an']」。**判据工作正常**，红的是数据。

写法约束（血泪）：
  ① 纯字面量。`scripts/verification_tests.py:_fallback_ids()` 用
     `re.search(r"^_FALLBACK = \\[(.*?)^\\]", src, re.S | re.M)` 抠出正文再 `eval`，
     所以块内**不许出现任何表达式/函数调用**，也不许在行首出现 `]`。
  ② **双引号**。该判据按 `^_FALLBACK = \\[` 定位；`repr()` 给单引号虽能 eval，
     但历史上 `_FALLBACK = [` 与 `[` 后换行的形状被写死过，保持原样最稳。
  ③ 生成完必须**自校验**：用与判据完全相同的正则抠回来、eval、与主表逐字段比。
     本脚本末尾就做这件事；不通过则非零退出、不写文件。

用法：python output/_gen_fallback.py [--check]
  --check 只比对不写盘（CI/夜间自检用）。
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules", "default.json")
HOOK = os.path.join(ROOT, "hooks", "pre_tool_use.py")

# 与 `scripts/verification_tests.py:_fallback_ids()` 逐字相同的提取式。
# 改这里必须同步那边 —— 两处不一致会出现「生成器说对了、判据说没对」。
EXTRACT = re.compile(r"^_FALLBACK = \[(.*?)^\]", re.S | re.M)

# 字段输出顺序：照主表出现顺序走，`an` 紧跟在 `id` 之后（它是身份的一部分）。
ORDER_HEAD = ["id", "an"]
ORDER_TAIL = ["name", "category", "severity", "type", "enabled",
              "tool_names", "apply_to_tools", "target",
              "file_patterns", "command_patterns", "content_patterns",
              "placeholder_patterns", "exclude_patterns",
              "detection", "check", "codepoints", "platforms",
              "whitelist_domains", "compound_nonprimary", "specific_from",
              "name_min_len_for_distance", "name_near_miss_max_distance",
              "description", "description_zh",
              "remediation", "remediation_zh", "label_zh", "note"]


def _lit(v):
    """Python 字面量（不是 JSON —— 没有 true/false/null）。"""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        # json.dumps 给的转义对 Python 字符串同样合法（\\u 转义、\\" 转义），
        # 但 JSON 会把控制字符写成 \\u00xx —— Python 也认。
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(_lit(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (_lit(k), _lit(x)) for k, x in v.items()) + "}"
    raise TypeError("不支持的类型：%r" % (type(v),))


def _emit_value(key, val, indent):
    """短值行内、长值折行（纯粹为了 diff 可读，不影响语义）。"""
    one = _lit(val)
    pad = " " * indent
    if len(one) + indent <= 96 or not isinstance(val, list) or not val:
        return one
    inner = " " * (indent + 1)
    return "[\n" + ",\n".join(inner + _lit(x) for x in val) + "]"


def render(rules):
    out = ["_FALLBACK = ["]
    for r in rules:
        keys = [k for k in ORDER_HEAD if k in r]
        keys += [k for k in ORDER_TAIL if k in r]
        keys += [k for k in r if k not in keys]          # 未登记的新字段也不许丢
        first = keys[0]
        out.append('    {%s: %s,' % (_lit(first), _emit_value(first, r[first], 6)))
        for k in keys[1:]:
            comma = "" if k == keys[-1] else ","
            out.append('     %s: %s%s' % (_lit(k), _emit_value(k, r[k], 6), comma))
        out.append("     },")
    out.append("]")
    return "\n".join(out)


def extract(src):
    m = EXTRACT.search(src)
    if not m:
        raise SystemExit("★ 抠不到 _FALLBACK 块（正则与 hooks/pre_tool_use.py 不同源？）")
    if m.group(0).rstrip().splitlines()[-1] != "]":
        raise SystemExit("★ 块尾不是独占一行的 ]")
    return m.start(), m.end(), eval("[" + m.group(1) + "]")


def main():
    rules = json.loads(open(RULES, encoding="utf-8").read())["rules"]
    if not rules:
        raise SystemExit("★ 主表 0 条 —— 空集不许当通过")
    new_block = render(rules)
    src = open(HOOK, encoding="utf-8").read()
    s, e, old = extract(src)
    same = old == rules

    print("主表 %d 条 / 兜底 %d 条 / 现况%s" % (len(rules), len(old), "全等" if same else "不等"))
    if not same:
        by = {r["id"]: r for r in rules}
        for r in old:
            L = by.get(r.get("id"))
            if L is None:
                print("  兜底多出：%s" % r.get("id"))
                continue
            ks = [k for k in (set(r) | set(L)) if r.get(k) != L.get(k)]
            if ks:
                print("  %s 差 %d 个字段：%s" % (r["id"], len(ks), ks[:6]))

    if "--check" in sys.argv:
        return 0 if same and src[s:e] == new_block else 1

    out = src[:s] + new_block + src[e:]
    open(HOOK, "w", encoding="utf-8", newline="\n").write(out)

    # ---- 自校验：按判据的口径读回来，逐字段比 ----
    again = open(HOOK, encoding="utf-8").read()
    _, _, back = extract(again)
    if back != rules:
        raise SystemExit("★ 写盘后自校验失败：兜底仍与主表不等（不许提交）")
    print("写出 %d 字节；回读自校验：与主表逐字段全等。" % (len(new_block)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
