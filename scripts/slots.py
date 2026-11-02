# SPDX-License-Identifier: Apache-2.0
"""槽位求值器：82 个槽位的唯一求值实现（规则登记表：`rules/slots.json`）。

设计约束（逐条都有出处，不是我的偏好）：

1. **唯一实现**（并行约定 R4 / 九维 1）
   46 个槽位共用本模块的六个算子，不各写一份。加槽位＝改 JSON，不加代码。

2. **四态，不是布尔**（九维 1「测不出不报 PASS」＋ 九维 8「数据版本迁移」）
   judged_hit / judged_clean / undecidable / not_collected
   ★ 字段缺失 ⇒ undecidable，**绝不当 clean**。四态互斥且穷尽。

3. **不二次实现产品口径**（九维 5 / 铁律 8）
   日锚、链校验、规则哈希一律 import 产品模块或读产品产出，不在这里重算。

4. **账本两类文件必须分开**（实测教训）
   `.psl/audit/` 下同时有 `YYYY-MM-DD.jsonl`（链上记录，有 type/hash）
   和 `lock_events.jsonl`（锁事件流水，5779 条、无 type、不在链上）。
   按目录扫会把流水当记录 ⇒ 读数全错。本模块只认日期文件名。

5. **六个算子，不许第七个**（施工计划 §2.3 / 风险 R1）
   count / ratio / exists / set_diff / sequence / monotonic
   每个算子在分母为 0 时必须返回 undecidable（空集比较是第十四族假绿常客）。
"""
from __future__ import annotations

import json
import os
import re
import sys

REGISTRY_REL = os.path.join("rules", "slots.json")

# 四态（互斥穷尽）
HIT = "judged_hit"
CLEAN = "judged_clean"
UNDECIDABLE = "undecidable"
NOT_COLLECTED = "not_collected"

ALL_STATES = (HIT, CLEAN, UNDECIDABLE, NOT_COLLECTED)

_DAY_FILE = re.compile(r"^\d{4}-\d{2}-\d{2}\.jsonl$")

#: 六个算子，与 rules/slots.json 的 operators.allowed 必须逐字一致
OPERATORS = ("count", "ratio", "exists", "set_diff", "sequence", "monotonic")


# ─────────────────────────── 登记表 ───────────────────────────
def validate_registry(reg):
    """校验登记表，返回问题清单（空＝通过）。

    ★ 抽成纯函数（不吃文件）：正控喂真表、负控喂变异表，**同一把尺子**。
      在闸门里另写一份校验逻辑＝第二套口径 ⇒ 必然分叉（铁律 8）。
    """
    problems = []
    if not isinstance(reg, dict):
        return ["登记表不是对象：%r" % (type(reg).__name__,)]
    slots = reg.get("slots")
    if not isinstance(slots, list):
        return ["slots 不是数组"]
    denom = reg.get("denominator")
    if denom != len(slots):
        problems.append("denominator=%r 但 slots=%d 条（分母必须等于清单）"
                        % (denom, len(slots)))

    ids = [s.get("id") for s in slots]
    exts = [s.get("ext_id") for s in slots]
    if len(set(ids)) != len(ids):
        problems.append("id 有重复（%d 条 / %d 个不同）" % (len(ids), len(set(ids))))
    if len(set(exts)) != len(exts):
        problems.append("ext_id 有重复（%d 条 / %d 个不同）"
                        % (len(exts), len(set(exts))))
    seqs = [s.get("seq") for s in slots]
    if seqs != list(range(1, len(slots) + 1)):
        problems.append("seq 不是 1..%d 连续（实际 %r…）"
                        % (len(slots), seqs[:5]))

    allowed_forms = {"judged", "probe", "annotated", "recorded"}
    allowed_status = {"implemented", "partial", "unregistered"}
    need = ("id", "ext_id", "seq", "family", "name", "order", "question",
            "form", "reader", "evidence_class", "action_cap", "timing",
            "observable_id", "status")
    for s in slots:
        miss = [k for k in need if k not in s]
        if miss:
            problems.append("%s 缺必填字段 %r" % (s.get("id"), miss))
            continue
        if s["form"] not in allowed_forms:
            problems.append("%s 的 form=%r 不在四形态内" % (s["id"], s["form"]))
        if s["status"] not in allowed_status:
            problems.append("%s 的 status=%r 不在三态内" % (s["id"], s["status"]))
        # 分诊结论（2026-11-02）：只有命中的槽位需要它，但它一旦写了就必须合规 ——
        # 报告要按这个字段把「真现象」与「尺子问题」分开，拼错一个字母就会
        # 静默落进 unclassified，读者以为那条没分诊。
        _tr = s.get("triage")
        if _tr is not None:
            if not isinstance(_tr, dict):
                problems.append("%s 的 triage 不是对象" % (s["id"],))
            else:
                if _tr.get("class") not in ("real", "defect", "calibration"):
                    problems.append("%s 的 triage.class=%r 不在 real/defect/calibration 内"
                                    % (s["id"], _tr.get("class")))
                if _tr.get("state") not in ("open", "fixed"):
                    problems.append("%s 的 triage.state=%r 不在 open/fixed 内"
                                    % (s["id"], _tr.get("state")))
                if _tr.get("env") not in ("any", "dev", "user"):
                    problems.append("%s 的 triage.env=%r 不在 any/dev/user 内"
                                    % (s["id"], _tr.get("env")))
        # 判据型必须声明取数通道（否则「判」这件事无从谈起）。
        # ★ 必须带 status 维度：status="unregistered" 的槽位本轮**明确不接线**，
        #   probe=null 是设计如此。漏判状态位会把「按计划留白」读成「违规」，
        #   九维 9「文档与代码同锚」就退化成了噪声。
        if s["status"] != "unregistered" and s["form"] == "judged" and not s.get("probe"):
            problems.append("%s 是 judged 却没有 probe（判据无从取数）" % (s["id"],))
        # 已接线的判据必须能答「命中算不算异常」——没有 predicate 就没有答案，
        #   会静默落进 clean（铁律 1：测不出不许报 PASS）。
        if s["status"] == "implemented" and s["form"] == "judged" and not s.get("predicate"):
            problems.append("%s 已 implemented 却无 predicate（命中也判不出好坏）"
                            % (s["id"],))

    # 登记的条数必须与 counts 自报的一致（九维 9：数字机器核验）
    reg_n = sum(1 for s in slots if s.get("status") != "unregistered")
    declared = (reg.get("counts") or {}).get("registered")
    if declared is not None and declared != reg_n:
        problems.append("counts.registered=%r 但实际登记 %d 条"
                        % (declared, reg_n))

    # 算子白名单
    for op in (reg.get("operators") or {}).get("allowed", []):
        if op not in OPERATORS:
            problems.append("声明了未实现的算子 %r" % (op,))

    # 每个 predicate 的 op 必须在白名单内
    for s in slots:
        pred = s.get("predicate") or {}
        if not pred:
            continue
        op = pred.get("op")
        if op not in OPERATORS:
            problems.append("%s 用了未实现的算子 %r" % (s["id"], op))
    return problems


def load_registry(root):
    """读登记表。读不到 ⇒ 抛异常（不许静默返回空表 —— 空表会让全部槽位变 not_collected）。"""
    p = os.path.join(str(root), REGISTRY_REL)
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    problems = validate_registry(data)
    if problems:
        raise ValueError("登记表不合规：" + "；".join(problems[:5]))
    return data


def slots_by_id(reg):
    return {s["id"]: s for s in reg["slots"]}


# ─────────────────────────── 上下文 ───────────────────────────
def _day_files(audit_dir):
    """只返回链上日文件；lock_events.jsonl / sidecar 一律排除。

    ★ 为什么必须这么写（实测）：audit 目录里 lock_events.jsonl 有 5779 条记录，
      它们没有 type、没有 hash、不在链上。按目录扫会把流水当记录。
    """
    if not os.path.isdir(audit_dir):
        return []
    out = []
    for fn in sorted(os.listdir(audit_dir)):
        if _DAY_FILE.match(fn):
            out.append(os.path.join(audit_dir, fn))
    return out


#: 哨兵：某个记录类型在全部历史里从未出现过 ⇒ 我们没有这个生产者。
#: 见到它必须报 undecidable，**不许**把 count=0 读成「没发生」。
#: 这是第十四族假绿（空集比较）的堵口：先断 before>0。
NO_PRODUCER = object()


class _NeverFired(int):
    """计数为 0，但**代码里有写入点**——即「生产者存在，从未被触发」。

    为什么必须与普通 0 分开：两者在报告里是两句话 ——
      「本窗口 0 次」 vs 「这个通道自装上起一次都没跑过」。
    后者若被读成前者，就是把「没测」说成「没事」（铁律 1）。
    """

    def __new__(cls, value, field):
        obj = super().__new__(cls, value)
        obj.field = field
        return obj


class Context(object):
    """一次读全，probe 之间共享；任何一项读不到就置 None 并记 why。"""

    def __init__(self, root, audit_dir=None, max_days=7, history_days=0,
                 read_history=True):
        self.root = str(root)
        self.audit_dir = audit_dir or os.path.join(self.root, ".psl", "audit")
        self.max_days = max_days
        self.why = {}
        all_days = _day_files(self.audit_dir)
        self.days = all_days[-max_days:]
        self.history_days = all_days if history_days <= 0 else all_days[-history_days:]
        self.records = self._read_records()
        # ★ read_history=False 是给闸门用的：闸门验的是**求值器对不对**，
        #   不是今天的读数。扫 34 个历史日要 4 秒，闸门预算 <5 秒，不能拿来干这个。
        #   ⚠️ 关掉之后「有写入点但从未触发」这类判断会退化成普通 0 —— 所以
        #   闸门里绝不能拿这个 Context 的结论当每日读数看。
        if read_history:
            self.history_type_counts = self._read_history_types()
        else:
            self.history_type_counts = {}
            self.history_pre_total = 0
            self.history_hit_total = 0
            self.history_rule_ids = {}
        self.declared_types = self._scan_declared_types()
        self.day_manifest = self._read_json("day_manifest.json")
        self.manifest = self._read_json_abs(
            os.path.join(self.root, "psl", "manifest.json"))
        # 宿主盾状态：监理自己的存活、hook 注册文件、注册哈希，都只在这一份里
        self.host_shield = self._read_json_abs(
            os.path.join(os.path.expanduser("~"), ".antinel", "host_shield.json"))
        self._cache = {}

    def _scan_declared_types(self):
        """扫产品代码里**真写了**哪些 `"type": "<name>"` 字面量。

        为什么必须用这个而不是「历史里有没有」：
            历史里 0 条有两种完全相反的含义 ——
              ① 生产者在，但从未触发（可能是好事：每次 deny 都被尊重）
              ② 生产者根本不存在（死代码：定义了但零实现）
            用历史判会把这二者混成一个。所以「有没有生产者」只能查代码，
            而且必须用 AST（铁律 3：数调用点用 AST 不用文本正则）。
        """
        import ast
        found = set()
        targets = []
        for d in ("hooks", "tools"):
            base = os.path.join(self.root, d)
            if not os.path.isdir(base):
                continue
            for fn in sorted(os.listdir(base)):
                if fn.endswith(".py") and ".away-" not in fn:
                    targets.append(os.path.join(base, fn))
        for p in targets:
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    tree = ast.parse(f.read())
            except (SyntaxError, OSError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                for k, v in zip(node.keys, node.values):
                    if (isinstance(k, ast.Constant) and k.value == "type"
                            and isinstance(v, ast.Constant)
                            and isinstance(v.value, str)):
                        found.add(v.value)
        return found

    def _read_history_types(self):
        """一遍扫全部历史，同时得出三样：type 计数、判据命中基线、规则号分布。

        ★ 为什么一次扫出三样：34 个日文件、单日 5–8 MB，分三趟读＝三倍 IO，
          而且三趟之间文件还可能变（跑测中途改树＝作废）。一次读定。
        ★ 命中基线只数「pre_tool_use 里 rules_hit 的条数 / pre_tool_use 条数」，
          不重新实现「什么算命中」—— 那是产品的事（铁律 8）。
        """
        counts = {}
        pre_total = 0
        hit_total = 0
        rule_ids = {}
        for fp in self.history_days:
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        t = rec.get("type")
                        if t:
                            counts[t] = counts.get(t, 0) + 1
                        if t != "pre_tool_use":
                            continue
                        pre_total += 1
                        for h in rec.get("rules_hit") or []:
                            rid = h.get("rule_id") if isinstance(h, dict) else h
                            if rid:
                                hit_total += 1
                                rule_ids[rid] = rule_ids.get(rid, 0) + 1
            except OSError as e:
                self.why["hist:%s" % os.path.basename(fp)] = repr(e)
        self.history_pre_total = pre_total
        self.history_hit_total = hit_total
        self.history_rule_ids = rule_ids
        return counts

    # —— 读盘三件 ——
    def _read_records(self):
        recs = []
        bad = 0
        for fp in self.days:
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            recs.append(json.loads(line))
                        except ValueError:
                            bad += 1
            except OSError as e:
                self.why["read:%s" % os.path.basename(fp)] = repr(e)
        if bad:
            # 坏行不吞：它本身就是「留痕不可追溯」的证据
            self.why["bad_json_lines"] = bad
        return recs

    def _read_json(self, name):
        return self._read_json_abs(os.path.join(self.audit_dir, name))

    def _read_json_abs(self, p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError) as e:
            self.why["json:%s" % os.path.basename(p)] = repr(e)
            return None

    # —— 便捷取数 ——
    def of_type(self, *types):
        want = set(types)
        return [r for r in self.records if r.get("type") in want]

    def type_counts(self):
        out = {}
        missing = 0
        for r in self.records:
            t = r.get("type")
            if t is None:
                missing += 1
                continue
            out[t] = out.get(t, 0) + 1
        if missing:
            out["<missing_type>"] = missing
        return out

    def cached(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]


# ─────────────────────────── 算子 ───────────────────────────
def _op_exists(val, spec):
    """spec.match: "true"/"false" 或 "nonzero"/"missing_or_empty" 等自由串。"""
    if val is None:
        return UNDECIDABLE, "字段读不到"
    want = spec.get("match")
    truth = bool(val)
    if want in ("true", "nonzero", "nonempty"):
        return (HIT if truth else CLEAN), "%s=%r" % (spec.get("field"), val)
    if want in ("false", "zero", "empty"):
        return (HIT if not truth else CLEAN), "%s=%r" % (spec.get("field"), val)
    # 其余形态由 probe 自己给结论（probe 返回 (state, snippet)）
    return UNDECIDABLE, "未定义的 exists.match=%r" % (want,)


def _op_count(val, spec):
    if val is None:
        return UNDECIDABLE, "计数读不到"
    thr = spec.get("threshold", 0)
    if not isinstance(thr, (int, float)):
        # 阈值写成 "window_budget" 这类占位串 ⇒ 明确报「阈值未定」，
        # 不许拿 0 顶上（那会把「还没定」读成「一条都不许有」）
        return UNDECIDABLE, "阈值未定（threshold=%r）" % (thr,)
    direction = spec.get("direction", "higher_worse")
    tail = ""
    if isinstance(val, _NeverFired):
        tail = "｜★ 该 type 有写入点但全部历史从未触发 ⇒ 这个 0 不是「已验证没问题」"
    if direction == "lower_worse":
        return (HIT if val < thr else CLEAN), "count=%d thr=%s (低于即命中)%s" % (
            val, thr, tail)
    return (HIT if val > thr else CLEAN), "count=%d thr=%s%s" % (val, thr, tail)


def _op_ratio(val, spec):
    """val = (num, den)。分母 0 ⇒ undecidable（空集不许当通过）。

    ★ direction 必须显式：同一个 ratio 算子在两类槽位上方向相反——
      「未配对率」越高越坏，「可复核率」越低越坏。
      不写 direction 就默认 higher_worse，会把 0.9978 判成 clean（实测踩过）。
    """
    if val is None:
        return UNDECIDABLE, "比值读不到"
    if not (isinstance(val, (tuple, list)) and len(val) == 2):
        # 算子契约被破坏 ⇒ 明确报「判不了」，不许硬算出一个假比值
        return UNDECIDABLE, "ratio 入参不是 (num, den)：%r" % (val,)
    num, den = val
    if not den:
        return UNDECIDABLE, "分母为 0（空集比较不成立）"
    r = float(num) / float(den)
    thr = spec.get("threshold")
    if not isinstance(thr, (int, float)):
        return UNDECIDABLE, "阈值不是数字"
    direction = spec.get("direction", "higher_worse")
    # 分子分母可能是浮点（如「命中密度偏移比」），一律用 %g ——用 %d 会把
    # 0.383/0.802 印成 "0/0"，读数的人会以为分母是空的（实测踩过一次）。
    pair = "%g/%g" % (num, den)
    if direction == "lower_worse":
        return (HIT if r < thr else CLEAN), "%s=%.4f thr=%s (低于即命中)" % (
            pair, r, thr)
    return (HIT if r > thr else CLEAN), "%s=%.4f thr=%s" % (pair, r, thr)


def _op_set_diff(val, spec):
    """val = 差集 list。空 ⇒ clean；非空 ⇒ hit。两边都要存在（None ≠ 空集）。"""
    if val is None:
        return UNDECIDABLE, "有一侧读不到"
    return (HIT if val else CLEAN), "diff=%d %s" % (len(val), str(val[:3]))


def _op_sequence(val, spec):
    """val = (最长重复次数, 东西)。重复数为 0 ⇒ undecidable（没样本，不是"没发生"）。"""
    if val is None:
        return UNDECIDABLE, "序列读不到"
    n, what = val
    rep = spec.get("repeat")
    if not isinstance(rep, int):
        return UNDECIDABLE, "repeat 不是整数"
    if n == 0:
        return UNDECIDABLE, "无可比较样本（空序列不判）"
    return (HIT if n >= rep else CLEAN), "max_repeat=%d/%d on %r" % (n, rep, what)


def _op_monotonic(val, spec):
    if val is None:
        return UNDECIDABLE, "序列读不到"
    n = val
    thr = spec.get("threshold")
    if not isinstance(thr, (int, float)):
        return UNDECIDABLE, "阈值不是数字/不可量化"
    return (HIT if n > thr else CLEAN), "changes=%s thr=%s" % (n, thr)


_APPLY = {
    "exists": _op_exists,
    "count": _op_count,
    "ratio": _op_ratio,
    "set_diff": _op_set_diff,
    "sequence": _op_sequence,
    "monotonic": _op_monotonic,
}


# ─────────────────────────── probe ───────────────────────────
def _p_ledger_types(ctx):
    """type 计数 ＋ 判据命中基线（X2b-04 用）+ 生产者存在性证明。"""
    # ★ 空窗口必须返回 None。否则 `count(type)=0` 会被算子读成「没发生」，
    #   而真相是「这一段时间我们什么都没看见」（铁律 1）。实测过：审计目录为空时
    #   X3-01 一路报清白，看上去像「拦截全被尊重」，其实一条记录都没有。
    if not ctx.records:
        ctx.why["ledger_types"] = "窗口内没有任何账本记录"
        return None
    pre = ctx.of_type("pre_tool_use")
    win_pre = len(pre)
    win_hit = sum(len(r.get("rules_hit") or []) for r in pre)
    # 判据基线偏移：命中密度相对历史基线的偏移（相对量的绝对值，不是百分点）
    num = den = None
    if win_pre and getattr(ctx, "history_pre_total", 0):
        rate_w = float(win_hit) / win_pre
        rate_h = float(ctx.history_hit_total) / ctx.history_pre_total
        num, den = abs(rate_w - rate_h), rate_h
    return {"type_counts": ctx.type_counts(),
            "history_types": dict(ctx.history_type_counts),
            "declared_types": ctx.declared_types,
            "baseline_shift_num": num,
            "baseline_shift_den": den,
            "hit_density": (win_hit, win_pre),
            "_n": len(ctx.records),
            "_days": len(ctx.days),
            "_history_days": len(ctx.history_days)}


def _p_ledger_actions(ctx):
    """pre/post 按 content_digest 配对。返回配对缺口计数与配对率。"""
    pre = [r for r in ctx.of_type("pre_tool_use")]
    post = [r for r in ctx.of_type("post_tool_use")]
    pre_d = set(r.get("content_digest") for r in pre if r.get("content_digest"))
    post_d = set(r.get("content_digest") for r in post if r.get("content_digest"))
    if not pre_d and not post_d:
        return None                              # 两侧都空 ⇒ undecidable
    gap = pre_d - post_d                          # 有 pre 无 post（可能还在跑）
    gap2 = post_d - pre_d                         # 有 post 无 pre（决策没留痕）
    return {
        "pre": len(pre), "post": len(post),
        "pre_digests": len(pre_d), "post_digests": len(post_d),
        "unpaired": len(gap),
        # ★ set_diff 要的是「东西的清单」而不是个数 —— 数 3 和列出哪 3 个
        #   在报告里是两句话。样例取前 5 个 digest 以便回查（不带全量，防爆内存）。
        "unpaired_sample": sorted(gap)[:5],
        # ★ 两个方向必须是**两个字段**：I1-01「无留痕」问的是「动作做完了，
        #   决策却没记」＝ post 侧多出来的；I1-02「留痕不完整」问的是配对缺口。
        #   把两者都映射到 `unpaired` 会让两条判据对同一事实给出相反结论——
        #   实测过一次：I1-01 判命中 354，I1-02 判清白 2.6%。
        "unpaired_post_sample": sorted(gap2)[:5],
        "unpaired_post": len(gap2),
        "ledger_records": len(ctx.records),
        "pair_ratio": (len(pre_d & post_d), len(pre_d)),
    }


# 「按设计无链直写」的记录类型 —— **白名单，不是「凡是缺 hash 就豁免」**。
# ★ 唯一依据：`docs/AUDIT_SCHEMA.md` §2「例外（历史遗留）」明文只有 `session_start`。
#   新增一种必须同时改 schema，否则就是拿「按设计的例外」洗分母（第十五族）。
_NO_CHAIN_BY_DESIGN = ("session_start",)


def _p_ledger_ts(ctx):
    """时间戳与链字段质量。九维 8 的正例：格式不同不是缺失。"""
    if not ctx.records:
        return None
    lens = {}
    missing = 0
    with_hash = 0
    exempt = 0          # 按设计无链的类型条数
    should = 0          # 分母：本该带 hash 的记录数
    hashed_in_scope = 0  # 分子：其中真带了 hash 的
    prev = None
    max_gap_min = 0.0
    inversions = 0
    for r in ctx.records:
        _h = bool(r.get("hash"))
        if _h:
            with_hash += 1
        if r.get("type") in _NO_CHAIN_BY_DESIGN:
            # ★ 不计入分子也不计入分母：schema 说它不参与链校验。
            #   只「从分母里扣」会留下分子 100% 的假象；分子分母同范围才诚实。
            exempt += 1
        else:
            should += 1
            if _h:
                hashed_in_scope += 1
        ts = r.get("ts")
        if ts is None:
            missing += 1
            continue
        lens[len(ts)] = lens.get(len(ts), 0) + 1
        if len(ts) != 25:
            # 另一种格式（实测 19 字符 776 条）不与 25 字符混比，避免假逆序
            continue
        if prev is not None:
            if ts < prev:
                inversions += 1
            else:
                try:
                    from datetime import datetime
                    a = datetime.strptime(prev[:19], "%Y-%m-%dT%H:%M:%S")
                    b = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
                    gap = (b - a).total_seconds() / 60.0
                    if gap > max_gap_min:
                        max_gap_min = gap
                except ValueError:
                    pass
        prev = ts
    out = {"ts_lengths": lens, "missing_ts": missing,
           "inversions_25": inversions, "n": len(ctx.records),
           "total": len(ctx.records),
           "records_with_hash": with_hash,
           "records_without_hash": len(ctx.records) - with_hash,
           # 口径 A（旧）：全部记录里带 hash 的比例 —— 分母混进按设计的例外，必假红
           # 口径 B（现行）：只问「本该带 hash 的都带了吗」
           "records_exempt_no_hash": exempt,
           "records_should_have_hash": should,
           "records_hashed_in_scope": hashed_in_scope,
           "max_gap_minutes": round(max_gap_min, 1)}
    out.update(_hook_latency(ctx))
    return out


def _hook_latency(ctx):
    """钩子端到端耗时（毫秒）—— 这才是**告警延迟**，不是 pre→post 的差。

    ★ 为什么不能用 pre/post 时间差：post_tool_use 是在工具**执行完**才写的，
      两者的差是「命令跑了多久」。实测最大 4102 秒（≈68 分钟的 gate 全量），
      拿它当告警延迟＝把工具执行时长说成告警慢（异质单位做加减，F54）。
      产品自己记了 `hook_slow.elapsed_ms`，用它。

    ★ 为什么 n=0 也要返回字段（2026-11-02）：原先无记录时 `return {}`，
      字段缺失 ⇒ `_op_count` 判 undecidable ⇒ MS1-01 只有 hit/undecidable
      两态、**永远不可能 clean**。而「本窗口一条慢钩子都没有」是真实可得的
      事实（链读到了、就是没有），必须能说出口。链本身读不到的情形由
      `_p_ledger_ts` 顶端的 `if not ctx.records: return None` 负责，两者不混。

    ★ p95 只在有记录时给：n=0 时给 0 会让人误读成「延迟 0ms」。字段不存在
      比一个假 0 诚实（0 与不可判不同貌）。
    """
    vals = [r.get("elapsed_ms") for r in ctx.of_type("hook_slow")
            if isinstance(r.get("elapsed_ms"), (int, float))]
    vals.sort()
    out = {"hook_slow_n": len(vals),
           "hook_slow_max_ms": max(vals) if vals else 0}
    if vals:
        out["hook_slow_p95_ms"] = vals[int(len(vals) * 0.95) - 1 if len(vals) > 1 else 0]
    return out


def _p_day_anchor(ctx):
    """日锚缺口：有数据的天却没有锚，或锚的 size 与文件实际大小不符。

    ★ 不在这里重算 hash 链——那是 tools/verify_chain 的事（铁律 8：不二次实现）。
    """
    if ctx.day_manifest is None:
        return None                              # 锚文件读不到 ⇒ undecidable
    missing_anchor = []
    size_mismatch = []
    for fp in ctx.days:
        name = os.path.basename(fp)
        entry = ctx.day_manifest.get(name)
        if not entry:
            missing_anchor.append(name)
            continue
        try:
            actual = os.path.getsize(fp)
        except OSError:
            continue
        if int(entry.get("size", -1)) != actual:
            size_mismatch.append((name, entry.get("size"), actual))
    return {"days": len(ctx.days), "missing_anchor": missing_anchor,
            "size_mismatch": size_mismatch,
            # 同一份取数的另一个读数：MS1-02「报告按时率」＝锚覆盖比。
            # ★ 不是第二把尺子 —— 一个 probe 两个算子，问的是「缺了哪几天」与
            #   「覆盖了几成」，两个问题不能互相替代。
            "anchored": len(ctx.days) - len(missing_anchor),
            "total": len(ctx.days)}


_HASH_NORM_CACHE = {}


def _hash_normalizer(root):
    """版本行归一化的**唯一真源在 `host_shield`**；本模块只消费，不自己实现。

    ★ 为什么必须有这一步（2026-11-02 实测）：`hooks/pre_tool_use.py` 是**版本承载件**，
      写进 `psl/manifest.json` 的是**归一化后**的哈希（`build_package._manifest_hash_of`
      与 `tools/antinel_verify.py:649` 同法）。本探针原先直接算裸 sha256 ⇒ 与记账值
      **恒不相等** ⇒ X2b-06「采集器自身被篡改」永久判红。
      实证：manifest 记 `sha256:5b079c…`（归一化值），裸算 `sha256:ce2cf5…`。
      那是最吓人的一条结论，一旦恒红，整张槽位表都会被读成噪声。

    ★ 本文件第 3 条设计约束（见模块 docstring）本来就写着「规则哈希一律 import
      产品模块或读产品产出，不在这里重算」—— 原实现在这一点上违反了它自己的约束。
      修复不是新发明，是让它遵守已声明的纪律。

    返回 `(norm_bytes|None, bearing_tuple, note)`。拿不到 ⇒ note 非空，调用方必须判
    undecidable。**不退回裸哈希**：`antinel_verify` 那种"退回裸算并记账"适用于发布
    验收（宁可假阳性也要有结论），而这里是"有没有被篡改"的告警——假阳性会让人
    直接关掉告警。
    """
    key = os.path.abspath(root)
    if key in _HASH_NORM_CACHE:
        return _HASH_NORM_CACHE[key]
    try:
        if key not in sys.path:
            sys.path.insert(0, key)
        import host_shield as _H
        got = (_H.norm_version_bytes,
               tuple(getattr(_H, "VERSION_BEARING_CHAIN_FILES", ())), "")
    except Exception as e:                                     # noqa: BLE001
        got = (None, (), "拿不到 host_shield（%r）" % (e,))
    _HASH_NORM_CACHE[key] = got
    return got


def _p_rules_hash(ctx):
    """X2b-06：采集器自身（hooks + rules）有没有被改过 —— 只查自检钉住的那几个。

    ★ 校验对象必须与「谁会被自检钉住」一致：manifest.files 里有、并且属于
      采集器主体的条目。全表比对会把交付文档也拉进来，一次正常改文档就报
      「被篡改」——判据立刻变成噪声。
    ★ 比对口径**必须与写 manifest 的那一侧同法**（版本承载件先归一化再算），
      否则恒失配 —— 见 `_hash_normalizer` 的说明。
    """
    if not ctx.manifest:
        return None
    files = ctx.manifest.get("files")
    if not isinstance(files, dict) or not files:
        return None
    import hashlib
    norm, bearing, note = _hash_normalizer(ctx.root)
    if norm is None:
        ctx.why["rules_hash"] = (
            "%s ⇒ 无法按 manifest 的记账口径比对（版本承载件需归一化，"
            "裸哈希会让它恒失配）" % note)
        return None
    watched = [k for k in files
               if k.startswith("hooks/") or k == "rules/default.json"]
    if not watched:
        ctx.why["rules_hash"] = "manifest.files 里没有 hooks/ 或 rules/default.json"
        return None
    diff, checked = [], 0
    for rel in sorted(watched):
        p = os.path.join(ctx.root, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            diff.append((rel, "missing"))
            continue
        checked += 1
        with open(p, "rb") as f:
            data = f.read()
        if rel in bearing:
            data = norm(data)
        live = "sha256:" + hashlib.sha256(data).hexdigest()
        want = files.get(rel)
        if not str(want).startswith("sha256:"):
            bare = str(want).split(":", 1)[-1]
            same = live.split(":", 1)[1] == bare
        else:
            same = live == want
        if not same:
            diff.append((rel, "hash_mismatch"))
    return {"diff": diff, "checked": checked,
            "watched": len(watched),
            "manifest_version": ctx.manifest.get("version")}


def _p_rules_categories(ctx):
    """规则表按产品自己的 category 分组 —— 判据不许自己写一份「什么算危险」。

    ★ 铁律 8：危险/凭证/提权的定义只能来自 `rules/default.json` 的 `category`
      与 `name`，在这里手抄一份 ID 名单就是第二套口径，改了规则它不跟。
    """
    p = os.path.join(ctx.root, "rules", "default.json")
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        ctx.why["rules_table"] = repr(e)
        return None
    rows = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return None
    by_cat = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        by_cat.setdefault(r.get("category") or "?", []).append(r)
    return by_cat


def _rule_ids(rows, name_has=None):
    out = set()
    for r in rows or []:
        if name_has and name_has not in (r.get("name") or "").lower():
            continue
        if r.get("id"):
            out.add(r["id"])
    return out


def _hit_ids(rec):
    """从一条记录的 rules_hit 里取规则号（两种形态都认：dict 与裸串）。"""
    out = set()
    for h in rec.get("rules_hit") or []:
        if isinstance(h, dict):
            if h.get("rule_id"):
                out.add(h["rule_id"])
        elif isinstance(h, str):
            out.add(h)
    return out


def _inner(rec, key, default=""):
    v = (rec.get("input") or {}).get(key)
    return v if isinstance(v, str) else default


def _rel_to(ctx, p):
    """路径相对仓根；在仓外 ⇒ None。

    ★ 三种写法都要认（实测都出现过）：
        ① `D:/psl/...`（记录里常见的正斜杠）
        ② `D:\\psl\\...`
        ③ `/d/psl/...`（MSYS/Git-Bash 风格，来自我们这个环境的命令行）
      只认前两种时，第 ③ 种会在 Windows 上被解析成 `<cwd>\\d\\psl\\...`，
      于是**仓内的读被报成越界**——那是纯假红，一次就够毁掉整条判据的可信度。
    """
    if not p:
        return None
    q = p
    if re.match(r"^/[a-zA-Z]/", q):                      # ③ MSYS → 盘符
        q = q[1].upper() + ":" + q[2:]
    try:
        a = os.path.abspath(q)
        root = os.path.abspath(ctx.root)
        rel = os.path.relpath(a, root)
    except (ValueError, OSError):
        return None
    if rel.startswith(".."):
        return None
    return rel.replace("\\", "/")


# ══════════════ 2026-11-01：B1–B7 新接线（九源，一源多槽） ══════════════
def _p_exit_code(ctx):
    """Q1-01：构建/类型检查命令的退出码。

    ★ 只认「构建/检查」类命令。把任何非零退出都算进来，`ls` 找不到目录也会
      变成「构建失败」—— 判据立刻退化成噪声源（假绿十四族 ③ 输入边界≠规则边界）。
    ★ 一条构建命令都没跑过 ⇒ 返回 None（undecidable），
      不许把「没跑过」报成「构建全绿」（铁律 1）。
    """
    hints = ("pytest", "py_compile", "compileall", "unittest", "run_harness",
             "npm run build", "npm test", "npm run test", "tsc ", "ruff",
             "flake8", "mypy", "black --check", "cargo build", "go build",
             "delivery_gate", "verification_tests", "regression_gate")
    runs = 0
    bad = []
    for r in ctx.of_type("post_tool_use"):
        cmd = (_inner(r, "command") or "").lower()
        if not cmd or not any(h in cmd for h in hints):
            continue
        runs += 1
        ec = r.get("exit_code")
        if isinstance(ec, int) and ec != 0:
            bad.append({"ts": r.get("ts"), "rc": ec, "cmd": cmd[:90]})
    if runs == 0:
        ctx.why["exit_code"] = "窗口内没有构建/检查类命令"
        return None
    return {"build_failed": bool(bad), "build_runs": runs,
            "build_failures": len(bad), "worst": bad[:3]}


def _p_artifact_path(ctx):
    """Q1-05：声称写完的产物，现在还在不在。

    ★ 只看 Write/Edit 的 file_path（那是唯一「声称产物」的字段），
      不看命令行里的字符串 —— 那是猜。
    ★ 消失不必然等于错（正常清理也会消失），所以 snippet 必须带上条数与样例，
      让读者自己判断；判据说的是「有声称产物现在不在」这件事实。
    """
    claimed = {}
    for r in ctx.of_type("post_tool_use"):
        if r.get("tool") not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            continue
        p = _inner(r, "file_path")
        if p:
            claimed[p] = r.get("ts")
    if not claimed:
        ctx.why["artifact_path"] = "窗口内没有 Write/Edit 的 file_path"
        return None
    missing = [p for p in claimed if not os.path.exists(p)]
    return {"missing_artifact": bool(missing), "claimed": len(claimed),
            "n_missing": len(missing),
            "missing": sorted(missing)[:5]}


def _p_write_set(ctx):
    """Q1-06 / K1-01 / MK1-01 共用：写入集合、读取集合、越界集合。

    ★ 一个源出三个字段，**不许**为三个槽位各写一份扫描（R4：两套尺子守同一件事，
      其中一套必然漂）。三槽位只是从同一份结果里取不同的切片。
    """
    written, read = {}, {}
    for r in ctx.of_type("pre_tool_use"):
        tool = r.get("tool") or ""
        p = _inner(r, "file_path")
        if not p:
            continue
        if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            written[p] = tool
        elif tool in ("Read", "Grep", "Glob"):
            read[p] = tool
    if not written and not read:
        ctx.why["write_set"] = "窗口内没有带 file_path 的读写动作"
        return None

    # 验收标准承载件：改这些等于改「什么算通过」
    guard_prefix = ("ci/", "tests/", "test/")
    guard_exact = {"scripts/verification_tests.py", "scripts/run_harness.py",
                   "scripts/build_package.py", "rules/default.json",
                   "pyproject.toml", "ci/version_check.py"}
    protected, out_scope = [], []
    for p in written:
        rel = _rel_to(ctx, p)
        if rel is None:
            out_scope.append(p)
            continue
        if rel in guard_exact or any(rel.startswith(g) for g in guard_prefix):
            protected.append(rel)
    read_out = [p for p in read if _rel_to(ctx, p) is None]

    def is_tmp(p):
        q = p.replace("\\", "/").lower()
        return ("/temp/" in q or q.startswith("/tmp/") or "/tmp/" in q
                or "/appdata/local/temp" in q)

    # 「越界」这个词太笼统：101 条里可能 74 条在同一个兄弟项目目录，
    # 也可能散落 100 个地方 —— 前者是「跨目录协作」，后者是「乱写」。
    # 所以按**上两级目录**归堆，让读数的人一眼看出是哪种。
    bucket = {}
    for p in out_scope:
        q = p.replace("\\", "/")
        parts = [x for x in q.split("/") if x]
        key = "/".join(parts[:2]) if len(parts) >= 2 else q
        bucket[key] = bucket.get(key, 0) + 1
    top = sorted(bucket.items(), key=lambda kv: -kv[1])[:5]
    return {"protected_hit": sorted(protected),
            "out_of_scope": sorted(out_scope),
            "files_read_by_us": sorted(read_out),
            "out_of_scope_tmp": sum(1 for p in out_scope if is_tmp(p)),
            "out_of_scope_real": sum(1 for p in out_scope if not is_tmp(p)),
            "out_of_scope_top": top,
            "read_outside_tmp": sum(1 for p in read_out if is_tmp(p)),
            "read_outside_real": sum(1 for p in read_out if not is_tmp(p)),
            "n_written": len(written), "n_read": len(read)}


def _p_cmd_text(ctx):
    """A1-01 / A1-05 / K1-02 共用：动作文本上的规则命中，按 category 切片。

    ★ 三类「危险」的定义全部来自规则表：destructive / secrets 里的字面量类 /
      AN-013 提权。手抄名单就是第二套口径（铁律 8）。
    """
    cats = _p_rules_categories(ctx)
    if cats is None:
        return None
    dangerous = _rule_ids(cats.get("destructive"))
    priv = _rule_ids(cats.get("destructive"), name_has="escalation")
    secret = _rule_ids(cats.get("secrets"), name_has="secret")
    if not dangerous or not priv or not secret:
        ctx.why["cmd_text"] = "规则表里找不到 destructive/escalation/secret 类"
        return None

    n = 0
    d_hit, s_hit, p_hit = [], [], []
    for r in ctx.of_type("pre_tool_use"):
        ids = _hit_ids(r)
        if not ids:
            n += 1
            continue
        n += 1
        if ids & dangerous:
            d_hit.append({"ts": r.get("ts"), "rules": sorted(ids & dangerous)})
        if ids & secret:
            s_hit.append({"ts": r.get("ts"), "rules": sorted(ids & secret)})
        if ids & priv:
            p_hit.append({"ts": r.get("ts"), "rules": sorted(ids & priv)})
    if n == 0:
        return None
    return {"dangerous_hit": bool(d_hit), "secret_hit": bool(s_hit),
            "privilege_hit": bool(p_hit),
            "n_pre": n, "n_dangerous": len(d_hit), "n_secret": len(s_hit),
            "n_privilege": len(p_hit),
            "samples": (d_hit + s_hit + p_hit)[:3]}


def _p_ledger_seq(ctx):
    """S1-02 / S1-04 / S1-05 共用：会话内动作序列。

    ★ content_digest 为空时不做「连续相同」判断 —— 空串相等是假重复。
    ★ 一个会话都没有 ⇒ 返回 None，不许报「没有死循环」（空序列不是清白）。
    """
    by_sess = {}
    dropped = 0
    for r in ctx.of_type("pre_tool_use"):
        s = r.get("session")
        if not s:
            # ★ 无 session 的记录**不能**被并成一个桶：实测 38 条无 session、
            #   17 个不同 digest，按桶排在一起会凭空造出「连续 21 次同动作」。
            #   那是最坏的一种假红 —— 数字很大、看起来最像真问题。
            dropped += 1
            continue
        by_sess.setdefault(s, []).append(r)
    if not by_sess:
        ctx.why["ledger_seq"] = "窗口内没有带 session 的动作记录"
        return None

    exit_of = {}
    for r in ctx.of_type("post_tool_use"):
        d = r.get("content_digest")
        if d:
            exit_of[d] = r.get("exit_code")

    max_run, run_who = 0, None
    max_fail_run, fail_who = 0, None
    max_steps, steps_who = 0, None
    for s, rs in by_sess.items():
        if len(rs) > max_steps:
            max_steps, steps_who = len(rs), s
        run = 1
        frun = 1
        for i in range(1, len(rs)):
            a, b = rs[i - 1], rs[i]
            da, db = a.get("content_digest"), b.get("content_digest")
            same = bool(da) and da == db and a.get("tool") == b.get("tool")
            if same:
                run += 1
            else:
                run = 1
            if run > max_run:
                max_run, run_who = run, (s[:8], b.get("tool"))
            fa = exit_of.get(da)
            fb = exit_of.get(db)
            if same and isinstance(fa, int) and fa != 0 and isinstance(fb, int) and fb != 0:
                frun += 1
            else:
                frun = 1
            if frun > max_fail_run:
                max_fail_run, fail_who = frun, (s[:8], b.get("tool"))
    return {"tool+args_digest": (max_run, run_who),
            "failed_action": (max_fail_run, fail_who),
            "session_actions": max_steps,
            "max_session": (steps_who or "")[:8],
            "sessions": len(by_sess),
            "dropped_no_session": dropped}


def _read_json_path(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _p_config_hooks(ctx):
    """A1-10 / P1-01 / P1-02 / P1-03 / X3-03 / XM3-02 / MK1-02 共用：配置面。

    ★ hooks 有没有被摘掉，看**宿主真正读取的那个文件**（host_shield.json 里
      记着 settings_file），不看我们自己的副本 —— 副本永远是对的。
    """
    hs = ctx.host_shield or {}
    reg = hs.get("hook_registration") or {}
    settings = reg.get("settings_file")
    cands = [settings] if settings else []
    cands += [os.path.join(ctx.root, ".qoder", "settings.json"),
              os.path.join(ctx.root, ".claude", "settings.json")]
    cfg, cfg_path = None, None
    for p in cands:
        if p and os.path.isfile(p):
            cfg, cfg_path = _read_json_path(p), p
            if cfg is not None:
                break
    if cfg is None:
        ctx.why["config_hooks"] = "找不到宿主的 hook 配置文件"
        return None

    hooks = cfg.get("hooks") or {}
    text = json.dumps(hooks, ensure_ascii=False)

    def has(script):
        return script in text

    pre_ok, post_ok = has("pre_tool_use.py"), has("post_tool_use.py")

    # 谁把 hook 关掉的：产品自己记录 invoked_by（A1-10 与 XM3-02 共用这份归因）
    by_agent = by_user = 0
    for t in ("host_shield_changed", "policy_changed"):
        for r in ctx.of_type(t):
            who = (r.get("invoked_by") or "").lower()
            if (r.get("field") or "").startswith(("hook", "hooks")):
                if who in ("agent", "unknown", ""):
                    by_agent += 1
                elif who in ("user", "cli"):
                    by_user += 1

    # 禁用应验：规则写明 enabled:false，却仍在窗口里命中
    # ★★ 必须扣掉产品自己在 `hardcoded_rules.declared_but_code_driven` 里声明的条目：
    #    那几条写 `enabled:false` 是**设计**（判定走代码内置，写 false 只为不让通用
    #    正则接管）。不扣就会把「按设计如此」报成「关不掉」——实测踩过：AN-037
    #    连续命中，看上去像重大缺陷，其实是产品说明书自己写着的行为（按 ID 猜语义）。
    disabled_but_loaded = []
    p = os.path.join(ctx.root, "rules", "default.json")
    table = _read_json_path(p)
    rows = (table or {}).get("rules") if isinstance(table, dict) else None
    code_driven = set(((table or {}).get("hardcoded_rules") or {})
                      .get("declared_but_code_driven") or {})
    off = {r.get("id") for r in (rows or [])
           if isinstance(r, dict) and r.get("enabled") is False}
    off_generic = off - code_driven
    if off_generic:
        for r in ctx.of_type("pre_tool_use", "dst02_bash_path_suspect"):
            bad = _hit_ids(r) & off_generic
            if bad:
                disabled_but_loaded.append(sorted(bad))
    # MCP：本机服务表（空表是一个**真事实**，不是缺数据）
    mcp = _read_json_path(os.path.join(os.path.expanduser("~"), ".claude.json")) or {}
    servers = mcp.get("mcpServers") or {}
    unauthorized = sorted(servers) if servers else []

    # 配置变更次数（P1-03 配置漂移）
    changes = sum(len(ctx.of_type(t)) for t in
                  ("policy_changed", "host_shield_changed", "rules_snapshot_refreshed"))
    return {"hooks_off_by_agent": by_agent > 0,
            "hooks_off_by_user": by_user > 0,
            "hooks_off": not (pre_ok and post_ok),
            "pre_ok": pre_ok, "post_ok": post_ok,
            "config_file": cfg_path,
            "disabled_but_loaded": bool(disabled_but_loaded),
            "disabled_sample": disabled_but_loaded[:3],
            "n_rules_disabled": len(off),
            # 扣掉「判定走代码」之后**真正**该被关掉的条数 —— 报告里要能说清
            # 「1 条写 false」与「0 条该被关掉」是两件事。
            "n_rules_enabled_off_generic": len(off_generic),
            "code_driven_rules": sorted(code_driven),
            "unauthorized_mcp": unauthorized,
            "n_mcp": len(servers),
            "tool_def_drift": [],      # 无 MCP ⇒ 无工具定义可比（见 undecidable 说明）
            "config_changes": changes,
            "consent_missing": not bool(reg),
            "hook_sha": reg.get("sha256")}


# 「显式终止」的**独立事件**类型。★ 当前产品**不写**这一类记录：
#   今天的处置以 deny 为主、几乎不 kill（X3-02 的 why_partial 早已写明这一点）。
#   所以这里多半是空集 —— 空集时 X3-02 必须判「不可判定」，不许拿复活记录顶替。
_STOP_EVENT_TYPES = ("host_shield_stopped", "host_shield_killed")


def _p_self_pid(ctx):
    """X2a-01 / X3-02 / MA1-01 共用：监理自身是否还在跑。

    ★ 判活**不看 pid 单值**（MEMORY：62 秒内 pid 可复用）⇒ 用心跳时刻距离。
      心跳取自产品自己的记录，不另起一套探测。
    """
    hs = ctx.host_shield or {}
    hb = ctx.of_type("host_shield_heartbeat")
    stamps = sorted(r.get("ts") for r in hb if r.get("ts"))
    newest = max([r.get("ts") for r in ctx.records if r.get("ts")] or [""])
    if not stamps or not newest:
        ctx.why["self_pid"] = "窗口内没有心跳记录"
        return None
    from datetime import datetime
    try:
        last = datetime.strptime(stamps[-1][:19], "%Y-%m-%dT%H:%M:%S")
        now = datetime.strptime(newest[:19], "%Y-%m-%dT%H:%M:%S")
        gap_min = (now - last).total_seconds() / 60.0
    except ValueError:
        return None
    alive = gap_min <= 20.0          # 心跳周期实测 10 分钟，两倍容差
    enabled = hs.get("enabled")
    revived = ctx.of_type("host_shield_revived")
    out = {"pid_alive": alive,
           "expected_alive_but_dead": bool(enabled) and not alive,
           "n_revived": len(revived),
           "gap_min": round(gap_min, 1),
           "last_heartbeat": stamps[-1],
           "sentinel_pid": hs.get("sentinel_pid"),
           "started_at": hs.get("sentinel_started_at")}

    # ── 假重启计数（2026-11-02：X3-02 现在的问法）──
    # 「假重启」＝ 我们一个手指都没动，链上却写了「已重新拉起」。
    #   产品自己把拉起方式记在 `spawn_mode` 里（实测全链 635 条 revived、
    #   **无一条缺这个字段**），而 `already-running` 的定义是「进程活着且
    #   心跳新鲜」（spawn_sentinel 的幂等分支）—— 也就是什么都没发生。
    #   所以这类记录的存在本身就自相矛盾，不必解析 reason 文本，也不必找
    #   old_pid（记录里根本没有这个字段，pid 只有新的那一个）。
    #
    # ★ 为什么必须另立一个数，不能拿下面那条顶替：
    #   下面问的是「我们让它停，它有没有再活」（终止应验）——产品今天不写
    #   显式终止事件，所以它多数窗口只能判不可判定；
    #   这里问的是「它明明活着，我们有没有谎称重启过」——**不需要前置终止
    #   事件**就成立，而且实测有 34 条真的发生过。
    #   旧实现用前者顶替后者 ⇒ 真问题（假重启）根本没有尺子。
    #
    # ★ n=0 是诚实结论：窗口内没有 revived 记录，就不可能有假重启。
    #   链本身读不到的情形由函数顶部 `if not stamps or not newest: return None`
    #   挡掉，两件事不混（0 与不可判不同貌）。
    out["revived_already_running_n"] = sum(
        1 for r in revived if r.get("spawn_mode") == "already-running")
    # 伴随读数：把窗口里出现过的拉起方式列出来，让「0」能自证看过全部记录，
    # 而不是只挑了 already-running 那几个（读数要能自证读得到）。
    out["revived_modes"] = sorted({str(r.get("spawn_mode") or "?")
                                   for r in revived})

    # 「终止应验」= 我们说停了它，它又活了。**两个条件缺一不可**：
    #   ① 窗口内有「让它停」的独立事件；② 该事件之后还有复活记录。
    # ★ 旧实现只看 ①（有 revived 就算），把 `host_shield_revived` 读成「停了没停」——
    #   而产品写这条记录的场景恰恰是**自愈**（cause 全为 hook-paramedic），
    #   语义整个反了（第十六族：把自愈读成失控）。
    # ★ ① 不存在时**不许判 clean**：那是「恒 clean 假绿」；给不出字段 ⇒ undecidable，
    #   并把原因写成一句话，让读的人知道「不是没事，是没法量」。
    stops = [r for r in ctx.records if r.get("type") in _STOP_EVENT_TYPES]
    out["n_stop_events"] = len(stops)
    if not stops:
        ctx.why["self_pid"] = (
            "窗口内没有显式终止记录（产品当前只 deny 不 kill）⇒「停了没停」无从判起；"
            "不退回「有 revived 就算」——那是把自愈读成失控")
    else:
        last_stop = max((r.get("ts") or "") for r in stops)
        after = [r for r in revived if (r.get("ts") or "") > last_stop]
        if not last_stop:
            ctx.why["self_pid"] = "终止记录没有时间戳，先后顺序不成立"
        else:
            out["revived_after_stop"] = bool(after)
            out["n_revived_after_stop"] = len(after)
    return out


_PRODUCT_VERSION_CACHE = {}


def _product_version(root):
    """当前产品版本 —— 唯一真源是 `hooks/pre_tool_use.py` 的 `_ANTINEL_VERSION`。

    ★ 不用 `psl/manifest.json` 的 `version`：那一个是**发布记录**，按 D-23
      （鸡生蛋）它会在「代码已升版、manifest 尚未重签」的窗口里落后一版。
      拿它去比探针版本，会把刚跑出来的新鲜探针误判成过期。
    """
    key = os.path.abspath(root)
    if key in _PRODUCT_VERSION_CACHE:
        return _PRODUCT_VERSION_CACHE[key]
    ver = None
    try:
        import ast as _ast
        with open(os.path.join(key, "hooks", "pre_tool_use.py"),
                  "r", encoding="utf-8") as f:
            tree = _ast.parse(f.read())
        for node in tree.body:
            if (isinstance(node, _ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], _ast.Name)
                    and node.targets[0].id == "_ANTINEL_VERSION"
                    and isinstance(node.value, _ast.Constant)
                    and isinstance(node.value.value, str)):
                ver = node.value.value
                break
    except Exception:                                          # noqa: BLE001
        ver = None
    _PRODUCT_VERSION_CACHE[key] = ver
    return ver


def _p_self_probe(ctx):
    """XM3-01 / MP1-01 / XM2a-01 共用：产品自带的执法探针结果。

    ★★ 这里有一条必须写死的纪律（品质五条 ①「量具坏了被当产品坏了」）：
      `enforcement_probe` 实测 22 条、ok 全 False、got 恒为 `allow(rc=0)`，
      而 reason 自己写着 `contract=False legacy=False` —— 那是**探针没接上通道**，
      不是产品不拦。两种解释我们分不开 ⇒ 返回 None（undecidable），
      并把「探针自身可疑」记进 why，让报告说「量具坏了」，而不是说「产品坏了」。

    ★★ 2026-11-02 补两条前置腿（实测踩到，不是假想）：

      ① **证据版本**。实测 12 条探针全部 `antinel_version=0.30.0`，而当前产品是
         0.63.2 —— 用去年的体检报告回答「今年有没有病」，而且它会给出一条
         **clean**（因为最后一条恰好 ok=True）。过期证据不是证据。

      ② **不稳定**。实测 11-01 `09:59:19 ok=False` 与 `09:59:20 ok=True`
         相隔 1 秒，同版本、同探针、结论相反。原实现只取 `pr[-1]` ——
         那是赌顺序，不是判读。

      这两条不是新规矩：同一个文件的 `_p_self_selftest` 早就写着「跨快照比对
      才能回答 flaky，只有一份 ⇒ 都返回 None」。这里是同一纪律漏了一处。
    """
    pr = ctx.of_type("enforcement_probe")
    if not pr:
        ctx.why["self_probe"] = "没有任何 enforcement_probe 记录"
        return None

    # ── ① 证据必须来自当前产品版本 ──
    cur = _product_version(ctx.root)
    vers = sorted({str(r.get("antinel_version") or "?") for r in pr})
    if cur:
        fresh = [r for r in pr if str(r.get("antinel_version") or "") == cur]
        if not fresh:
            # ★ 两个原因一起写，不许只写版本：MP1-01 / XM2a-01 要的字段
            #   **即使重跑探针也不会出现**（探针只测 deny 三通道）。只写"证据过期"
            #   会让读的人以为重跑一次就好了 —— 那是把根因说轻。
            ctx.why["self_probe"] = (
                "%d 条执法探针全部来自旧版本（记录版本 %s，当前 %s）⇒ 先重跑探针；"
                "另：这些探针只跑 pre_tool_use 的 deny 三通道，**不含**依赖可用性"
                "（MP1-01）与观测权（XM2a-01）探测，即使重跑也不会出现那两个字段"
                % (len(pr), "/".join(vers), cur))
            return None
    else:
        fresh = pr

    # ── ② 同版本同探针结论不一致 ⇒ 不许只取最后一条 ──
    oks = {bool(r.get("ok")) for r in fresh}
    if len(oks) > 1:
        ctx.why["self_probe"] = (
            "%d 条探针里 ok 既有 True 又有 False ⇒ 结论不稳定，"
            "取最后一条等于赌顺序，不足以支撑「通道可用」" % len(fresh))
        return None

    gots = {str(r.get("got")) for r in fresh}
    if (len(fresh) >= 3 and oks == {False} and len(gots) == 1
            and "rc=0" in list(gots)[0]):
        ctx.why["self_probe"] = (
            "%d 条执法探针 ok 全 False 且 got 恒为同一值 ⇒ 探针未建立通道契约，"
            "结果不可用作产品结论" % len(fresh))
        return None
    last = fresh[-1]
    # ★★ 2026-11-01：这两个键原来写死成 None 占位，于是 evaluate 报
    #   「字段取不到（名字对不上）」—— **原因说错了**。
    #   真相是：执法探针只测 pre_tool_use 的 deny 通道，**从来没有**做过
    #   「依赖模型可用性」和「观测权有效性」这两类探测 ⇒ 出口里不存在这两个键，
    #   不是笔误、也不是没数据。说错原因比不给结论更坏（读数要能自证）。
    #   ⇒ 不返回这两个键，把原因写进 why；槽位仍是 undecidable，但理由对了。
    ctx.why["self_probe"] = (
        "执法探针只跑 pre_tool_use 的 deny 三通道，**不含**依赖可用性探测"
        "（MP1-01）与观测权探测（XM2a-01）⇒ 这两个字段在本出口里根本不存在，"
        "不是名字写错")
    return {"probe_ok": bool(last.get("ok")),
            "n_probes": len(fresh),
            "expected": last.get("expected"), "got": last.get("got")}


def _p_self_selftest(ctx):
    """MQ1-03 / XM2b-01 / XM2b-02 / XM2b-03 共用：自检快照。

    ★ 快照不只一份（实测 psl/ci_debug 下有 19 份 last_results.json），
      跨快照比对才能回答「同一输入是不是给了不同结论」（flaky）。
      只有一份 ⇒ flaky 与冲突**都返回 None**，不许报 clean。
    """
    base = os.path.join(ctx.root, "psl", "ci_debug")
    snaps = []
    for dirpath, _dirs, files in os.walk(base):
        if "last_results.json" in files:
            p = os.path.join(dirpath, "last_results.json")
            data = _read_json_path(p)
            if isinstance(data, list):
                snaps.append((os.path.getmtime(p), p, data))
    if not snaps:
        ctx.why["self_selftest"] = "找不到 last_results.json"
        return None
    snaps.sort(key=lambda t: t[0])
    latest = snaps[-1][2]
    failed = [x.get("name") for x in latest if isinstance(x, dict) and not x.get("pass")]

    def as_map(rows):
        out = {}
        for x in rows:
            if isinstance(x, dict) and x.get("name"):
                out[x["name"]] = bool(x.get("pass"))
        return out

    # ★ 「flaky」只能由**同条件重复运行**回答：同一份用例、同一台机器、同一个
    #   python。跨平台/跨版本两两相比，差异里混着环境噪声，得到的不是尺子不稳，
    #   是世界不一样（假红），或者两边都过（假绿）。
    #   目录名的尾巴 `run0341a/b/c/d`、`night0331/b/c` 才是同条件重复跑。
    fam = {}
    for m, p, data in snaps:
        stem = os.path.basename(os.path.dirname(p))
        key = re.sub(r"^(.*\d)[a-z]$", r"\1", stem)   # run0341a → run0341
        fam.setdefault(key, []).append((m, p, data))
    repeated = {k: v for k, v in fam.items() if len(v) >= 2}
    cutoff = max(m for m, _p, _d in snaps) - 7 * 86400
    repeated_recent = {k: v for k, v in repeated.items()
                       if sum(1 for m, _p, _d in v if m >= cutoff) >= 2}
    flaky = cases_lost = None
    basis = None
    if repeated_recent:
        k = max(repeated_recent, key=lambda kk: len(repeated_recent[kk]))
        pair = [x for x in repeated_recent[k] if x[0] >= cutoff]
        cur, prev = as_map(pair[-1][2]), as_map(pair[-2][2])
        common = set(cur) & set(prev)
        if common:
            flaky = sorted(n for n in common if cur[n] != prev[n])
            cases_lost = sorted(set(prev) - set(cur))
            basis = (os.path.basename(os.path.dirname(pair[-2][1])),
                     os.path.basename(os.path.dirname(pair[-1][1])))
    else:
        ctx.why["self_selftest"] = (
            "快照 %d 份，但最近 7 天没有**同条件重复运行**（同平台同版本跑两遍）"
            "⇒ flaky 与前置条件两项无从检验" % len(snaps))
    # 同一份快照里重名且结论相反 ⇒ 判据之间冲突
    seen, dup_conflict = {}, []
    for x in latest:
        if not isinstance(x, dict) or not x.get("name"):
            continue
        n = x["name"]
        if n in seen and seen[n] != bool(x.get("pass")):
            dup_conflict.append(n)
        seen[n] = bool(x.get("pass"))
    conflicting = dup_conflict
    return {"failed_checks": len(failed),
            "failed_sample": failed[:5],
            "n_cases": len(latest),
            "snapshots": len(snaps),
            "latest_snapshot": os.path.relpath(snaps[-1][1], ctx.root),
            "flaky_detected": (bool(flaky) if flaky is not None else None),
            "flaky_sample": (flaky or [])[:5],
            "flaky_basis": basis,
            "cases_lost": cases_lost,
            "conflicting_verdicts": (bool(conflicting) if conflicting is not None else None),
            "conflict_sample": conflicting[:5]}


def _p_self_coverage(ctx):
    """XM2a-02（标注档）：监理自己承认的盲区清单，只列举不判定。"""
    dna = ctx.of_type("session_dna")
    if not dna:
        return None
    last = dna[-1]
    cov = last.get("coverage") or {}
    return {"days": len(cov.get("days") or []),
            "records": cov.get("records"),
            "truncated": bool(cov.get("truncated")),
            "generated_at": last.get("generated_at")}


PROBES = {
    "LEDGER_TYPES": _p_ledger_types,
    "LEDGER_ACTIONS": _p_ledger_actions,
    "LEDGER_TS": _p_ledger_ts,
    "DAY_ANCHOR": _p_day_anchor,
    "RULES_HASH": _p_rules_hash,
    # —— 2026-11-01 B1–B7 ——
    "EXIT_CODE": _p_exit_code,
    "ARTIFACT_PATH": _p_artifact_path,
    "WRITE_SET": _p_write_set,
    "CMD_TEXT": _p_cmd_text,
    "LEDGER_SEQ": _p_ledger_seq,
    "CONFIG_HOOKS": _p_config_hooks,
    "SELF_PID": _p_self_pid,
    "SELF_PROBE": _p_self_probe,
    "SELF_SELFTEST": _p_self_selftest,
    "SELF_COVERAGE": _p_self_coverage,
}


def probe_names():
    return sorted(PROBES)


# ─────────────────────────── 求值 ───────────────────────────
def evaluate(slot, ctx):
    """返回一条槽位结论（四态之一）。永远是 dict，不抛异常。"""
    sid = slot.get("id")
    ext = slot.get("ext_id")
    base = {"slot": sid, "ext": ext, "form": slot.get("form"),
            "reader": slot.get("reader", "internal"),
            "observable_id": slot.get("observable_id")}

    if slot.get("status") == "unregistered":
        base.update(state=NOT_COLLECTED, match_kind="not_registered",
                    snippet="本版未登记（分母内，分子不计）")
        return base

    form = slot.get("form")
    if form == "recorded":
        base.update(state=NOT_COLLECTED, match_kind="recorded_only",
                    snippet="记账档：只记不判（原理上判不了）")
        return base
    if form == "annotated":
        base.update(state=NOT_COLLECTED, match_kind="annotated_only",
                    snippet="标注档：只给报告加一栏，不出判据结论")
        return base

    pname = slot.get("probe")
    pred = slot.get("predicate") or {}
    if not pname or pname not in PROBES:
        base.update(state=NOT_COLLECTED, match_kind="probe_missing",
                    snippet="取数通道未接线（probe=%r）" % (pname,))
        return base

    try:
        val = ctx.cached("probe:" + pname, lambda: PROBES[pname](ctx))
    except Exception as e:                                   # noqa: BLE001
        # probe 自己崩了 ⇒ undecidable，不许读成 clean
        base.update(state=UNDECIDABLE, match_kind="probe_error",
                    snippet="取数失败：%r" % (e,))
        return base

    if val is None:
        # probe 自己会说清「为什么没数」——那句话比通用文案有用得多。
        # ★ 不许用「窗口内无可用数据」盖过「量具本身坏了」这种原因（品质五条 ①）。
        why = ctx.why.get(str(pname).lower())
        base.update(state=UNDECIDABLE, match_kind="no_data",
                    snippet=("取数失败：%s" % why) if why else
                            "取数通道在，但窗口内无可用数据")
        return base

    # probe 给的可以直接是结论（形态复杂的槽位），也可以交给算子
    if isinstance(val, tuple) and val and val[0] in ALL_STATES:
        base.update(state=val[0], match_kind="probe_direct", snippet=val[1])
        return base

    op = pred.get("op")
    fn = _APPLY.get(op)
    if fn is None:
        base.update(state=UNDECIDABLE, match_kind="bad_operator",
                    snippet="未实现的算子 %r（只许六个）" % (op,))
        return base

    field = pred.get("field")
    arg = _extract(val, field, op, pred)
    if arg is NO_PRODUCER:
        base.update(state=UNDECIDABLE, match_kind="no_producer",
                    snippet="产品代码里没有任何地方写 type=%r（AST 扫 hooks/ 与 tools/）"
                            "⇒ 这是死代码，不是「没发生」" % (field,))
        return base
    if arg is None:
        why = ctx.why.get(str(pname).lower())
        # ★ 默认文案不能说死「名字对不上」——「键不存在」有两种完全不同的原因：
        #   ① probe 里键名写错（我的 bug，改代码就能修）
        #   ② 这项探测根本没实现（改名字一辈子也修不好）
        #   两者对读者意味着完全不同的下一步，所以默认只陈述事实，原因交给 why。
        base.update(state=UNDECIDABLE, match_kind="field_missing",
                    snippet="字段 %r 取不到%s" % (
                        field, ("：" + str(why)) if why else
                        "（该 probe 出口里没有这个键：可能是键名写错，"
                        "也可能是这项探测尚未实现——须查 probe 实现，不能当成「没数据」）"))
        return base
    state, snip = fn(arg, pred)
    base.update(state=state, match_kind="%s:%s" % (op, field), snippet=snip)
    # ★ 「有写入点但一次都没触发」必须能被汇总层单独数出来（铁律 1）：
    #   它在四态里是 clean，但语义是「这条防线从没被验证过」，不能混进
    #   「已验证清白」的分子里去。
    if isinstance(arg, _NeverFired):
        base["never_fired"] = True
    return base


def _extract(val, field, op, spec):
    """从 probe 结果里取算子要的入参；取不到 ⇒ None（下游变 undecidable）。

    ★ ratio 要的是 (分子, 分母) 二元组：分子=field，分母=spec["against"]。
      这两个名字都必须在 probe 结果里真实存在；缺一个就返回 None，
      不许拿 0 或 1 顶上（那是「把不知道说成知道」）。
    """
    if not isinstance(val, dict):
        return None
    if op == "ratio":
        num = val.get(field)
        den = val.get(spec.get("against"))
        if num is None or den is None:
            return None
        return (num, den)
    if op == "count":
        # ① 按记录类型记数（LEDGER_TYPES 的出口）
        tc = val.get("type_counts")
        if isinstance(tc, dict) and field not in val:
            declared = val.get("declared_types")
            if isinstance(declared, (set, frozenset, list, tuple)):
                if field not in declared:
                    # 代码里压根没有这个 type 的写入点 ⇒ 死代码（定义了但零实现）
                    return NO_PRODUCER
            hist = val.get("history_types") or {}
            if field not in hist and field in (declared or ()):
                # 有写入点，但全部历史里一次都没触发过。
                # 这不是「没发生」也不是「死代码」——是「生产者从未被调用」，
                # 交回 0 让判据出 clean，但 evaluate 会补一条 never_fired 说明。
                return _NeverFired(0, field)
            return tc.get(field, 0)
        # ② 顶层直接有该字段
        if field in val:
            return val[field]
        return None
    if op == "set_diff" and field == "days_without_anchor":
        return val.get("missing_anchor")
    if op == "set_diff" and field == "live_hash":
        return val.get("diff")
    return val.get(field)


def evaluate_all(reg, ctx):
    return [evaluate(s, ctx) for s in reg["slots"]]


# ─────────────────────────── 汇总 ───────────────────────────
def summarize(results, reg):
    """三个数分开报：已拦（能拦的）/ 已判（判得出但拦不住的）/ 未观测。

    ★ 不许把 not_collected 与 undecidable 合并：前者是「本版没做」，
      后者是「做了但数据不够」。两句话不能互换（方案书 §5.3 三条不许混的措辞）。
    """
    reg_ids = {s["id"] for s in reg["slots"] if s.get("status") != "unregistered"}
    judged = [r for r in results if r["slot"] in reg_ids]
    by_state = {}
    for r in judged:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
    by_reader = {}
    for r in judged:
        by_reader.setdefault(r["reader"], {}).setdefault(r["state"], 0)
        by_reader[r["reader"]][r["state"]] += 1
    # 命中的**性质**（2026-11-02）：命中不等于缺陷。分诊结论写在登记表的
    # `triage.class` 里（数据，不是这里的判断）——本函数只做计数。
    # ★ 三个数分开：真现象 / 尺子缺陷 / 阈值标定。合并成一个「命中」数会让
    #   读者把「我们的判据写错了」也算成「产品出事了」，这正是分诊要防的。
    _hit_ids = {r["slot"] for r in judged if r["state"] == HIT}
    by_triage = {"real": 0, "defect": 0, "calibration": 0, "unclassified": 0}
    # 命中的**触发环境**（2026-11-02）。为什么这一栏必须出现在报告里：
    #   本机本轮 9 条命中全部由开发动作触发（改自己的 ci/、在临时目录跑夹具、
    #   长程任务本身几千个动作）。用户第一次看到「11 项命中」会以为被攻击了。
    # ★ 这不是给命中找借口：env=dev 的条目在用户机器上仍然会发生（只是预期为 0），
    #   写出来是为了让读者知道「这一条该在哪儿复现」。
    by_env = {"dev": 0, "user": 0, "any": 0}
    for s in reg["slots"]:
        if s["id"] not in _hit_ids:
            continue
        _cls = (s.get("triage") or {}).get("class")
        by_triage[_cls if _cls in ("real", "defect", "calibration") else "unclassified"] += 1
        _env = (s.get("triage") or {}).get("env")
        by_env[_env if _env in ("dev", "user") else "any"] += 1
    return {
        "denominator": reg["denominator"],
        "registered": len(reg_ids),
        "covered_hit": by_state.get(HIT, 0),
        "covered_clean": by_state.get(CLEAN, 0),
        "by_triage": by_triage,
        "by_env": by_env,
        # 清白里有一部分是「有写入点但从未触发」——单列，别混进已验证
        "never_fired": [r["ext"] for r in judged if r.get("never_fired")],
        "undecidable": [r["ext"] for r in judged if r["state"] == UNDECIDABLE],
        "not_collected": [r["ext"] for r in judged if r["state"] == NOT_COLLECTED],
        "by_reader": by_reader,
        "by_state": by_state,
    }
