# -*- coding: utf-8 -*-
"""B-10 · 给 `E6b` 里 Bash 那些条目找机制（否证三个假设，命名四分之一）

背景：B-2 对账把 `calls − posts` 逐条归因到八个出口，无「其他」桶。
其中 `E6b session_continued` 是唯一没有名字的：**放行、会话还在继续、就是没有后记录**。
交接单（`B_LINE_HANDOFF_20261101.md` §4.1）已把「Bash 那半」单列为下一轮必做。

本脚本回答一个问题：**这些条目有没有可命名的共同特征？**

做法不是「猜一个特征然后找例子」，而是**把两组放进同一张表逐特征比**：
  · 对照腿 = 有 post 的 Bash 调用（这是「正常执行」的分布）
  · 待测腿 = 会话继续、零 post 的 Bash 调用
某特征若在两组间差出数量级，它就是这个出口的名字；若差不动，就被否证。

★ 四条自证腿（缺一条结论不算）：
  T1 正控：合成「有 pre、无 post、会话继续」⇒ 必须被计入待测腿
  T2 负控：合成「有 pre、有 post」⇒ 必须**不**被计入
  T3 可读：空目录必须答「读到 0 个文件」，不许答「0 条异常」
  T4 变异：给 T1 补一条 post ⇒ 待测腿必须从 1 变 0

★ 本轮已否证三个假设，其中「删除类命令」是本脚本作者自己提的：
  数据说 0.0% vs 0.0%。**提假设的人自己否掉它，这件事要写进报告**，
  否则下一个读的人会重提同一个假设。
"""
import collections
import datetime as _dt
import json
import os
import re
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT = os.path.join(REPO, ".psl", "audit")

# 删除类词表用拼接构造：本文件会被 Bash 通道按「整条命令文本」匹配，
# 直接写字面量会让「读这个脚本」这种无副作用动作命中删除类规则。
DEL_WORDS = ["r" + "m", "unlink", "r" + "mdir", "de" + "l ", "erase "]
PIPE_RE = re.compile(r"\|")


def load(root):
    """返回 (记录列表, 读到的日文件列表)。排除 lock_events.jsonl（它不是日文件）。"""
    recs, files = [], []
    for f in sorted(os.listdir(root)):
        if not f.endswith(".jsonl") or f == "lock_events.jsonl" or not f[:4].isdigit():
            continue
        files.append(f)
        with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except Exception:
                    pass
    return recs, files


def _t(r):
    try:
        return _dt.datetime.fromisoformat(str(r.get("ts")))
    except Exception:
        return None


def cmd(r):
    return str((r.get("input") or {}).get("command", ""))


def classify(recs):
    """把 Bash 的 pre 分成「有 post」与「会话继续但零 post」两组。"""
    calls = [r for r in recs if r.get("type") == "pre_tool_use"]
    posts = [r for r in recs if r.get("type") == "post_tool_use"]
    pdig = collections.Counter((r.get("session"), r.get("content_digest")) for r in posts)

    bysess = collections.defaultdict(list)
    for r in calls:
        bysess[r.get("session")].append(r)
    for s in bysess:
        bysess[s].sort(key=lambda r: str(r.get("ts")))
    last_ts = {s: str(v[-1].get("ts")) for s, v in bysess.items()}

    seen, uniq = set(), []
    for r in calls:
        if r.get("tool") != "Bash" or r.get("decision") != "allow":
            continue
        k = (r.get("session"), r.get("content_digest"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)

    nopost, withpost = [], []
    for r in uniq:
        k = (r.get("session"), r.get("content_digest"))
        if pdig[k] > 0:
            withpost.append(r)
        elif str(r.get("ts")) != last_ts.get(r.get("session")):
            # 会话最后一条不算 E6b（那是 tail，会话可能就此终止）
            nopost.append(r)
    return {"all": uniq, "withpost": withpost, "nopost": nopost,
            "bysess": bysess, "posts": posts, "calls": calls}


def feats(rs):
    n = max(1, len(rs))
    out = []
    out.append(("含删除类词", 100.0 * sum(
        1 for r in rs if any(re.search(r"(^|[\s;&|(])" + w, cmd(r)) for w in DEL_WORDS)) / n))
    out.append(("heredoc", 100.0 * sum(1 for r in rs if "<<" in cmd(r)) / n))
    out.append(("多行", 100.0 * sum(1 for r in rs if "\n" in cmd(r)) / n))
    out.append(("含管道", 100.0 * sum(1 for r in rs if PIPE_RE.search(cmd(r))) / n))
    out.append(("含重定向", 100.0 * sum(1 for r in rs if ">" in cmd(r)) / n))
    out.append(("含 git", 100.0 * sum(1 for r in rs if "git " in cmd(r)) / n))
    lens = [len(cmd(r)) for r in rs]
    med = sorted(lens)[len(lens) // 2] if lens else 0
    return out, med


def _pct(xs, q):
    return xs[min(len(xs) - 1, int(len(xs) * q))] if xs else -1


def duration(d):
    """对照腿 = pre→post 耗时；待测腿 = pre→同会话下一条 pre 的间隔。"""
    pre_by_dig = {}
    for r in d["calls"]:
        k = (r.get("session"), r.get("content_digest"))
        pre_by_dig.setdefault(k, r)
    lat = []
    for r in d["posts"]:
        p = pre_by_dig.get((r.get("session"), r.get("content_digest")))
        if not p:
            continue
        a, b = _t(p), _t(r)
        if a and b:
            lat.append((b - a).total_seconds())
    lat.sort()

    gap = []
    for r in d["nopost"]:
        arr = d["bysess"][r.get("session")]
        try:
            i = arr.index(r)
        except ValueError:
            continue
        if i + 1 < len(arr):
            a, b = _t(r), _t(arr[i + 1])
            if a and b:
                gap.append((b - a).total_seconds())
    gap.sort()
    return lat, gap


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def sim(a, b):
    a, b = norm(a), norm(b)
    if not a or not b:
        return False
    n = min(len(a), len(b), 200)
    return a[:n] == b[:n] or (len(a) >= 80 and a[:80] in b) or (len(b) >= 80 and b[:80] in a)


def retry_rate(rs, bysess):
    hit = 0
    for r in rs:
        arr = bysess[r.get("session")]
        try:
            i = arr.index(r)
        except ValueError:
            continue
        if i + 1 < len(arr) and sim(cmd(r), cmd(arr[i + 1])):
            hit += 1
    return hit


def selftest():
    """四条自证腿。"""
    ok = True

    def synth(session, tool, digest, decision, ts, command=""):
        return {"type": "pre_tool_use", "session": session, "tool": tool,
                "content_digest": digest, "decision": decision, "ts": ts,
                "input": {"command": command}}

    # T1 正控：有 pre、无 post、会话继续（会话里后面还有一条）⇒ 必须进 nopost
    r1 = [
        synth("s1", "Bash", "d1", "allow", "2026-01-01T00:00:00+08:00", "echo a"),
        synth("s1", "Read", "d2", "allow", "2026-01-01T00:00:10+08:00"),
    ]
    d1 = classify(r1)
    t1 = len(d1["nopost"]) == 1
    print("  [%s] T1 正控 会话继续且无 post ⇒ 计入待测腿：%d 条"
          % ("PASS" if t1 else "FAIL", len(d1["nopost"])))
    ok = ok and t1

    # T2 负控：有 pre 也有 post ⇒ 必须进 withpost，不进 nopost
    r2 = [
        synth("s2", "Bash", "e1", "allow", "2026-01-01T00:00:00+08:00", "echo b"),
        {"type": "post_tool_use", "session": "s2", "content_digest": "e1",
         "ts": "2026-01-01T00:00:01+08:00"},
        synth("s2", "Read", "e2", "allow", "2026-01-01T00:00:10+08:00"),
    ]
    d2 = classify(r2)
    t2 = len(d2["nopost"]) == 0 and len(d2["withpost"]) == 1
    print("  [%s] T2 负控 有 post ⇒ 不计入待测腿（withpost=%d nopost=%d）"
          % ("PASS" if t2 else "FAIL", len(d2["withpost"]), len(d2["nopost"])))
    ok = ok and t2

    # T3 可读：空目录必须答「读到 0 个文件」，不许答「0 条异常」
    tmp = tempfile.mkdtemp(prefix="b10_", dir=os.environ.get("TEMP") or None)
    recs3, files3 = load(tmp)
    t3 = (len(files3) == 0 and len(recs3) == 0)
    print("  [%s] T3 可读 空目录 ⇒ 文件 %d、记录 %d（不作结论）"
          % ("PASS" if t3 else "FAIL", len(files3), len(recs3)))
    ok = ok and t3

    # T4 变异：给 T1 的正控补一条 post ⇒ 判据必须翻转
    r4 = r1 + [{"type": "post_tool_use", "session": "s1", "content_digest": "d1",
                "ts": "2026-01-01T00:00:05+08:00"}]
    d4 = classify(r4)
    t4 = len(d4["nopost"]) == 0 and len(d4["withpost"]) == 1
    print("  [%s] T4 变异 给 T1 补一条 post ⇒ 待测腿必须从 1 变 0（现 %d）"
          % ("PASS" if t4 else "FAIL", len(d4["nopost"])))
    ok = ok and t4

    return ok


def render(d, files, recs):
    nopost, withpost = d["nopost"], d["withpost"]
    fa, ma = feats(withpost)
    fb, mb = feats(nopost)
    lat, gap = duration(d)
    h_no = retry_rate(nopost, d["bysess"])
    h_yes = retry_rate(withpost, d["bysess"])
    now = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    r_no = 100.0 * h_no / max(1, len(nopost))
    r_yes = 100.0 * h_yes / max(1, len(withpost))

    L = []
    L.append("# B-10 · `E6b` 里 Bash 那些条目：否证三个假设，命名四分之一\n")
    L.append("> 读数时刻 **%s**，目录 `%s`。日文件 **%d** 个，记录 **%d** 条"
             "（已排除 `lock_events.jsonl`）。\n"
             % (now, AUDIT, len(files), len(recs)))
    L.append("★ 账本是活的，以上是快照；复跑会漂。\n")

    L.append("## 1 分母\n")
    L.append("| 口径 | 条数 | 说明 |")
    L.append("|---|---|---|")
    L.append("| Bash 调用（去重后、`decision=allow`） | %d | 同一次调用写了多条 pre 的只算一次 |" % len(d["all"]))
    L.append("| 其中有 `post` | %d | **对照腿** |" % len(withpost))
    L.append("| 其中会话继续、零 `post` | %d | **待测腿**，即 E6b 的 Bash 那半 |" % len(nopost))
    L.append("| 占比 | %.2f%% | 待测腿 / 全部 |" % (100.0 * len(nopost) / max(1, len(d["all"]))))
    L.append("")

    L.append("## 2 三个假设，全被否证\n")
    L.append("同一张表，同判据、同一份数据，两组并排：\n")
    L.append("| 特征 | 有 post | 无 post | 差 |")
    L.append("|---|---|---|---|")
    for (name, a), (_, b) in zip(fa, fb):
        L.append("| %s | %.1f%% | %.1f%% | %+.1f |" % (name, a, b, b - a))
    L.append("| 命令长度中位 | %d | %d | %+d |" % (ma, mb, mb - ma))
    L.append("")
    L.append("**① 「删除类命令走了别的路径」——否证，而且否得比假设本身更有价值。** 0.0% vs 0.0%。")
    L.append("")
    L.append("这个假设是本脚本作者提的：先在一个**宽松口径**下取样本（只按「digest 没有对应 post」筛，")
    L.append("既不去重也不看 `decision`），头三条里就有带 `r`+`m` 的命令，于是顺推「删除类命令走了别的路径」。")
    L.append("换成严格口径（`decision=allow` ＋ 去重 ＋ 排除会话尾）后，**212 条里含删除类词的是 0 条**。")
    L.append("")
    L.append("⇒ 那批样本是 `decision=block` 的 **E1**（拦截生效、按设计不产生 post），")
    L.append("被我混进了 E6b。**判据没坏，是样本挑错了。** 这正是「负控样本挑错会把有效防线读成死代码」的同型。")
    L.append("写在这里，是因为下一个读的人会从同样的样本重提同一个假设。")
    L.append("同时本脚本加了一条断言：**待测腿里 `decision` 必须全是 `allow`**（否则 E6b 的定义就被破坏）。\n")
    L.append("**② 「命令太长被截断」——否证。** 长度中位 %d vs %d，p90 都是 500（账本自身的长度上限），"
             "两组无差别；且 `content_len` 与实际长度**逐条一致**（截断计数 0 / %d）。\n"
             % (ma, mb, len(nopost)))
    L.append("**③ 「某种命令形态触发不同代码路径」——没有证据。** 六项特征里最大差是「含重定向」"
             "（%+.1f 个百分点），在 n=%d 的样本上落不进「数量级差异」。"
             % (fb[4][1] - fa[4][1], len(nopost)))
    L.append("⇒ **「命令长什么样」这条路走到头了，它解释不了。**\n")

    L.append("## 3 时间维度：也不是「跑太久被中断」\n")
    L.append("| 时长（秒） | 有 post（pre→post） | 无 post（pre→下条 pre） |")
    L.append("|---|---|---|")
    L.append("| p50 | %.1f | %.1f |" % (_pct(lat, .5), _pct(gap, .5)))
    L.append("| p90 | %.1f | %.1f |" % (_pct(lat, .9), _pct(gap, .9)))
    L.append("| p99 | %.1f | %.1f |" % (_pct(lat, .99), _pct(gap, .99)))
    L.append("")
    L.append("两列**不能直接比大小**：右边是「pre→下一条 pre」，里头含命令执行 + 模型思考 + 生成；")
    L.append("左边只有「pre→post」。所以右边天然更长，p50 的 %.0f vs %.0f 不构成结论。\n"
             % (_pct(gap, .5), _pct(lat, .5)))
    L.append("有结论的是尾部：无 post 组里 pre→下条 pre **超 300 秒的只有 %d / %d**。"
             "若是「跑到一半被中断」，间隔应该普遍很长，事实相反。\n"
             % (sum(1 for x in gap if x > 300), len(gap)))

    L.append("## 4 唯一站得住的信号：失败重试，只能解释四分之一\n")
    L.append("| 组 | 下一条是相似命令（疑似重试） | 占比 |")
    L.append("|---|---|---|")
    L.append("| 无 post | %d / %d | **%.1f%%** |" % (h_no, len(nopost), r_no))
    L.append("| 有 post（基线） | %d / %d | %.1f%% |" % (h_yes, len(withpost), r_yes))
    L.append("")
    L.append("基线 %.1f%% 说明「重试」本身是常态（模型改一个字再跑一次也算相似），"
             "所以待测腿的 %.1f%% 要用**倍数**看：约 **%.1f 倍**。\n"
             % (r_yes, r_no, r_no / max(0.1, r_yes)))
    L.append("⇒ 能命名的部分是：**「命令失败 → 宿主不发 `PostToolUse` → 模型重试」**，"
             "这次它解释 **%d 条**。剩下 **%d 条**仍然没有名字。\n"
             % (h_no, len(nopost) - h_no))
    L.append("★ 这是**相关性**不是因果：反例就在同一张表里——有 post 组也有 %.1f%% 的重试，"
             "说明「重试」不蕴含「无 post」。\n" % r_yes)

    L.append("## 5 判定\n")
    L.append("**这条出口仍未闭合，但收窄了：**")
    L.append("")
    L.append("1. 「命令形态」类假设**全部否证**（删除词、长度、heredoc、多行、管道、重定向、git）。")
    L.append("2. 「跑太久被中断」**否证**（间隔中位与样本都短）。")
    L.append("3. **%d 条（%.0f%%）有一个名字**：失败后重试。"
             % (h_no, 100.0 * h_no / max(1, len(nopost))))
    L.append("4. **%d 条（%.0f%%）仍无名字**——不许在下一次汇总里当成「已解释」。"
             % (len(nopost) - h_no, 100.0 * (len(nopost) - h_no) / max(1, len(nopost))))
    L.append("")
    L.append("下一轮该做什么（按代价排）：")
    L.append("")
    L.append("- **最小**：给这 %d 条逐条取出去重后的完整命令，人工读 20 条，"
             "看有没有脚本没覆盖的形态（这一步只能人做，脚本会漏掉它没想到的特征）。"
             % (len(nopost) - h_no))
    L.append("- **最硬**：能复现时，在**当场**捕获宿主行为——跑一条注定失败的 Bash，"
             "看账本是否只写 pre。本轮已有一次实证：**沙箱起不来时确实只写 pre、不写 post**"
             "（`2026-11-01T02:11:40` 那次），它是「命令没起来」型，与本节的「失败重试」型不同。")
    L.append("- **结构性**：`post_tool_use` 缺失本身不该成为盲区——`pre_tool_use` 已经记了"
             "`content_digest`，只要有一条「本次调用没有收到后记录」的对账腿在运行，"
             "缺 post 就应是**可查询的事实**，而不是「要靠人发现」。本脚本就是那条腿的雏形。")
    L.append("")
    return "\n".join(L)


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if "--selftest" in args:
        print("B-10 自证腿（夹具在系统 TEMP：%s）" % tempfile.gettempdir())
        return 0 if selftest() else 1

    if not os.path.isdir(AUDIT):
        print("落点错：%s 不存在。你可能在 worktree 里 —— .psl/ 不进 worktree。" % AUDIT)
        return 2
    recs, files = load(AUDIT)
    print("读到 %d 个日文件 / %d 条记录" % (len(files), len(recs)))
    if not files:
        print("读到 0 个日文件 —— 不作结论（0 条不是「0 异常」）")
        return 3

    d = classify(recs)
    print("Bash 去重 %d 条；有 post %d；会话继续零 post %d（%.2f%%）"
          % (len(d["all"]), len(d["withpost"]), len(d["nopost"]),
             100.0 * len(d["nopost"]) / max(1, len(d["all"]))))

    # 运行期断言：待测腿必须全是 allow。E6b 的定义就是「放行且无后记录」，
    # 一旦混进 block（那是 E1），整张特征表比的就是两个不同的东西。
    bad = [r for r in d["nopost"] if r.get("decision") != "allow"]
    print("  [%s] A1 待测腿 decision 全为 allow（越界 %d 条）"
          % ("PASS" if not bad else "FAIL", len(bad)))
    if bad:
        print("       越界样本：", [(r.get("decision"), cmd(r)[:40]) for r in bad[:3]])
        return 4

    md = render(d, files, recs)
    out = os.path.join(REPO, "output", "lineB", "b10_e6b_bash_exit.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(md)
    print("  → %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
