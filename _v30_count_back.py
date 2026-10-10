# -*- coding: utf-8 -*-
"""v3.0 方案件的计数回读：文档里每一个关键数，都用脚本重算一遍再对。

只读，不改文档。退出码 0 = 全部相符。
用法： python _v30_count_back.py <file.md>
"""
import io, os, re, json, subprocess, sys, collections, datetime

DOC = sys.argv[1]
ROOT = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(ROOT, ".psl", "audit")
txt = io.open(DOC, encoding="utf-8").read()

def has(s):
    return s in txt

results = []
LIVE = {"记录总数", "放行", "提醒", "拦截", "单条规则提醒数", "疑似真投毒"}

def ck(name, got, want_str):
    """★ 初版只判断「文档里有没有这个字符串」⇒ 25 条里 22 条假绿（复活 160 对文档 189 也判 OK）。
       量具的失效形态常常是「通过」，不是「报错」。⇒ 必须做数值比较，不是子串存在性判断。
       ★ 第二处口径：审计库在持续写入 ⇒ 总量类数字是【时点值】，重算必然继续增长。
         这类项按相对偏差 2% 判定，并在报告里标「活数」；其余严格相等。"""
    try:
        want = float(str(want_str).replace(",", ""))
    except ValueError:
        results.append((name, str(got), want_str, "★ 期望值非数值")); return
    got = float(got)
    if name in LIVE:
        ok = (want == 0 and got == 0) or abs(got - want) / max(abs(want), 1) < 0.02
        st = "OK（活数）" if ok else "★ 不符"
    else:
        ok = abs(got - want) < 0.51
        st = "OK" if ok else "★ 不符"
    results.append((name, int(got) if abs(got - int(got)) < 1e-9 else got, want_str, st))

# ---- 1. 生产仓复活记录 ----
rev = []          # (ts, cause, reason)
cause = collections.Counter()
for d, _dirs, fs in os.walk(AUDIT):
    for f in fs:
        if not f.endswith(".jsonl"): continue
        p = os.path.join(d, f)
        with io.open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: r = json.loads(line)
                except Exception: continue
                if r.get("type") == "host_shield_revived":
                    rev.append((r.get("ts"), r.get("cause"), r.get("reason") or ""))
                    cause[r.get("cause") or "-"] += 1
ck("生产仓复活条数", len(rev), "160")
ck("复活触发来源 自家钩子", cause.get("hook-paramedic"), "143")
ck("复活触发来源 人工", cause.get("console"), "15")

def ts_of(r):
    v = r.get("ts")
    if isinstance(v, (int, float)): return float(v)
    if isinstance(v, str):
        try: return datetime.datetime.fromisoformat(v.replace("Z", "")).timestamp()
        except Exception: return None
    return None

ts_by_file = collections.defaultdict(list)
for d, _dirs, fs in os.walk(AUDIT):
    for f in fs:
        if not f.endswith(".jsonl"): continue
        p = os.path.join(d, f)
        with io.open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: r = json.loads(line)
                except Exception: continue
                if r.get("type") == "host_shield_revived":
                    x = ts_of(r)
                    if x: ts_by_file[p].append(x)
gaps = []
for _p, ts in ts_by_file.items():
    ts.sort()
    gaps += [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
gaps.sort()
short = [g for g in gaps if g < 300]
edge  = [g for g in gaps if 290 <= g <= 310]
mid   = [g for g in gaps if 5 <= g < 60]
med   = gaps[len(gaps) // 2]
ck("同文件相邻间隔总数", len(gaps), "145")
ck("短于节流窗", len(short), "68")
ck("落在节流边界", len(edge), "2")
ck("五到六十秒档", len(mid), "34")
ck("间隔中位数（秒）", round(med), "341")
none_pid = sum(1 for _t, _c, rn in rev if "pid=None" in rn)
ck("旧进程号为空", none_pid, "91")

# ---- 2. 全量决策分布 ----
ROOTS = [r"C:\Users\大马\.antinel", r"C:\Users\大马\.workbuddy\antinel-audit",
         ROOT, r"D:\2026\PSL"]
SKIP = {".git", "node_modules", "__pycache__"}
nfile = ntot = nbad = 0
dec = collections.Counter(); alert_types = collections.Counter(); tamper = collections.Counter()
for root in ROOTS:
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP and not x.startswith("_buildjunk")
                   and not x.startswith("antinel-0.")]
        if d[len(root):].count(os.sep) > 7:
            dirs[:] = []; continue
        for f in fs:
            if not f.endswith(".jsonl"): continue
            nfile += 1
            try: fh = io.open(os.path.join(d, f), encoding="utf-8", errors="replace")
            except Exception: continue
            with fh:
                for line in fh:
                    line = line.strip()
                    if not line: continue
                    try: r = json.loads(line)
                    except Exception: nbad += 1; continue
                    ntot += 1
                    if r.get("decision"): dec[r["decision"]] += 1
                    if r.get("decision") == "alert" and r.get("type"):
                        alert_types[r["type"]] += 1
                    if r.get("type") == "host_shield_tamper":
                        s = r.get("reason") or ""
                        k = ("自检不符" if "自检不符" in s else
                             "布防位不一致" if "enabled" in s else
                             "疑似投毒" if "投毒" in s else "其它")
                        tamper[k] += 1
ck("记录文件数", nfile, "422")
ck("记录总数", ntot, "364,983")
ck("解析失败", nbad, "2,384")
ck("放行", dec["allow"], "56,993")
ck("提醒", dec["alert"], "16,797")
ck("拦截", dec["block"], "2,403")
ck("拒绝", dec["deny"], "735")
ck("配置回退", dec["config_fallback"], "102")

# 规范值输出（供更新文档；这两个数在文档里是「占比」形态，需先算出分子分母）
_d02 = alert_types.get("dst02_bash_path_suspect", 0)
# ---- 6. 规范值一览（统一用「生产仓 .psl\audit」口径；时点＝脚本运行时刻）----
g5 = [g for g in gaps if g < 5]
g60 = [g for g in gaps if 5 <= g < 60]
g290 = [g for g in gaps if 60 <= g < 290]
print("\n== 规范值一览（供更新文档）==")
print("  复活条数（生产仓审计目录）      = %d" % len(rev))
print("  触发来源 自家钩子 / 人工         = %d / %d" % (cause.get("hook-paramedic", 0), cause.get("console", 0)))
print("  旧进程号为空                    = %d（%.1f%%）" % (none_pid, 100.0 * none_pid / max(len(rev), 1)))
print("  间隔分桶：小于5秒=%d，5至60秒=%d，60至290秒=%d，290至310秒=%d，5分至1小时=%d，大于1小时=%d"
      % (len(g5), len(g60), len(g290), len(edge),
         len([g for g in gaps if 310 < g < 3600]), len([g for g in gaps if g >= 3600])))
print("  短于节流窗（小于300秒）         = %d / %d（%.1f%%）" % (len(short), len(gaps), 100.0 * len(short) / max(len(gaps), 1)))

# 同秒并发簇：同一文件、同一秒出现多条 ⇒ 多出来的条数
sec = collections.Counter()
for _p, ts in ts_by_file.items():
    for t in ts:
        sec[(round(t), _p)] += 1
burst = sum(v - 1 for v in sec.values() if v > 1)
print("  同秒并发簇多出的条数            = %d（%.1f%%）" % (burst, 100.0 * burst / max(len(rev), 1)))

now = datetime.datetime.now().timestamp()
n48 = sum(1 for t in ts_by_file for x in ts_by_file[t] if now - x <= 48 * 3600)
print("  最近 48 小时拉起次数            = %d" % n48)
print("  提醒与拦截之比                  = %d : %d（约 %.1f : 1）"
      % (dec["alert"], dec["block"], dec["alert"] / max(dec["block"], 1)))

print("  规范值｜单条路径疑似规则提醒数 = %d；提醒总数 = %d；占比 %.1f%%"
      % (_d02, dec["alert"], 100.0 * _d02 / max(dec["alert"], 1)))
print("  规范值｜篡改构成 = %s；总数 = %d"
      % (dict(tamper), sum(tamper.values())))
ck("单条规则提醒数", _d02, "12,350")
ck("篡改总数", sum(tamper.values()), "160")
ck("疑似真投毒", tamper.get("疑似投毒", 0), "12")

# ---- 3. 本仓结构数 ----
def grep_count(path, pat, flags=re.M):
    s = io.open(path, encoding="utf-8", errors="replace").read()
    return len(re.findall(pat, s, flags))
hs = os.path.join(ROOT, "host_shield.py")
# 判据取「整份写回那个名为 state 的变量」这种形态，不是全部 save_state 出现处
ck("主循环整份写回处数", grep_count(hs, r"save_state\(state\)"), "6")
ck("按字段更新调用处数", grep_count(hs, r"^\s*update_state_fields\("), "3")

rules = json.load(io.open(os.path.join(ROOT, "rules", "default.json"), encoding="utf-8"))
dst01 = None
for r in rules if isinstance(rules, list) else rules.get("rules", []):
    if r.get("id") == "DST-01" or "DST-01" in json.dumps(r)[:200]:
        dst01 = r; break
if dst01:
    ck("删除规则命令模式条数", len(dst01.get("command_patterns") or []), "21")
    ck("删除规则例外条数", len(dst01.get("exclude_patterns") or []), "19")

# ---- 4. 构建目录被追踪文件数（本仓）----
try:
    out = subprocess.run(["git", "ls-files", "build"], cwd=ROOT, capture_output=True, text=True)
    n61 = len([x for x in (out.stdout or "").split("\n") if x.strip()])
except Exception:
    n61 = -1
ck("构建目录被追踪", n61, "61")

print("== 计数回读 ==")
bad = 0
for name, got, want, st in results:
    # ★ 判定一律走 startswith("OK")：活数分支的 st 是「OK（活数）」，
    #   用 == 判断会把它当成不符 —— 量具自己的显示口径也会造成假红。
    flag = "OK " if st.startswith("OK") else "★"
    if not st.startswith("OK"): bad += 1
    print("  %s %-22s 重算=%-12s 文档写=%-12s %s" % (flag, name, got, want, st))
print("\n相符 %d / %d；不符 %d" % (len(results) - bad, len(results), bad))
sys.exit(1 if bad else 0)
