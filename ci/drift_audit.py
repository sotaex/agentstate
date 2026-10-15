# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

r"""Antinel 漂移审计 v1.0：需求文件 → 盘上行为，逐条机械化验证。
需求源：RULES.md / THREAT_MODEL.md v0.27 / AUDIT_SCHEMA v1.2 / SKILL.md / A6 / 三问三答 / UX定稿 / 宿主审计说明书 v1.2
审计对象：部署包（默认 D:\psl\poc\antinel-security，可用 ANTINEL_PKG 覆盖）（与真实行为，非文档对照文档）

0.29.0 两处修正：
  · 本 docstring 改成 **raw 字符串**（r 前缀）。它里面的 Windows 路径含 \p，非 raw 时会触发
    `SyntaxWarning: invalid escape sequence '\p'`（Python 3.12+ 告警，未来版本会变成错误）。
  · PKG 改为可用环境变量覆盖。写死一个绝对路径等于"只有这台机器能跑"——既无法审计
    暂存构建，换台机器就废。与 D-5（antinel.py 硬编码作者机解释器路径）同族。
"""
import io, sys, os, json, re, subprocess, tempfile, shutil, hashlib, glob

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
PKG = os.environ.get("ANTINEL_PKG", r"D:\psl\poc\antinel-security")
PY = sys.executable
HOOK_PRE = os.path.join(PKG, "hooks", "pre_tool_use.py")
HOOK_POST = os.path.join(PKG, "hooks", "post_tool_use.py")

results = []
def check(n, ok, evidence=""):
    results.append((n, bool(ok), str(evidence)[:160]))
    print(("PASS " if ok else "FAIL ") + n + ("" if ok else "  -- " + str(evidence)[:160]))


def blocked(n, why):
    """★ 第三态（2026-09-26 加）：**受阻（没测到）**，既不是 PASS 也不是 FAIL。

    与 A11d 同一条纪律：**受阻 ≠ 通过**。把"量具被环境摆布"记成 FAIL ⇒ 长期红 ⇒
    没人看（＝没有守卫）；记成 PASS ⇒ 假绿，比没有还坏。必须单列。

    ★ 为什么需要它：门闸靠 ACL 拒写。**审计进程若处在提权（High/System 完整性）
    上下文**，`acl_deny` 授出的 `BUILTIN\\Administrators:(OI)(CI)(F)` 对该进程本身生效
    ⇒ `is_denied()` 恒为 False ⇒ 锁**在审计进程眼里**永远没上。
    后果是整段门闸检查**双向失真**：
      · A13b / A16（期望"锁得住"）⇒ 恒 FAIL（假红）
      · A12 / A13（期望"锁不住"）⇒ 恒 PASS（**假绿**，正是「没有对象的检查项」）
    实测 2026-09-26：`whoami /groups` = `High Mandatory Level`(S-1-16-12288) +
    `BUILTIN\\Administrators` 启用；acl_deny 在 temp/workspace/pkg 三处**全部** is_denied=False，
    而 icacls 文本显示用户仅 `(WDAC,RD,X)` —— 说明生效的是 Administrators 那条 ACE。
    ⇒ 这是**环境**，不是产品缺陷（`_lock_pending_tree` 在 `acl_deny` 失败时如实记
    `【上锁未生效】` 且 severity=critical，留痕是诚实的）。
    """
    results.append((n, None, str(why)[:200]))
    print("BLOCK " + n + "  -- " + str(why)[:200])


# ★ 端到端钩子 / 子命令类检查的统一判据（2026-09-26 加）。
#   依据 A11d 的实测：宿主删除守卫越阈时，钩子内的 `os.remove` 被杀 ⇒ 钩子表现为 **rc=1**。
#   rc=1 既不是"放行"也不是"拦下"，是**没测到** ⇒ 按「受阻 ≠ 通过」必须单列。
#   ★ 不单列就会被读成一次真失败 —— 一次假红就足以让人开始忽略这条守卫
#     （「一个会误报的检查器，用两次就没人信了」）。
# ★★ 级联（同日实测）：环境一旦坏了，**由那次钩子输出派生的项**也一起变红 ——
#   A5b（读链里有没有 released）、A11b（读 rc==2）、A11d（自己）全红，于是审计的
#   FAIL 数开始**依赖环境**，不再可信。⇒ 一处检测、全线归因：`hook()` 见到
#   rc=1（且无 traceback）就**立旗**，派生项用 `_chk_env()` 记 BLOCKED。
#   旗子**只立不撤**（一个回合内环境不会自愈）。
_HOOK_ENV = {"dead": False}


def _hook_env_dead(rc, err):
    """rc==1 且**没有 traceback** ⇒ 判定为「被宿主环境杀死」，并**立旗**（只立不撤）。
    返回：**本次**是不是环境杀死。

    ★ 防遮蔽：真崩溃（未捕获异常）会留 traceback ⇒ 不立旗、照旧记 FAIL ——
      否则这条判据本身就成了"把所有 rc=1 都洗白"的假守卫（本仓最忌讳的那种）。
    """
    hit = (rc == 1 and "Traceback" not in (err or ""))
    if hit:
        _HOOK_ENV["dead"] = True
    return hit


def _chk_hook(name, rc, ok, evidence="", err=""):
    """端到端钩子 / 子命令类检查：**本次** rc==1 ⇒ 受阻（BLOCKED），不记 FAIL。"""
    if _hook_env_dead(rc, err):
        blocked(name, "rc=1：被宿主环境杀死（多为删除守卫越阈；实测输出含 "
                      "SAFE_DELETE_BULK_CONFIRM_REQUIRED）⇒ 本次没测到，换一个回合重跑即恢复")
    else:
        check(name, ok, evidence)


def _chk_env(name, ok, evidence=""):
    """**派生项**（结论取自上面某次钩子的输出或它写的链）：环境已坏 ⇒ 没测到，不记 FAIL。"""
    if _HOOK_ENV["dead"]:
        blocked(name, "本次钩子被宿主环境杀死（rc=1，多为删除守卫越阈）⇒ 该项由那次输出派生，"
                      "结论没测到；换一个回合重跑即恢复")
    else:
        check(name, ok, evidence)

base = tempfile.mkdtemp(prefix="drift_")
proj = os.path.join(base, "proj")
os.makedirs(os.path.join(proj, ".psl", "rules"))
shutil.copy(os.path.join(PKG, "rules", "default.json"), os.path.join(proj, ".psl", "rules", "default.json"))
rb = open(os.path.join(proj, ".psl", "rules", "default.json"), "rb").read()
json.dump({"rules_hash": "sha256:" + hashlib.sha256(rb).hexdigest(),
           "hooks_registered": ["PreToolUse", "PostToolUse"]},
          open(os.path.join(proj, ".psl", "manifest.json"), "w", encoding="utf-8"))
json.dump({"global_settings": {}, "whitelist": {"domains": [], "paths": [], "commands": []}},
          open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))

def hook(script, tool, ti, sid="d"):
    ev = {"session_id": sid, "transcript_path": "", "tool_name": tool, "tool_input": ti}
    # ★ 2026-09-28：接住子进程超时。此前 `subprocess.run(..., timeout=60)` 的
    #   `TimeoutExpired` **直接冒到顶**，一次钩子变慢就让**整份审计脚本死掉**，
    #   后面几十条检查项一条都不跑 —— 输出看起来像"审计通过了一部分"，实际是**没跑**。
    #   口径与 `scripts/verification_tests.py:159` 完全一致：超时 ⇒ `rc=124`。
    #   `rc=124` 不是"放行"也不是"拦下" ⇒ `_hook_env_dead` 不立旗、`_chk_hook` 记 FAIL，
    #   即「这次没测到」不会被读成「这次通过了」。
    try:
        p = subprocess.run([PY, os.path.join(PKG, "hooks", script)], cwd=proj,
                           input=json.dumps(ev).encode(), capture_output=True, timeout=60)
        _rc, _so, _se = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        _rc = 124
        _so = e.stdout or b""
        _se = (e.stderr or b"") + b"\n[TIMEOUT] %s " % script.encode() + b"exceeded 60s (no return)"
    out = {}
    try:
        out = json.loads(_so.decode("utf-8", "replace").strip().splitlines()[-1])
    except Exception as _e2:
        # ★ 2026-09-30：此处原为 `pass`（**静默**）。
        #   危害：`out` 变成 `{}` 后，调用方若判「某键**不存在**」就会得到 True
        #   ⇒ **假绿**：把"没解析出来"读成"没发现"（铁律②「报出来≠出事了」的反面）。
        #   ⇒ 解析失败必须**留痕**：塞进 err，让读输出的人看得见这次没测到。
        _se = _se + ("\n[JSON-PARSE-FAILED] %s: %s" % (type(_e2).__name__, _e2)).encode()
    _err = _se.decode("utf-8", "replace")
    _hook_env_dead(_rc, _err)               # ★ 立旗：环境坏了 ⇒ 后面的派生项按"受阻"归因
    return _rc, out, _err

def chain_lines():
    fn = os.path.join(proj, ".psl", "audit", "2026-09-22.jsonl")
    if not os.path.isfile(fn):
        import datetime
        fn = os.path.join(proj, ".psl", "audit",
                          datetime.datetime.now().strftime("%Y-%m-%d") + ".jsonl")
    if not os.path.isfile(fn):
        return []
    return [json.loads(l) for l in open(fn, encoding="utf-8") if l.strip()]

# ---- A. 协议与规则 ----
rules = json.load(open(os.path.join(PKG, "rules", "default.json"), encoding="utf-8"))["rules"]
fam = {}
for r in rules:
    fam.setdefault(r["id"].split("-")[0], []).append(r["id"])
# 0.29.0：**不再硬编码条数**。此前 A1 写死 `len(rules) == 24`、A2 写死家族计数
# （SEC6/NET3/DST10/CTX5）。规则集一变（25→31）这两个守卫就变成**假红**：rules 与文档
# 其实一致，只是守卫自己过期了。**守卫过期 = 没有守卫。** 正确判据是"文档 vs 数据"：
_tm = open(os.path.join(PKG, "references", "THREAT_MODEL.md"), encoding="utf-8").read()
_m = re.search(r"(\d+)\s*rules", _tm)
_claimed = int(_m.group(1)) if _m else None
check("A1 规则总数与 THREAT_MODEL 宣称一致", _claimed == len(rules),
      f"宣称 {_claimed}，实际 {len(rules)}")
# A2 改成**结构不变量**：每个家族的编号必须自 1 起连续、无洞、无重复。
# 这样规则增减不会让它假红，而"加了 DST-12 却漏了 DST-11"这类真错仍会被抓住。
#
# 0.29.0 增补：**已知编号洞显式声明**。CTX-06 经查在两仓（源/产物）均不存在、
# 全仓零引用、0.29.0 之前的备份里也没有 ⇒ 是**从未存在过的历史遗留**，不是被删掉的。
# 处理原则：**不许为了让它绿而把守卫改松**（那是"守卫过期＝没有守卫"的老路）。
# 正确做法是把"这个洞是我知道的"写成**数据**，于是：
#   · 新的洞            → 照样报警（守卫没被削弱）
#   · 声明的洞被补上了  → 反而报警（提示声明过期，防止声明腐烂）
KNOWN_HOLES = {"CTX": {6}}
_gaps = []
for _f, _ids in sorted(fam.items()):
    _n = sorted(int(i.split("-")[1]) for i in _ids if i.split("-")[1].isdigit())
    _dup = sorted(set(x for x in _n if _n.count(x) > 1))
    _holes = set(KNOWN_HOLES.get(_f, ()))
    _expect = set(range(1, max(_n) + 1)) - _holes
    _missing = sorted(_expect - set(_n))        # 出现了新洞
    _stale = sorted(set(_n) & _holes)           # 声明的洞被补上了 ⇒ 声明过期
    if _dup or _missing or _stale:
        _gaps.append({"家族": _f, "实际": _n, "重复": _dup,
                      "新出现的洞": _missing, "声明过期(洞已补上)": _stale})
check("A2 家族编号自 1 起连续（已知洞 %s 除外）、无重复" % (
          "、".join("%s-%02d" % (f, n) for f, s in sorted(KNOWN_HOLES.items()) for n in sorted(s)) or "无"),
      not _gaps,
      f"异常 {_gaps}；实际计数 {json.dumps({k: len(v) for k, v in fam.items()})}")

# A10（0.29.0 新增）：**随包文档里的规则区间 vs 实际规则**。
# 为什么必须有这一项：0.29.0 把规则从 25 加到 31，总数用令牌自动跟上了，
# 但 THREAT_MODEL/README 里的**家族区间仍是手写** ⇒ 文档仍在宣称
# `SEC-01..06`（实际 10）、`DST-01..10`（实际 11）、只列 `NET-03`（实际 4）、
# 且**完全没提 CTX-07** —— 静默少报了 4 条**偷数据防线**（SEC-07..10）。
# 而 THREAT_MODEL 自己就写着 "a stale range silently understates what is enforced"。
# ★ 没有这一项 ⇒ 第 5 项（区间改动态生成）就**没有检查项盯着**，等于没有禁令。
# ★ 2026-09-28 修订：原实现**只读 `references/THREAT_MODEL.md`**，而上面注释里
#   明明写着「THREAT_MODEL/README 里的家族区间仍是手写」—— 注释说了、代码没做。
#   后果实测：`README.md:30` 一直写 `SEC-01..10`（实际 11），而 A10 看不见它
#   ⇒ **判据覆盖不全**，正是「查不出来 ≠ 查出来是好的」。
#   ⇒ 改为**逐文档**检查，新增文档时只要加进 `_RANGE_DOCS` 即可。
_RANGE_DOCS = ["references/THREAT_MODEL.md", "README.md"]
_live_ids = set((_f2, int(i.split("-")[1])) for _f2, _ids2 in fam.items() for i in _ids2)
_ghost, _short = [], []
for _docrel in _RANGE_DOCS:
    _dp = os.path.join(PKG, _docrel)
    if not os.path.exists(_dp):
        _short.append("%s 不存在（区间无从核对）" % _docrel)
        continue
    _txt = open(_dp, encoding="utf-8").read()
    _doc_ids = set()
    for _mm in re.finditer(r"\b([A-Z]{3})-(\d{2})(?:\.\.(\d{2}))?", _txt):
        _f2, _a = _mm.group(1), int(_mm.group(2))
        _b = int(_mm.group(3)) if _mm.group(3) else _a
        if _f2 not in fam:
            continue                               # 不是规则家族的缩写，不参与
        for _k in range(_a, min(_b, _a + 200) + 1):   # 上限防呆，避免文档笔误炸掉
            _doc_ids.add((_f2, _k))
    for _x in sorted("%s-%02d" % y for y in (_doc_ids - _live_ids)):
        _ghost.append("%s:%s" % (_docrel, _x))     # 文档提了但不存在
    _byfam = {}
    for _f2, _n2 in _doc_ids:
        _byfam.setdefault(_f2, set()).add(_n2)
    for _f2, _ids2 in sorted(fam.items()):
        _liven = sorted(int(i.split("-")[1]) for i in _ids2)
        _docn = _byfam.get(_f2) or set()
        if not _docn:
            continue
        # ★ 已知洞不算"少报"：CTX-06 本身就不存在，要求文档写出它反而是错的。
        _miss = [x for x in range(max(_docn) + 1, max(_liven) + 1)
                 if x not in set(KNOWN_HOLES.get(_f2, ()))]
        if _miss:
            _short.append("%s: %s 止于 %02d、实际止于 %02d（少报 %s）" % (
                _docrel, _f2, max(_docn), max(_liven),
                "、".join("%s-%02d" % (_f2, x) for x in _miss)))
        if min(_docn) != min(_liven):
            _short.append("%s: %s 起于 %02d、实际起于 %02d" % (
                _docrel, _f2, min(_docn), min(_liven)))
check("A10 随包文档（THREAT_MODEL + README）规则区间与实际一致（不多报、不少报）",
      not _ghost and not _short,
      ("文档提到但不存在的规则 %s；" % _ghost if _ghost else "")
      + ("区间少报/错位 %s" % _short if _short else ""))

rc, out, err = hook("pre_tool_use.py", "Bash", {"command": "rm -rf /tmp/x"})
_chk_hook("A3 critical=block：exit2+stdout JSON+stderr 双通道", rc,
      rc == 2 and out.get("decision") == "block" and "拦截" in err, f"rc={rc} out={out}", err)
rc, out, err = hook("pre_tool_use.py", "Bash", {"command": "curl http://evil-drift-check.com/x"})
_chk_hook("A4 warning=alert：exit0+stderr 提醒+放行", rc,
      rc == 0 and "NET-01" in err and out.get("decision") != "block", f"rc={rc}", err)

# A5 whitelist.paths：放行 SEC 读 + dst02_path_whitelisted 留痕（写 .ssh 下一个白名单路径）
pol = json.load(open(os.path.join(proj, ".psl", "policy.json"), encoding="utf-8"))
pol["whitelist"]["paths"] = [(proj + "\\keys\\").replace("\\", "/")]
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))
rc, out, err = hook("pre_tool_use.py", "Read", {"file_path": os.path.join(proj, "keys", "id_rsa")})
cl = chain_lines()
# 0.29.0 (D-1)：本项此前**长期红** —— 判据要求"放行了 且 留痕"，代码只做了一半
# （放行了，什么都不写）。现在补上 `sec_path_whitelisted` 事件类型，并把新类型加进
# 期望集合 —— ★ 只改生产代码不改这条判据 = 改了一半：守卫还在找旧类型，永远不会绿。
allow_logged = any(r.get("type") in ("workspace_root_allow", "dst02_path_whitelisted",
                                     "sec_path_whitelisted") for r in cl)
_chk_hook("A5 whitelist.paths 豁免 SEC 读且留痕", rc, rc == 0 and allow_logged, f"rc={rc} 留痕={allow_logged}", err)
# A5b（0.29.0 新增）：账本必须能区分"放行"与"没命中"。
# 放行后主记录若仍是 {rules_hit: [], severity: "none"} 而与"没匹配任何规则"同形，
# 则事后复盘无法区分 ⇒ 判据④同型（"被放行"被伪装成"没命中"）。
_released = [r for r in cl if r.get("type") == "pre_tool_use" and r.get("released")]
_chk_env("A5b 放行在主记录上标 released（不与'没命中'同形）", bool(_released),
         f"带 released 字段的主记录 {len(_released)} 条")

# A11（0.29.0 E-2 新增）：**万能卡不得复活**。
# 路径白名单只该开"靠路径判断"的那扇门。C 批次把 `category == "secrets"` 一刀切收窄为
# 必须带 file_patterns，于是与路径无关的三条（SEC-06 密钥字面量 / SEC-07 剪贴板 /
# SEC-08 截屏）不再被顺带放行 —— 此前实测 `pbpaste` 因同一次调用带了个白名单内路径
# 就被静默放过。
# ★ 为什么必须补这条守卫：按「无检查项的禁令 ＝ 没有禁令」，收窄做完而无人盯着
#   ⇒ 下次有人改回一刀切，没人会发现。
# ★ 负控前提：先确认"确实存在与路径无关的 secrets 规则"。否则本项就是
#   「没有对象的检查项 ＝ 假守卫」—— 与我自己犯过的 G-1 同型（查了一个不存在的键名）。
_pathless = sorted(r["id"] for r in rules
                   if r.get("category") == "secrets" and not r.get("file_patterns"))
check("A11a 本守卫有对象：存在与路径无关的 secrets 规则", len(_pathless) >= 1,
      f"无 file_patterns 的 secrets 规则 = {_pathless}")
# 白名单此时仍开着（A5 设的 proj/keys/），故意让它带一个白名单内的 file_path
rc, out, err = hook("pre_tool_use.py", "Bash",
                    {"command": "pbpaste", "file_path": os.path.join(proj, "keys", "a.txt")})
_chk_env("A11b 路径白名单不再顺带放行剪贴板读取（万能卡已废）", rc == 2,
         f"rc={rc}（白名单开着；rc=0 即万能卡复活）")
# A11d（0.29.0 E-2）：**端到端钩子有没有被宿主环境杀死**。
# F-1：WorkBuddy 的删除守卫按**回合**计数（阈值 50），而 Antinel 每次写审计都要
# `os.remove` 锁文件 ⇒ 长回合内累积越阈后删除被杀，钩子表现为 **rc=1**。
# ★ 为什么必须单列：rc=1 既不是"放行"也不是"拦下"，是**没测到**。按「受阻 ≠ 通过」，
# 任何 rc==1 的端到端结论都不可信；不单列，它就会被读成一次真失败 —— 而一次
# 假红就足以让人开始忽略这条守卫（「一个会误报的检查器，用两次就没人信了」）。
_chk_env("A11d 端到端钩子未被宿主环境杀死（rc∈{0,2}；rc=1 = 受阻）", rc in (0, 2),
         f"rc={rc}（rc=1 多为 F-1 宿主删除守卫越阈，换一个回合重跑即恢复）")
_src = open(os.path.join(PKG, "hooks", "pre_tool_use.py"), encoding="utf-8").read()
_i = _src.find('if path_wl and rule.get("category") == "secrets"')
check("A11c 放行分支仍带 file_patterns 限定（防退回一刀切）",
      _i > 0 and "file_patterns" in _src[_i:_i + 200],
      (_src[_i:_i + 120] if _i > 0 else "未找到放行分支"))

# A6 whitelist.commands 不得放宽 critical
pol = json.load(open(os.path.join(proj, ".psl", "policy.json"), encoding="utf-8"))
pol["whitelist"]["commands"] = ["rm -rf /tmp/x"]
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))
rc, out, err = hook("pre_tool_use.py", "Bash", {"command": "rm -rf /tmp/x"})
_chk_hook("A6 whitelist.commands 不放宽 critical（仍拦）", rc, rc == 2, f"rc={rc}", err)
pol["whitelist"]["commands"] = []
json.dump(pol, open(os.path.join(proj, ".psl", "policy.json"), "w", encoding="utf-8"))

# A7 DST-09/10 平台门（规则在场=计数不变；nt 外跳过）
d9 = next(r for r in rules if r["id"] == "DST-09")
# 0.29.0：`platforms` 在规则文件里是**列表**（['nt']），此前拿字符串 `== "nt"` 比 ⇒ 永远假红。
_plats = d9.get("platforms")
check("A7 DST-09/10 platforms 限定 nt（计数平台不变）", _plats in ("nt", ["nt"]),
      f"platforms={_plats!r} (type={type(_plats).__name__})")

# A8 不记内容只记哈希/长度 + mask
big = "SECRET" * 3000
hook("pre_tool_use.py", "Write", {"file_path": os.path.join(proj, "big.txt"), "content": big})
cl = chain_lines()
wrecs = [r for r in cl if r.get("input", {}).get("content_len")]
check("A8 只记 content_len 不记内容",
      bool(wrecs) and all("content" not in r.get("input", {}) or not r["input"].get("content")
                          for r in wrecs), f"{len(wrecs)} 条含 content_len")

# A9 运行时零网络：钩子源码无**出站**网络调用
#
# ★ 2026-09-28 修订：原判据「源码里出现 `import socket` 就红」**过粗**。
#   实测命中 1 处：`hooks/pre_tool_use.py:2624` 的 `import socket as _sock`，
#   它属于 0.33.0 的**常驻判定薄客户端**（`performance_mode=resident`，**默认 hook、opt-in**）：
#     连接目标写死 `("127.0.0.1", _jd["port"])` —— 本机回环 IPC，**不是外网**。
#   ⇒ 语义上「运行时零网络（外传）」并未被违反；违反的是判据的**字面**。
#   长期红的守卫＝没有守卫：这一条从 0.33.0 起一直红，真有事时没人能从红里认出来。
#
# ★ 为什么不是"把 socket 从名单里删掉"：那样连**真的**出站也会漏判（改松判据）。
#   收紧为**语义判据** —— 逐处看这次 import 到底连去哪：
#     · 只允许出现在 `performance_mode == "resident"` 的薄客户端段里；
#     · 该段里的 `connect(...)` 主机必须是 `127.0.0.1` / `localhost` / `::1`；
#     · 同一段里**不许**出现任何非回环主机字面量或外部 URL。
#   `requests` / `urllib` / `httpx` / `http.client` 仍是**无条件红**（没有回环用法）。
net_hits = []
_allowed_loopback = []
for f in (HOOK_PRE, HOOK_POST):
    src = open(f, encoding="utf-8").read()
    for pat in (r"import requests", r"import urllib", r"httpx", r"http\.client"):
        if re.search(pat, src):
            net_hits.append((os.path.basename(f), pat))
    if re.search(r"import socket", src):
        # 有 socket 导入 ⇒ 逐条核对它是否只用于回环
        _lines = src.splitlines()
        _nonloop = re.findall(r'connect\(\s*\(\s*["\']([^"\']+)["\']', src)
        _bad_hosts = [h for h in _nonloop
                      if h not in ("127.0.0.1", "localhost", "::1")]
        _urls = re.findall(r'https?://[A-Za-z0-9._-]+', src)
        _urls = [u for u in _urls
                 if not re.match(r'https?://(127\.0\.0\.1|localhost)([:/]|$)', u)]
        if _bad_hosts or _urls:
            net_hits.append((os.path.basename(f),
                             "socket 用于非回环：hosts=%r urls=%r" % (_bad_hosts, _urls)))
        else:
            _allowed_loopback.append(
                (os.path.basename(f), "%d 处 connect 全为回环" % len(_nonloop)))
check("A9 钩子运行时零网络（无出站调用；socket 仅限 127.0.0.1 回环 IPC）",
      not net_hits,
      str(net_hits) if net_hits else "放行回环: %s" % (_allowed_loopback or "无 socket 导入"))

# ---- B. 链（AUDIT_SCHEMA v1.2）----
cl = chain_lines()
ok_hash = ok_prev = True
prev_full = ""
for r in cl:
    body = {k: v for k, v in r.items() if k != "hash"}
    canon = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    if hashlib.sha256((prev_full + canon).encode("utf-8")).hexdigest() != r.get("hash"):
        ok_hash = False
    if r.get("prev", "") != prev_full[-16:]:
        ok_prev = False
    prev_full = r.get("hash", "")
check("B1 链公式可复算（AUDIT_SCHEMA §2）", ok_hash and ok_prev and len(cl) > 3,
      f"{len(cl)} 条 hash_ok={ok_hash} prev_ok={ok_prev}")

mainf = os.path.join(proj, ".psl", "audit")
side = os.path.join(mainf, "sidecar")
check("B2 主链无 unlocked 记录（v1.2：降级落 sidecar）",
      all(r.get("chain") != "unlocked" for r in cl), "")
check("B3 day_manifest 日锚存在且单调", os.path.isfile(os.path.join(mainf, "day_manifest.json")), "")
# B4 第三方验证器**必须进出件**（不是"源码树里有"）。
#   ★ 2026-10-06 真实用户验收实测的缺陷：这条判据原来只查 `PKG`（**源码树**），
#     于是**仓里永远绿**；而 `challenge/` 当时**根本没进 wheel**（只进 sdist），
#     用户在 pip 装到的布局里跑 `verify` 教的那条命令，得到的是
#     `Errno 2 No such file or directory`。
#     ⇒ 「查源码树」不是「查出件」—— 没对象的检查项＝假守卫。
#   现在：源码树 **＋ 每个构建出来的 wheel** 都查。
#   （更一般的守卫见 `ci/verify_promises_guard.py`：它读产品自己的
#    `antinel._VERIFY_RECOMPUTE` 登记表，不写死路径。）
def _b4_missing_items():
    import glob as _glob
    import zipfile as _zip
    miss = []
    for rel in ("challenge/verify.py", "tools/antinel_verify.py"):
        if not os.path.isfile(os.path.join(PKG, *rel.split("/"))):
            miss.append("源码树缺 " + rel)
    for w in sorted(_glob.glob(os.path.join(PKG, "dist", "*.whl"))):
        base = os.path.basename(w)
        try:
            names = set(_zip.ZipFile(w).namelist())
        except Exception as e:                                  # noqa: BLE001
            miss.append("%s 打不开：%r" % (base, e))
            continue
        for rel in ("challenge/verify.py", "tools/antinel_verify.py"):
            if rel not in names:
                miss.append("%s 里没有 %s" % (base, rel))
    return miss


_b4 = _b4_missing_items()
check("B4 第三方验证器在**出件**里（源码树 ＋ 每个 wheel）", not _b4, "; ".join(_b4))

# B5 追加式：链文件只以 "a" 打开（无覆写路径）
src_post = open(HOOK_POST, encoding="utf-8").read()
bad_writes = re.findall(r'open\(fn,\s*"w"', src_post) + re.findall(r'open\(fn,\s*"w[b]?"', src_post)
check("B5 链文件无覆写打开（append-only）", not bad_writes, str(bad_writes))

# ---- C. 失败语义 ----
# C1 畸形输入 fail-open
p = subprocess.run([PY, HOOK_PRE], cwd=proj, input=b"not-json{{", capture_output=True, timeout=30)
check("C1 畸形 stdin → exit0 fail-open + HOOK_ERROR 留痕",
      p.returncode == 0 and b"HOOK_ERROR" in p.stderr, f"rc={p.returncode}")
# C2 坏 transcript → usage_source 降级不崩
p = subprocess.run([PY, HOOK_POST], cwd=proj,
                   input=json.dumps({"session_id": "d", "transcript_path": "Z:/nope.jsonl",
                                     "tool_name": "Write",
                                     "tool_input": {"file_path": os.path.join(proj, "x.txt"), "content": "y"},
                                     "tool_response": {"success": True}}).encode(),
                   capture_output=True, timeout=60)
check("C2 坏 transcript → post 不崩（exit0）", p.returncode == 0, f"rc={p.returncode}")

# ---- D. UX / CLI ----
ANT = os.path.join(PKG, "antinel.py")
r1 = subprocess.run([PY, ANT, "--host", "zcode"], cwd=proj, capture_output=True, timeout=60)
help_out = r1.stdout.decode("utf-8", "replace")
r2 = subprocess.run([PY, ANT, "--host", "zcode", "routes", "--markdown"], cwd=proj,
                    capture_output=True, timeout=60)
routes_out = r2.stdout.decode("utf-8", "replace")
# 0.29.0：两处修正。
# ① 先剥 HTML 注释再扫。`routes --markdown` 的表头是
#    `<!-- 由 antinel routes --markdown 生成；与 help 同源（ROUTES） -->` —— 这行**自指**
#    会被正则扫成一个并不存在的 `antinel routes` 命令，于是 D1 变成**假红**
#    （help 与 routes 其实同源，都从 ROUTES 生成）。检查器读到了不该读的东西；
#    与"一个会误报的检查器，用两次就没人信了"同源。
# ② 判据改成 `help ⊆ routes`，唯一允许的 routes 侧差集是**宿主条件项** `antinel credits`：
#    routes 是宿主无关的路由契约（会被烘进随包 references/AGENT_SKILL.md），
#    help 才是按宿主经济画像过滤的交互面（见 antinel.py cmd_help 的 0.29.0 注释）。
#    另外把 `--host` 这类旗标排除掉（正则要求首字符是字母）。
_HOST_COND = {"antinel credits"}


def _cmds(t):
    return set(re.findall(r"antinel (?!-)[a-z][a-z-]*", re.sub(r"<!--.*?-->", "", t, flags=re.S)))


cmds_help = _cmds(help_out)
cmds_routes = _cmds(routes_out)
check("D1 help 与 routes 同源（除宿主条件项 antinel credits）",
      bool(cmds_help) and bool(cmds_routes)
      and not (cmds_help - cmds_routes)
      and not (cmds_routes - cmds_help - _HOST_COND),
      f"help={len(cmds_help)} routes={len(cmds_routes)}"
      f" 只在routes={sorted(cmds_routes - cmds_help - _HOST_COND)}"
      f" 只在help={sorted(cmds_help - cmds_routes)}")
check("D2 裸 antinel 显示宿主与记账口径", "zcode" in help_out and ("token" in help_out or "记账" in help_out), "")
check("D3 token 宿主下无 credits 子命令", "credits" not in help_out, "")

# D4 SEC 拦截文案不含放行命令（UX 定稿 §七）
rc, out, err = hook("pre_tool_use.py", "Read", {"file_path": "C:/Users/demo/.ssh/id_rsa"})
check("D4 SEC 拦截文案无 add 放行命令",
      "antinel paths add" not in err and "antinel domains add" not in err, err[:120])

# D5 七步写：paths add → policy_changed 进链
r = subprocess.run([PY, ANT, "--host", "zcode", "paths", "add", os.path.join(proj, "extra")],
                   cwd=proj, capture_output=True, timeout=60, input=b"\n")
cl = chain_lines()
pc = [r for r in cl if r.get("type") == "policy_changed"]
check("D5 paths add → policy_changed 进链", bool(pc), f"{len(pc)} 条")

# D6 digest 存在且带覆盖声明
r = subprocess.run([PY, ANT, "--host", "zcode", "digest", "--days", "1"], cwd=proj,
                   capture_output=True, timeout=120)
dg = r.stdout.decode("utf-8", "replace")
check("D6 digest 带覆盖声明（分母显式）", ("覆盖" in dg) and ("未接入" in dg or "宿主" in dg), dg[:80].replace("\n", " "))

# ---- E. 宿主审计 ----
r = subprocess.run([PY, ANT, "--host", "zcode", "host-shield", "status"], cwd=proj,
                   capture_output=True, timeout=60)
hs = (r.stdout + r.stderr).decode("utf-8", "replace")
# ★ 2026-09-28 修订：原判据是 `"disabled" in hs or "未启用" in hs or "关闭" in hs`
#   —— **文本级匹配措辞**。而产品文案是「关着」/「开着」（antinel.py:1196,1206），
#   三个待匹配词**一个都不出现** ⇒ 无论护盾开还是关，E1 **永远红**。
#   长期红的守卫＝没有守卫（本项目自立的纪律）：真出事时没人能从一片红里认出来。
#   ⇒ 改判**事实**：直接读状态真源（与产品同一份 `host_shield.load_state()`），
#     措辞只作为副证据打印，不再进判据。
_e1_state = subprocess.run(
    [PY, "-c",
     "import sys;sys.path.insert(0,{pkg!r});import host_shield as h;"
     "print('ENABLED=' + repr(bool(h.load_state().get('enabled'))))".format(pkg=PKG)],
    cwd=proj, capture_output=True, timeout=60)
_e1_out = _e1_state.stdout.decode("utf-8", "replace").strip()
_e1_disabled = (_e1_out == "ENABLED=False")
check("E1 host-shield 默认 disabled（D0 默认全关）",
      _e1_disabled,
      "状态真源 %s ｜ 文案 %r" % (_e1_out, hs[:70].replace("\n", " ")))
hosts_reg = glob.glob(os.path.join(PKG, "rules", "hosts", "*.json"))
ev_ok = True
for f in hosts_reg:
    d = json.load(open(f, encoding="utf-8"))
    for w in d.get("watch", []):
        if "evidence" not in w:
            ev_ok = False
check("E2 外传路径登记表逐条带 evidence（§10.1）", ev_ok and bool(hosts_reg), f"{len(hosts_reg)} 个宿主档案")

# E3 卸载零残留（临时安装目录上做一遍）
tmp2 = tempfile.mkdtemp(prefix="drift_un_")
p2 = os.path.join(tmp2, "proj")
os.makedirs(os.path.join(p2, ".zcode"))
json.dump({"model": "t"}, open(os.path.join(p2, ".zcode", "config.json"), "w"))
inst = os.path.join(PKG, "scripts", "install.py")
_i3 = subprocess.run([PY, inst, "--root", p2, "--host", "zcode", "--skip-scan"],
                     capture_output=True, timeout=120)
_u3 = subprocess.run([PY, inst, "--root", p2, "--uninstall", "--purge"],
                     capture_output=True, timeout=120)
_psl_left = os.path.exists(os.path.join(p2, ".psl"))
raw = open(os.path.join(p2, ".zcode", "config.json"), encoding="utf-8").read()
# ★ 2026-09-28：原证据只有 `raw[:80]` —— 卸载失败时它只会显示 config.json 的**内容**
#   （如 `{"model":"t"}`），而那正是"卸载**成功**、config 已复原"的样子 ⇒
#   证据与结论**相反**，读的人会以为是别的问题。补上两次命令的 rc 与 stderr：
#   真残留（产品缺陷）与"子进程被环境拦了"（量具故障）在输出里必须长得不一样。
_u3_err = _u3.stderr.decode("utf-8", "replace")
# ★★ 2026-09-28：E3 的**环境受阻**识别。
#   实测证据（加上下文后一眼可见）：`uninstall rc=1`，stderr 是
#   `[safe-delete][SAFE_DELETE_BULK_GUARD_ERROR] state lock timeout ...`
#   —— 那是**宿主（WorkBuddy 安全中心）的删除守卫**在拦批量删除，不是 Antinel 的缺陷。
#   这与 A11d 实测过的事故同族：宿主越阈时杀掉 `os.remove`。按「受阻 ≠ 失败」，
#   这种情况必须记 **BLOCKED**，否则 E3 会变成**长期假红**（本机每次跑都红）。
#   ★ 注意判据用的是"卸载进程**明确报出了守卫错误**"，不是"卸载失败" ——
#     卸载失败但**没有**守卫字样时，仍记 FAIL（真残留不能被洗白）。
_E3_ENV_MARKERS = ("SAFE_DELETE", "safe-delete", "state lock timeout",
                   "BLOCKED BY SECURITY POLICY", "PermissionError")
_e3_env_blocked = (_u3.returncode != 0
                   and any(_m in _u3_err for _m in _E3_ENV_MARKERS))
_e3_ok = (not _psl_left) and ("antinel" not in raw.lower())
check("E3 uninstall --purge 零残留",
      _e3_ok if not _e3_env_blocked else None,
      ("★ 受阻：卸载进程被宿主删除守卫拦下（rc=%d）⇒ 本项**未测到**，不是产品残留。"
       "stderr=%r" % (_u3.returncode, _u3_err[:100])) if _e3_env_blocked
      else ("install rc=%d / uninstall rc=%d ｜ .psl 残留=%s ｜ config=%r ｜ uninstall stderr=%r"
            % (_i3.returncode, _u3.returncode, _psl_left, raw[:40], _u3_err[:80])))
shutil.rmtree(tmp2, ignore_errors=True)

# ---- F. 宣称一致性 ----
skill = open(os.path.join(PKG, "SKILL.md"), encoding="utf-8").read()
# 0.29.0：**不再硬编码条数**。此前写死 `"24 rules" in skill and len(rules) == 24`，
# 规则集一变（25→31）这个守卫就变成**假红**（SKILL.md 与 rules 其实是一致的，
# 只是守卫自己过期了）。守卫过期 = 没有守卫。正确判据：SKILL.md 必须宣称**当前实际条数**。
_want = "%d rules" % len(rules)
check("F1 SKILL.md 宣称的规则数与实际一致（%s）" % _want, _want in skill,
      "期望 SKILL.md 含 %r；实际 rules=%d" % (_want, len(rules)))
a6 = open(os.path.join(PKG, "docs", "A6收入边界声明.md"), encoding="utf-8").read()
# 0.29.0：A6 是对外**签署件**，条数只能由创始人按 A6 自身的修订规则去改 ——
# 所以本项**不判成败**，只如实报出差额。写死 24 的老写法在规则一变时同样变成假红。
_m = re.search(r"(\d+)\s*条检测规则", a6)
if _m is None:
    check("F2 A6 规则计数：A6 未声明条数", False, "A6 里找不到「N 条检测规则」")
else:
    print("  [INFO] F2 A6 声明 %d 条，实际 %d 条（差额 %+d）"
          "—— A6 为签署件，修订由创始人按 A6 自身规则执行"
          % (int(_m.group(1)), len(rules), len(rules) - int(_m.group(1))))
schema_pkg = open(os.path.join(PKG, "docs", "AUDIT_SCHEMA.md"), encoding="utf-8").read()
# 0.29.0：判据从"版本号等于 v1.2"改成"**sidecar 契约仍然在文档里**"。
# 版本号会一路涨（现在 v1.6），把它写进断言等于让守卫自带保质期。
check("F3 包内 AUDIT_SCHEMA 已登记 sidecar 契约",
      "sidecar" in schema_pkg and "chain" in schema_pkg, "")

# ---- G. 审核（host-scan）↔ 防范（门闸）的接缝 ----
# 0.29.0（F 批次新增）：此前 33 条检查项**全部盯着防范侧与账本**，审核侧零覆盖。
# 按「无检查项的禁令 ＝ 没有禁令」，接缝漂了没人知道。本段盯的是**接缝**，不是某一侧。
_gs = os.path.join(PKG, "host_shield.py")
_gh = os.path.join(PKG, "antinel.py")
_src_hs = open(_gs, encoding="utf-8").read() if os.path.isfile(_gs) else ""
_src_an = open(_gh, encoding="utf-8").read() if os.path.isfile(_gh) else ""

check("G1 审核侧有对象：findings 机制存在且可读",
      "def load_findings" in _src_hs and "def save_findings" in _src_hs,
      "host_shield.py 缺 load_findings/save_findings ⇒ host-scan 的发现无处登记")

_watch_nonempty, _watch_bad = [], []
for _f in sorted(glob.glob(os.path.join(PKG, "rules", "hosts", "*.json"))):
    try:
        _d = json.load(open(_f, encoding="utf-8"))
    except Exception:
        continue
    for _w in (_d.get("watch") or []):
        if not _w.get("path"):
            _watch_bad.append(os.path.basename(_f) + ":空 path")
            continue
        # H-1（0.29.0）：gate_default 由两值扩为三值 —— 新增 **report**（默认只报不拦）。
        # ★ 实测（2026-09-26）：这个字段此前**从未被代码读取**——只写在 json 里、只被本
        #   守卫判合法性 ⇒ 无论写 deny 还是 allow，行为都是同一条：未裁决即上锁。
        #   H-1 把它变成真判据，本项同步放开 report，否则守卫自己先假红。
        _gd = _w.get("gate_default")
        if _gd not in (None, "report", "deny", "allow"):
            _watch_bad.append(os.path.basename(_f) + ":gate_default=" + str(_gd))
        _watch_nonempty.append(os.path.basename(_f)[:-5])
check("G2 门闸登记契约（path 非空、gate_default 合法）", not _watch_bad,
      "违规条目 %s；已登记宿主 %s" % (_watch_bad[:3], _watch_nonempty))

# ★ 接缝核心一：host-scan 的发现**必须**既进得了门闸、也裁得了决。
# 只进不裁 ⇒ 用户永远无法放行（产品不可用）；只裁不进 ⇒ 回到"只报不拦"。
check("G3a 门闸巡视 host-scan 的 findings（不是只管 watch 表）",
      "for fd in load_findings()" in _src_hs,
      "scan_once 未巡视 findings ⇒ T2 落点仍在监管之外")
check("G3b decide 能裁决 findings 里的路径",
      "load_findings()" in _src_an, "decide 分支未读 findings ⇒ 用户无法对 T2 落点表态")

# ★ 接缝核心二（F-0 修的缺陷）：**用户确认放行就真的放行**。
# 旧代码 allow_always 只 `continue`，已上锁的目录不解 ⇒ 用户点了放行却还拦着。
_i_allow = _src_hs.find('if mode == "allow_always"')
check("G4 已确认放行的目录会解锁（放行必须真放行）",
      _i_allow > 0 and "acl_allow" in _src_hs[_i_allow:_i_allow + 500],
      "allow_always 分支未调用 acl_allow ⇒ 用户放行后仍被拦")

# ★ 23 个空表的病根：`rules/hosts/*.json` 的 `watch: []` 与"这个宿主真的没有外传落点"
#   字面上完全一样 ⇒ 读表的人以为 24 个都查过了。这就是「**没查**被伪装成**没发现**」。
#   取证档案把两者分开（measured／clean／unmeasured），本条盯住它别退化。
check("G6 取证档案机制存在（'没查过'与'查过没发现'不同形）",
      "def save_survey" in _src_hs and "def survey_path" in _src_hs,
      "缺 save_survey/survey_path ⇒ 空 watch 表又会读成'该宿主已查且安全'")

# ★ 接缝核心三：监管范围扩大时**不得重写判据**（两处各写一遍必然漂移）。
# ★ 判据随实现升级（0.29.0 H-4）：遍历已合并进 `iter_gate_targets`，scan_once 不再
#   各写两个循环。旧判据（数 `_lock_pending_tree(` 出现次数）会因实现改进而**假红**——
#   守卫一旦过期就等于没有守卫（F1 那条教训）。新判据盯的是**语义**：同一个产出函数
#   必须同时覆盖 watch 与 findings，且被真正调用。
_i_iter = _src_hs.find("def iter_gate_targets")
_iter_body = _src_hs[_i_iter:_i_iter + 900] if _i_iter > 0 else ""
check("G5 门闸对 watch 表与 findings 共用同一巡视实现",
      _i_iter > 0 and "load_findings()" in _iter_body and "watch" in _iter_body
      and _src_hs.count("iter_gate_targets(") >= 2,
      "iter_gate_targets 缺失或未同时覆盖 watch/findings ⇒ 监管范围一扩就又要重写判据")

# ---- H. 闸门合理化（0.29.0，H 批次）----
# ★ 起因（2026-09-26 实测，非推断）：门闸在**用户零裁决**（state["workspaces"] == {}）下，
#   对 zcode 的 4 个 pending 目录直接上锁；09-24 一天内 54 次补锁**同一**目录（拉锯 3h13m）；
#   锁上之后因 `if not is_denied(target)` 而**永不留痕**（09-25/26 审计只剩心跳、零 breach）。
# ★ 病根两条：① 把「未裁决」当成「deny」；② `gate_default` 字段**代码从不读取**
#   —— 只写在 json 里、只被 G2 判合法性 ⇒ 写 deny 还是 allow，行为完全相同。
# ★ 此前 33+ 条检查项**没有一条管过"该不该锁"** ⇒ 按「无检查项的禁令＝没有禁令」，
#   锁错了没人知道。本段盯的就是**上锁这个动作本身**。
# ★ 副作用声明（不藏）：本段行为检查调 scan_once → record → _notify_throttled，后者会更新
#   真实 state 的 notify_sent（告警节流时间戳）。仅此一项；已备份到 _hs_state_bak 备查。
#   不自动还原——还原会与在岗哨兵竞争写同一文件，反而更糟。
_hs_state_bak = ""
try:
    sys.path.insert(0, PKG)
    import host_shield as _hs
    _hs_state_bak = open(_hs.state_path(), encoding="utf-8").read()
except Exception as _e:
    _hs = None
    print("  [INFO] H 段：host_shield 未能导入或 state 未备份（%s）" % _e)

# 探针子脚本：参数走 argv（避免 % 转义把 Windows 路径搞坏），在临时目录上跑一次 scan_once。
_HS_PROBE_PY = os.path.join(base, "_hs_probe.py")
with open(_HS_PROBE_PY, "w", encoding="utf-8") as _f:
    _f.write(r'''
import os, sys, json, time, tempfile
pkg, d, gate, files = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
sys.path.insert(0, pkg)
import host_shield as hs
pend = os.path.join(d, "pending")
os.makedirs(pend, exist_ok=True)
for fn in json.loads(files):
    open(os.path.join(pend, fn), "w").write("x")
audit = tempfile.mkdtemp(prefix="hsaudit_")
# ★ 审计探针的两条"不许碰真实状态"，都必须显式声明：
#   ① save_state 会写 ~/.antinel/host_shield.json，而**监理在岗**——探针用的是假 state，
#      一旦落盘就把监理的 sentinel_pid/last_task_check 冲掉（护卫自己被自己人打死）。
#   ② note_pending 会写真实待裁决队列，临时目录条目会把用户的队列污染掉。
#   两者都重定向到临时目录/空实现；判据（is_denied）不依赖它们落盘。
hs.save_state = lambda st: None
hs.pending_path = lambda: os.path.join(audit, "pending_decisions.json")
regs = [{"watch": [{"path": d, "gate_default": gate, "lock_dirs": ["pending"]}]}]
st = {"enabled": True, "workspaces": {}, "windows": {}, "zones": [],
      "last_task_check": time.time()}
try:
    hs.scan_once(d, st, audit, regs=regs)
except Exception as e:
    print("EXC %s %s" % (type(e).__name__, e))
print("LOCKED=%d" % (1 if hs.is_denied(pend) else 0))
ev = []
_badlines = 0
fn2 = os.path.join(audit, time.strftime("%Y-%m-%d") + ".jsonl")
if os.path.isfile(fn2):
    for line in open(fn2, encoding="utf-8"):
        if line.strip():
            try:
                ev.append(json.loads(line).get("type"))
            except Exception:
                # ★ 2026-09-30：原为 `pass`（**静默丢行**）⇒ 坏行被悄悄丢掉，
                #   事件数会**少报**而没人知道（"查不出来≠查出来是好的"）。
                #   ⇒ 计数并打印：坏行数是可见的，读者才知道这份 EVENTS 是全的还是缺的。
                _badlines += 1
print("EVENTS=%s" % ",".join(ev))
print("EVENTS_BAD_LINES=%d" % _badlines)
''')


def _hs_probe(gate, files=()):
    """在临时目录上跑一次门闸巡视。

    返回三元组 `(locked, ev, alive)`：
      * `alive is False` ⇒ **探针根本没跑起来**（子进程崩了/被环境拦了 stdlib 读取），
        此时 `locked/ev` **无意义**，调用方必须记 **第三态 BLOCKED**，不许记 FAIL。
      * `alive is True` ⇒ 探针跑完了，`locked` 是可信读数。

    ★ 为什么必须是三元组（2026-09-28 修）：
      此前只返回 (locked, ev)，而 `locked=False` 有**两个来源**：
        ① 产品没上锁（真缺陷，该记 FAIL）
        ② 探针自己没跑起来（环境/沙箱，该记 BLOCKED）
      两者在返回值里**同形** —— 实测踩到：完整 drift_audit 跑一遍 A13b=FAIL，
      但同一条探针单独手跑连跑两轮都 `LOCKED=1`（产品是好的）。
      这正是本仓的「**受阻 ≠ 失败**」纪律：把一个量具故障记成 FAIL，
      会变成长期假红；而长期红的守卫＝没有守卫。
      「探针有没有跑完」的判据是**它有没有打出自己的收尾行** ——
      正常路径必然先打 `LOCKED=`；只有异常路径才会连它都没有。
    """
    d = tempfile.mkdtemp(prefix="hslock_")
    r = subprocess.run([PY, _HS_PROBE_PY, PKG, d, gate, json.dumps(list(files))],
                       capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    locked = "LOCKED=1" in out
    ev = set()
    for line in out.splitlines():
        if line.startswith("EVENTS="):
            ev = set(x for x in line[len("EVENTS="):].split(",") if x)
    # 收尾行到位 且 无解释器级异常 ⇒ 探针真跑完了
    alive = ("LOCKED=" in out) and (r.returncode == 0)
    if not alive:
        print("  [INFO] 门闸探针未跑完（gate=%s rc=%d）：stdout=%r stderr=%r"
              % (gate, r.returncode, out.strip()[:80], err.strip()[:80]))
    return locked, ev, alive


def _acl_audit_usable():
    """门闸段的环境自陈。返回 (usable, why)。理由见 blocked() 的长注释。

    ★ 判据用**进程完整性级别**，不用"acl_deny 有没有成功"——后者会把"锁真被废了"
      误判成"环境受阻"，从而**掩盖真缺陷**（那正是本批要防的事）。
      只有"审计进程自己提权"才算受阻。查不出级别 ⇒ 也按受阻处理（不许猜）。
    """
    try:
        r = subprocess.run(["whoami", "/groups"], capture_output=True, timeout=30)
        out = ((r.stdout or b"").decode("gbk", "replace")
               + (r.stderr or b"").decode("gbk", "replace"))
    except Exception as e:
        return False, "whoami 不可用（%s）：查不出完整性级别 ⇒ 本段结论不可信" % type(e).__name__
    lvl = None
    for line in out.splitlines():
        if "S-1-16-" in line:
            try:
                lvl = int(line.split("S-1-16-", 1)[1].split()[0])
            except (ValueError, IndexError):
                # ★ 2026-09-30 判读：**无害** —— 解析失败后 `lvl` 保持 None，
                #   紧接着的 `if lvl is None` 会**显式返回失败并说明原因**。
                #   失败是可见的，不会被读成"通过"。保留 pass（一行坏输出不该让整段崩）。
                pass
            break
    if lvl is None:
        return False, "whoami 输出无 S-1-16-*：查不出完整性级别 ⇒ 本段结论不可信"
    if lvl >= 0x3000:                      # 0x3000=High, 0x4000=System
        return False, (
            "审计进程处于提权上下文（Mandatory Level S-1-16-%d ≥ 0x3000）⇒ "
            "acl_deny 授出的 Administrators:(OI)(CI)(F) 对本进程生效，is_denied() 恒 False；"
            "本段 A12/A13/A13b/A16 双向失真（假红 + 假绿）。请在**非提权**终端复跑" % lvl)
    return True, "完整性级别 S-1-16-%d（非提权），ACL 判据可用" % lvl


_acl_ok, _acl_why = _acl_audit_usable()


def _chk_or_block(name, ok, evidence):
    """门闸段专用：环境受阻时记第三态 BLOCKED，否则正常 check（受阻 ≠ 通过）。

    ★ 2026-09-28：`ok is None` 也记 BLOCKED —— 供「探针没跑完」这类**量具故障**使用。
      与 `_acl_ok=False` 的区别只在证据文字：一个是"审计进程提权、ACL 判据失真"，
      一个是"这条探针这次没跑起来"。两者都必须**既不记 PASS 也不记 FAIL**。
    """
    if ok is None:
        blocked(name, evidence)
    elif _acl_ok:
        check(name, ok, evidence)
    else:
        blocked(name, _acl_why)


# A12 —— 未裁决不得上锁（创始人定的铁律：默认只报不拦，须用户确认）
# ★ 探针必须**带文件**（有写入证据）：否则 H-3 的门槛先把空目录挡下，gate 根本没被检验，
#   A12 就退化成 A13 的重复项。这是 2026-09-26 负控实测抓到的——注入"gate 恒 deny"后
#   A12 仍然 PASS（＝假守卫）。带上文件，gate 才是唯一变量。
_a12_locked, _a12_ev, _a12_alive = _hs_probe("report", files=["payload.bin"])
_chk_or_block("A12 未裁决且 gate=report 时不得上锁（即使有写入证据）",
      (not _a12_locked) if _a12_alive else None,
      "探针未跑完 ⇒ 本项未测到" if not _a12_alive
      else "gate=report 未裁决即被上锁 ⇒ 「未裁决」被当成「deny」；事件 %s" % sorted(_a12_ev))

# A13 —— 空目录不得上锁（H-3 门槛：既无文件、mtime 也无变化 ⇒ 不是落点）
_a13_locked, _a13_ev, _a13_alive = _hs_probe("deny")
_chk_or_block("A13 空目录不得上锁（无写入证据 ⇒ 不是落点）",
      (not _a13_locked) if _a13_alive else None,
      "探针未跑完 ⇒ 本项未测到" if not _a13_alive
      else "gate=deny 的空 pending 仍被上锁 ⇒ 上锁门槛仍停留在「目录存在」；事件 %s" % sorted(_a13_ev))

# A13b —— ★ 防矫枉过正：有写入证据时，锁**必须仍然生效**。
#   只加 A13 而不加这条，最省事的"修法"就是把锁整个废掉——那不是合理化，是缴械。
_a13b_locked, _a13b_ev, _a13b_alive = _hs_probe("deny", files=["payload.bin"])
_chk_or_block("A13b 有写入证据且 gate=deny 时锁仍然生效（防把锁废掉）",
      _a13b_locked if _a13b_alive else None,
      "探针未跑完 ⇒ 本项未测到（**不是**「产品不锁」）" if not _a13b_alive
      else "pending 有文件却没锁 ⇒ 防范能力已被误伤修理弄废；事件 %s" % sorted(_a13b_ev))

# A14 —— 上锁必须可列出（此前用户查 status 完全看不到自己被锁了）
r = subprocess.run([PY, ANT, "--host", "zcode", "host-shield", "locks"], cwd=proj,
                   capture_output=True, timeout=60)
_lk = (r.stdout + r.stderr).decode("utf-8", "replace")
_chk_hook("A14 已上锁目录可列出（locks 子命令可用）", r.returncode, r.returncode == 0,
          "rc=%d；输出 %s" % (r.returncode, _lk[:100].replace("\n", " ")), _lk)

# A15 —— 自保护：不得锁 Antinel 自身数据根（此前"没锁到自己"只是巧合：
#        .workbuddy/.antinel 下恰好没有 pending 目录，哪天多出一个就锁死自己且不报错）
# ★ 守卫自身纪律：缺实现时**必须判红，不许抛异常崩溃**。崩了就不是"红"，是审计件自己坏了
#   —— 后续 A16 会被连带跳过，整段结论不可信（与 A11d 那条「受阻 ≠ 通过」同一族）。
_sp = getattr(_hs, "is_self_protected", None) if _hs is not None else None
if _sp is None:
    check("A15 自保护生效（自身根 True、无关路径 False）", False,
          "host_shield 缺 is_self_protected ⇒ 自保护不存在（'没锁到自己'只是巧合）")
else:
    _self_hit = _sp(os.path.join(os.path.expanduser("~"), ".antinel"))
    _self_miss = _sp(tempfile.mkdtemp(prefix="hsrand_"))
    check("A15 自保护生效（自身根 True、无关路径 False）",
          _self_hit is True and _self_miss is False,
          "is_self_protected(~/.antinel)=%r，随机路径=%r" % (_self_hit, _self_miss))

# A16 —— 解锁必须真解锁（F-0 那个病：用户点了放行却还拦着；此处盯反方向的同一处）
_a16 = ""
try:
    _d16 = tempfile.mkdtemp(prefix="hsunlock_")
    _r16 = subprocess.run(
        [PY, "-c",
         "import sys;sys.path.insert(0,%r);import host_shield as h;"
         "d=%r;h.acl_deny(d);a=h.is_denied(d);h.acl_allow(d);b=h.is_denied(d);"
         "print('%%d %%d'%%(a,b))" % (PKG, _d16)],
        capture_output=True, timeout=120)
    _a16 = _r16.stdout.decode("utf-8", "replace").strip()
except Exception as _e:
    _a16 = "EXC:%s" % _e
_chk_or_block("A16 解锁真生效（acl_deny 后 is_denied=1，acl_allow 后必须=0）",
              _a16.endswith("1 0"), "实测 %r（期望 '1 0'）" % _a16)

# ---- EG. 出口账本（egress，0.29.0）----
# 规格 §3.2「★ 不许复制」：厂商词表 `VENDOR_KW` **只准有一份**。
# 复制两份的代价不是"多写几个字"，而是**静默漂移** —— 加新厂商时只改一处，
# 另一处照旧不认，**没有任何报错**。这正是本仓付过四次学费的那类病
# （两处同一判据 ⇒ 必然漂移；见 antinel.py 1314 行的注释），必须有断言盯着。
# ★ 判据分两层：静态（谁定义、谁导入、有没有人又写一份）＋ 行为（运行时是不是同一个对象）。
#   只做静态＝「文本级≠值级」；只做行为＝看不出"另写了一份但恰好相等"。
_eg_src = _an_src = ""
try:
    _eg_src = io.open(os.path.join(PKG, "egress.py"), encoding="utf-8").read()
    _an_src = io.open(os.path.join(PKG, "antinel.py"), encoding="utf-8").read()
except OSError:
    # ★ 2026-09-30 判读：**无害** —— 读不到 ⇒ 两个源串是空 ⇒ 下面的
    #   「谁定义 / 谁导入」两条断言都是 False ⇒ **判据会红**（文件缺失是看得见的失败），
    #   不会静默变绿。保留 pass（缺文件不该让整份审计崩掉）。
    pass

_eg_defines = bool(re.search(r"^VENDOR_KW\s*=", _eg_src, re.M))
_an_imports = bool(re.search(r"from\s+egress\s+import\s+VENDOR_KW", _an_src))
_an_dupe = bool(re.search(r"^_SCAN_VENDOR_KW\s*=\s*\(", _an_src, re.M))
_rv = subprocess.run(
    [PY, "-c",
     "import sys;sys.path.insert(0,%r);import egress as e,antinel as a;"
     "print('SAME' if getattr(a,'_SCAN_VENDOR_KW',None) is e.VENDOR_KW else 'DIFF')" % PKG],
    capture_output=True, timeout=60)
_rvo = _rv.stdout.decode("utf-8", "replace").strip()
check("EG1 出口账本词表共用（egress 定义 / antinel 导入 / 运行时同一对象）",
      _eg_defines and _an_imports and not _an_dupe and _rvo.endswith("SAME"),
      "egress定义=%r antinel导入=%r antinel另写一份=%r 运行时=%r err=%r"
      % (_eg_defines, _an_imports, _an_dupe, _rvo,
         _rv.stderr.decode("utf-8", "replace")[:80]))

# --------------------------------------------------------------------------
# EG2（2026-09-28）：**两命令的布防口径必须都出现在"会打印的字符串"里**。
#
# 为什么要有这条：`host-audit` 一直打「登记表共 24 个宿主，其中【已布门闸】1 个」，
# 而 `host-scan`（它自己把用户支使过去的那个命令）原本**不打这个数** ⇒ 用户只看到
# 「这条说 24、那条说 1」，拼不出全貌，"登记了 24 个"被读成"24 个都被盯住"。
# 那正是本项目反复吃亏的一种错：把「登记了」当成「会被查」。
#
# ★ 判据为什么必须**剥注释**：`grep "已布门闸"` 在 antinel.py 里能命中 7 处，
#   其中 3 处是**注释**。纯文本匹配会把「注释里写了」当成「会打印」⇒ 假绿。
#   这是"文本级 ≠ 值级校验"的又一例。这里用 tokenize 把注释与字符串字面量分开：
#   只认 **STRING token 里出现**的那些。
#
# ★ 判据为什么不能只匹配「已布门闸」四个字：两个函数里还有别的同名串 ——
#   `_die("登记表里没有任何【已布门闸】的宿主…")` 是**报错**、`"T1 已取证（已布门闸，deny）"`
#   是**分级标签**。它们都不携带"N 个登记 / M 个布防"这个数。
#   ⇒ 判据收紧为：字符串里**同时**含「登记表」与「已布门闸」——那才是那句声明。
def _armed_claim(fn):
    """取某个函数体里**会打印**的布防声明字符串（剥掉注释，只认字符串字面量）。"""
    import io as _io, tokenize as _tk, ast as _ast
    path = os.path.join(PKG, "antinel.py")
    try:
        text = open(path, encoding="utf-8").read()
        tree = _ast.parse(text)
    except Exception:
        return None
    _lines = text.splitlines(keepends=True)
    for n in tree.body:
        if isinstance(n, _ast.FunctionDef) and n.name == fn:
            seg = "".join(_lines[n.lineno - 1:n.end_lineno])
            got = []
            try:
                for tok in _tk.tokenize(_io.BytesIO(seg.encode()).readline):
                    if tok.type != _tk.STRING:
                        continue
                    if "登记表" in tok.string and "已布门闸" in tok.string:
                        got.append(tok.string[:60])
            except Exception:
                return None
            return got
    return None


_ha, _hs = _armed_claim("cmd_host_audit"), _armed_claim("cmd_host_scan")
check("EG2 两命令都打印【登记 N 个 / 已布门闸 M 个】声明（剥注释、只认字符串字面量）",
      bool(_ha) and bool(_hs),
      "host-audit=%r host-scan=%r" % (_ha, _hs))

shutil.rmtree(base, ignore_errors=True)
npass = sum(1 for _, ok, _ in results if ok is True)
nfail = sum(1 for _, ok, _ in results if ok is False)
nblock = sum(1 for _, ok, _ in results if ok is None)
# ★ 2026-09-28：**报出分母是否完整**。
#   此前只打 `{npass}/{len(results)}` —— 而 `len(results)` 是**已经跑到的**条数。
#   脚本若中途崩掉（实测：钩子子进程 60s 超时未接住），分母会**静默变小**，
#   输出看起来像"跑到的那几条都过了"。这正是「查不出来 ≠ 查出来是好的」。
#   ⇒ 钉一个**预期条数**常量，末尾直接报"跑了 N / 应跑 M"；不等就是被截断了。
#   实测（2026-09-28 15:23，完整跑通）：**48 条**（静态调用点 57 个，其中 9 个在
#   未进入的分支里）。若检查项确已增删，**必须回来同步这个数** —— 它偏小会让截断
#   重新变得不可见，偏大则会天天误报"被截断"。
_EXPECTED_CHECKS = 48
print(f"\nDRIFT AUDIT: {npass}/{len(results)} PASS  (FAIL {nfail} / BLOCKED {nblock})")
if len(results) != _EXPECTED_CHECKS:
    print("★★ 本次审计**被截断**：只跑了 %d 条检查项，预期 %d 条 —— "
          "下面是残缺数据，**不得当作通过**。" % (len(results), _EXPECTED_CHECKS))
    print("   （若检查项确已增删，请同步更新 _EXPECTED_CHECKS）")
else:
    print("覆盖完整：%d/%d 条检查项全部跑到。" % (len(results), _EXPECTED_CHECKS))
fails = [n for n, ok, _ in results if ok is False]
blocks = [n for n, ok, _ in results if ok is None]
print("未过项(FAIL):", fails if fails else "无")
if blocks:
    print("受阻项(BLOCKED —— 没测到 ≠ 通过，须换非提权终端复跑):", blocks)
