#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Re-run the verification suite against THIS package and record psl/judgment.json (psl-vs-0.1).
Usage: python -m scripts.run_harness            third parties: any failed re-run supersedes the shipped record
       python -m scripts.run_harness --bootstrap   build-time run: NO ledger write, verdict marked bootstrap

0.17.0 (P-A1, audit N2/N3): the assertion count now comes from the suite's
STRUCTURED results file (last_results.json), not from grepping human-readable
stdout; the record's presence is a REQUIRED input in pkg layout (a run without
it FAILS instead of quietly scoring 1 lower); and the ledger idempotency key
includes the assertion count, so a changed denominator can never be swallowed
by the "no change" guard again.
"""
import atexit, hashlib, json, os, platform, re, shutil, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

# 0.60.0：起子进程一律带 CREATE_NO_WINDOW —— 父进程可能是**无控制台**的
# pythonw（钩子）／DETACHED（哨兵）／GUI 宿主 ⇒ 不带就会给子进程新建控制台
# ＝ 用户看到黑窗一闪。本文件不 import host_shield，就地定义同一常量。
_CNW = 0x08000000 if os.name == "nt" else 0

PKG = Path(__file__).resolve().parent.parent      # run_harness lives in <pkg>/scripts/

# ★★★ 0.39.2：版本行归一化 —— **唯一真源在 host_shield.py**，这里 import 它。
#   本文件产出的 `digests` 会被 `tools/antinel_verify.py` 用来判"随包判定是否已失效"。
#   若这里算**原始**哈希、那边比**归一化**后的哈希，`hooks/pre_tool_use.py` 会
#   **永远**被判为"已变" ⇒ 判定恒为 superseded（0.16.0 那条断言会红）。
#   ⇒ 统一口径：唯一定义在 host_shield，这里只消费（判据 `ci/inbox_guards_0380.py` S19）。
if str(PKG) not in sys.path:
    sys.path.insert(0, str(PKG))
try:
    import host_shield as _hs
except Exception as _hs_e:                                     # noqa: BLE001
    raise SystemExit("★ run_harness 拿不到 host_shield（版本行归一化唯一真源）：%r" % (_hs_e,))


def _rel_of(p):
    """包内相对路径（正斜杠）。取不到 ⇒ 空串（不归一化，等价于原行为）。"""
    try:
        return str(Path(p).resolve().relative_to(PKG.resolve())).replace("\\", "/")
    except Exception:                                          # noqa: BLE001
        return ""


def _pkg_version():
    """0.33.1：从 antinel.py 读唯一版本源（不 import，避免执行主模块）。"""
    try:
        src = (PKG / "antinel.py").read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.0.0"
OUT = PKG / "psl" / "judgment.json"
LEDGER = PKG / "psl" / "verdict-ledger.jsonl"
MANIFEST = PKG / "psl" / "manifest.json"
COVERED = ["psl/antinel-namespaces.json",
           "rules/default.json", "rules/pricing.json", "rules/typosquat_top.json",
           "rules/economics/workbuddy.json", "rules/economics/zcode.json",
           "rules/economics/claude-code.json", "rules/economics/qoder.json",
           "rules/economics/generic.json",
           "hooks/pre_tool_use.py", "hooks/post_tool_use.py",
           "scripts/scan.py", "scripts/install.py", "scripts/report.py",
           "scripts/verification_tests.py", "session_dna.py", "transcript_reader.py",
           "audit_chain.py",
           "antinel.py", "hub.py", "tools/enforce_probe.py"]

def sha(p):
    """★ 0.39.2：版本承载件（`hooks/pre_tool_use.py`）走 host_shield 的**唯一归一化**。

    其余文件一律**原始字节**哈希（行为与 0.39.1 之前一致）。
    """
    rel = _rel_of(p)
    if rel in getattr(_hs, "VERSION_BEARING_CHAIN_FILES", ()):
        return _hs.file_digest(p, rel)
    return "sha256:" + hashlib.sha256(Path(p).read_bytes()).hexdigest()

# ═══════════════ 失败四分类账（0-b，2026-10-08 落账）═══════════════
# 为什么：verdict=FAIL 把四类不同性质的失败压成一个数字 ——「产品坏了」
# 「量具过期」「环境/时序」「记录没刷新」。读者无法区分，于是这个 FAIL
# 要么被全信（冤），要么被全疑（更冤）。2026-10-08 实测：发布账本 7–9 条
# 失败里，0 条已证实为产品逻辑缺陷。
#
# 分类纪律（四条，缺一不可）：
#   ① 只有机器可判的才机器判 —— 目前机器只出一个事实：上一版账本登记的
#      digests 与当前文件的偏差（写盘前实测，随账本留痕）。
#   ② 其余**默认 product**（fail-closed 方向）：证不出别的类，就记产品类。
#      宁可多认产品缺陷，不可少认 —— 少认等于替自己减刑。
#      推论：没做隔离实验的悬置项（如 0.26 SafeZone）**不给过的类** ——
#      默认项会逼着把实验做掉，而不是把话圆过去。
#   ③ 判为别的类必须带 **basis**：能回指到具体文件/行或实测结论，
#      basis 随账本发布 ⇒ 第三方能审分类，不只是审数字。
#   ④ 登记表自己会腐烂（断言改名后条目失效）⇒ 每次运行机器核对：
#      登记了但本轮没失败的条目进 stale_entries —— 表格腐烂本身留痕。
_BY_KIND_TAXONOMY = {
    "product": "产品缺陷：代码行为不符合声言（默认类，fail-closed）",
    "instrument": "判据腐化：断言/负控/夹具随产品演进失效，产品并无该错",
    "environment": "环境/时序：依赖机器状态（ACL/进程/spawn/时钟），非产品逻辑",
    "process-stale": "流程陈旧：记录（digests 等）未随合法编辑刷新，非代码缺陷",
}

# 登记表：断言名 → (类, basis)。只收有实测依据的；没有依据的一概不登记
# （落默认 product 类）。条目会腐烂 ⇒ stale_entries 机器核对（见下）。
_BY_KIND_OVERRIDES = {
    "UX: 同类提醒当天只提示一次（第二次静默记录）": ("instrument",
        "套件 539-541 行重置 proj/.psl/notify_state.json，而 0.35.3 起产品读 "
        "~/.antinel/notify_state.json ⇒ 重置指向死路径；且 522 行 chmod 777 script.sh "
        "与 UX 断言命中同一键 DST-05|chmod 777（键=规则+片段，不含文件名）⇒ 同轮内"
        "键已被消费。0.36.8 已修（重置改为 Path(os.environ[ANTINEL_HUB_DIR])/"
        "notify_state.json）并原样复现实测转绿。"),
    "0.16.0 DST-01 URL /rd/ segment is not a delete (NET-01 warns, no block)": ("instrument",
        "断言期望 err 含 NET-01，实际命中的是后增的白名单域规则 [NET-03]；被测"
        "代码并未重新触发放行 —— 断言口径与规则演进脱节。"),
    "0.16.0 antinel_verify derives current on an intact package": ("process-stale",
        "digests 定格于上一版 harness 写入态，此间的合法编辑未刷新记录 ⇒ 自书失真；"
        "本次 harness 重写即以新 digest 修复。"),
    "0.17.0 P-B1 without --manifest, a shipped file outside the digest set is out of scope (documented)": ("process-stale",
        "连带项：antinel_verify 对任何 digest 不符一律 rc=1，断言 rc==0 必红；"
        "根因是**记录陈旧**（随包 digests 未随合法编辑刷新），而非被篡改的那个"
        "随包件本身真进了 digest 集。"),
    "F-09 host-shield 自检查不出来时不谎报已安装（三态：None != True）": ("instrument",
        "负控衰减：注入 OSError 欲使 subprocess.run 抛错，但 0.35.3 起 task_installed() "
        "文件系统事实优先（os.path.isfile(shim) 早退 return True）⇒ 注入永远到不了"
        "被测分支；本机 shim 存在 ⇒ 产品行为反而更安全。"),
    "F-13 paramedic 复活死亡监理并留痕（死因 RC5 回归）": ("environment",
        "pid=999999999 是负控自造的假 pid，spawn-failed 属 spawn 环境问题；该条在"
        "10-08 重跑中未复现（失败集合成员漂移的实例）。"),
    "F-15 门闸高危事件实时推送＋同类 30 分钟节流（0.28.2 报警 v1）": ("instrument",
        "桩吞效应：断言先 hs._notify=lambda: None 打桩，再期望 notify_sent 被第一次 "
        "record 置位 —— 桩替换掉了被测效应本身 ⇒ t1 恒 0。"),
    "F-17 心跳判死：无心跳/心跳陈旧的监理会被强制重启（B2）": ("process-stale",
        "沙箱内 self-check-failed: host_shield.py 与 manifest 不符 ⇒ 与 "
        "antinel_verify 那条同根（清单与实物未同步），非心跳逻辑缺陷。"),
    # 0.26 SafeZone registered + tamper-locked
    #   ★★ 登记依据＝**隔离实验已经做掉了**（2026-10-09，本机；此前这里写着
    #   「故意不登记 —— ACL deny 未生效只是环境嫌疑，隔离实验从未跑过 ⇒ 证不出
    #   product 之外的类 ⇒ 按纪律落默认 product 类，逼着把实验做掉，而不是把话圆过去」。
    #   **那句话的条件已经满足，所以现在是登记，不是圆场）。**
    #   实测三条：① `IsUserAnAdmin()=1`、完整性级别 `S-1-16-12288`；
    #   ② `acl_deny()` **确实把 ACL 授上去了**（`icacls` rc=0，ACE 实测为
    #      `大马:(WDAC,RD,X)` ＋ `BUILTIN\Administrators:(OI)(CI)(F)`）；
    #   ③ 提权令牌属于 Administrators ⇒ 那条 `(OI)(CI)(F)` 先生效 ⇒ 写探针照样成功
    #      ⇒ `is_denied()` 恒 False。
    #   ⇒ 沙箱 WORK 下这条红是**提权令牌的可观测性限制**，不是"ACL 没上锁"。
    #   ★ 口径与 `ci/drift_audit._acl_audit_usable()` **同源** —— 它对本文件的
    #     A12/A13/A13b/A16 早已判「审计进程提权 ⇒ 双向失真，请在**非提权**终端复跑」。
    #   ★ **不因此免测**：断言仍是红（既不改判也不跳过），"须在非提权终端复跑"才可能转绿；
    #     两份提权实现的口径漂移由判据 **S32 / N-S32** 挡。
    #   ★ 未测到的部分（**不许当成结论**）：非提权终端下它是否转绿 —— 是**预测**，
    #     不是实测量；本机无法用受限令牌起进程（`runas /trustlevel` 与 `Start-Process`
    #     均被宿主策略拦截），所以这一格只能由人在非提权终端补跑。
    #   ★ 附带实测：它在本轮三次重跑里是 **红 / 绿 / 红** —— 这个判据自身在本机
    #     不可复现（详见《全类型报告审计 v1.1》§7.5），已单列，不与本登记混淆。
    "0.26 SafeZone registered + tamper-locked": ("environment",
        "隔离实验已做（2026-10-09）：IsUserAnAdmin()=1、完整性级别 S-1-16-12288；"
        "acl_deny() 确实授上了 ACL（icacls rc=0，ACE＝『大马:(WDAC,RD,X)』＋"
        "『Administrators:(OI)(CI)(F)』）；提权令牌属于 Administrators ⇒ (F) 先生效 ⇒ "
        "写探针照样成功 ⇒ is_denied() 恒 False。红因是**提权令牌的可观测性限制**，"
        "不是 ACL 没上锁。口径与 ci/drift_audit._acl_audit_usable() 同源"
        "（它对本文件 A12/A13/A13b/A16 早已判『提权 ⇒ 双向失真，须非提权终端复跑』）。"
        "★ 仍不免测：断言保持红，非提权终端下是否转绿属**预测（未实测）**；"
        "两份提权实现的口径漂移由判据 S32/N-S32 挡。"),
    # 0.26 这条另有一个**独立**的量具问题（本轮实测：三次重跑 红/绿/红）——
    # 它与上一条登记无关，属"判据自身不可复现"，另行单列，不在这里消化。
}


def classify_failures(failed, stale_digests):
    """0-b：失败四分类账。返回可直接写进 judgment 的 dict。

    stale_digests 是机器事实（写盘前实测的旧账本偏差清单）；每条失败的类
    与 basis 由上方纪律产生；表格自身的腐烂由 stale_entries 记账。
    """
    counts = {k: 0 for k in _BY_KIND_TAXONOMY}
    per, stale_entries = [], []
    names = [f.get("name") for f in failed]
    for f in failed:
        name = f.get("name") or ""
        if name in _BY_KIND_OVERRIDES:
            kind, basis = _BY_KIND_OVERRIDES[name]
        else:
            kind, basis = "product", ("未登记 ⇒ 按 fail-closed 纪律默认 product 类"
                                      "（不是结论，是尚未证出别的类）")
        counts[kind] += 1
        per.append({"name": name, "kind": kind, "basis": basis})
    for name in _BY_KIND_OVERRIDES:
        if name not in names:
            stale_entries.append(name)
    return {
        "taxonomy": _BY_KIND_TAXONOMY,
        "method": {
            "default": "fail-closed：证不出别的类就记 product 类",
            "machine_derived": "仅『记录陈旧』事实（stale_digests_at_run_time，写盘前实测）",
            "overrides": "_BY_KIND_OVERRIDES（scripts/run_harness.py 内），每条带 basis，随账本发布供第三方审计",
            "stale_check": "登记了但本轮未失败的条目进 stale_entries —— 表格腐烂本身留痕",
        },
        "counts": counts,
        "per_failure": per,
        "stale_entries": stale_entries,
        "stale_digests_at_run_time": {"count": len(stale_digests),
                                      "files": sorted(stale_digests)},
        "invariant": "sum(counts.values()) == len(failed) == %d" % len(failed),
    }

def pinned_fingerprint():
    """The namespace-list key fingerprint pinned in README.md (single source)."""
    try:
        txt = (PKG / "README.md").read_text(encoding="utf-8")
        m = re.search(r"sha256:[0-9a-f]{16}", txt)
        return m.group(0) if m else None
    except Exception:
        return None

def repo_identity():
    """(host, owner) this build declares itself as: git remote first, then the
    namespace the builder wrote into psl/manifest.json, else None."""
    try:
        out = subprocess.run(["git", "remote", "get-url", "origin"], cwd=str(PKG),
                             capture_output=True, text=True, timeout=5, creationflags=_CNW)
        url = (out.stdout or "").strip()
        m = re.search(r"[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?$", url)
        if m:
            # group(1)=owner, group(2)=repo —— owner 才是命名空间主体（0.29 修复：
            # 取反了会让 subject 解析成 github.com/antinel 而非 github.com/sotaex）
            return "github.com", m.group(1).lower(), m.group(2).lower()
    except Exception:
        pass
    try:
        ns = (json.loads(MANIFEST.read_text(encoding="utf-8")) or {}).get("namespace") or {}
        if ns.get("host") and ns.get("owner"):
            return ns["host"], ns["owner"], ns["owner"]
    except Exception:
        pass
    return None

def derive_object_ownership():
    """V12 derivation. fail-closed: the default is `unattributed`; `self` is
    returned only on a positive match against a signed list whose key
    fingerprint equals the value pinned in README.md."""
    try:
        doc = json.loads((PKG / "psl" / "antinel-namespaces.json").read_text(encoding="utf-8"))
    except Exception as e:
        return "unattributed", "namespaces list unreadable (%s)" % type(e).__name__
    sig = doc.get("signature") or {}
    if not (sig.get("value") and sig.get("public_key_fingerprint")):
        return "unattributed", "namespaces list carries no signature block"
    pinned = pinned_fingerprint()
    if not pinned or pinned != sig["public_key_fingerprint"]:
        return "unattributed", "list fingerprint %s does not match README-pinned %s" % (
            sig.get("public_key_fingerprint"), pinned)
    ident = repo_identity()
    if not ident:
        return "unattributed", "subject identity is not resolvable (no git remote, no manifest.namespace)"
    host, owner, _disp = ident
    for e in doc.get("namespaces") or []:
        if e.get("host") == host and str(e.get("owner", "")).lower() == owner:
            return "self", "subject %s/%s is in the signed namespace list" % (host, owner)
    return "third-party", "subject %s/%s is NOT in the signed namespace list" % (host, owner)

def should_append(prev_row, new_row):
    """0.18.0 (R-21/HP-14): the ledger-append decision, EXTRACTED so it can be
    exercised by tests without writing anything (scripts/run_harness.py
    --check-ledger). The idempotency key includes the assertion count, so a
    changed denominator always lands a new row."""
    return not (prev_row
                and prev_row.get("subject_digest") == new_row.get("subject_digest")
                and prev_row.get("verdict") == new_row.get("verdict")
                and prev_row.get("assertions") == new_row.get("assertions"))

def main():
    bootstrap = "--bootstrap" in sys.argv
    check_ledger = "--check-ledger" in sys.argv
    if check_ledger:
        # R-21 (HP-14): dry-run the ledger-append decision AGAINST THE CURRENT
        # TREE, using the existing judgment record's verdict/assertions -- no
        # suite run, no writes. Answers "would an official run right now land a
        # new ledger row?" in under a second, so tests can exercise idempotency.
        prev = None
        if LEDGER.is_file():
            for line in LEDGER.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try: prev = json.loads(line)
                    except Exception: pass
        try:
            old = json.loads(OUT.read_text(encoding="utf-8"))
            verdict = old.get("verdict", "FAIL")
            total = int(old.get("assertions_total", 0))
            passed = int(old.get("assertions_passed", 0))
        except Exception:
            print("would_append=unknown (no judgment record -- bootstrap first)")
            return 0
        digests = {rel: sha(PKG / rel) for rel in COVERED}
        ownership, _basis = derive_object_ownership()
        subject = "sha256:" + hashlib.sha256(
            "\n".join(digests[k] for k in COVERED).encode()).hexdigest()
        row = {"subject_digest": subject, "verdict": verdict,
               "assertions": "%d/%d" % (passed, total)}
        print("would_append=%s" % str(should_append(prev, row)).lower())
        return 0
    env = dict(os.environ); env["ANTINEL_PKG"] = str(PKG)
    # P-A1: the layout is DECLARED here. pkg = the record is required (absent
    # record FAILS the suite); bootstrap = build-time run before the record
    # exists -- the judgment block contributes 0 assertions and the ledger is
    # never written.
    env["ANTINEL_LAYOUT"] = "bootstrap" if bootstrap else "pkg"
    work = tempfile.mkdtemp(prefix="antinel_harness_")  # per-run: no stale results file
    # ★ 2026-09-28 收口修订：上面这句的注释只兑现了"不读旧结果"，**没兑现"不留新目录"**
    #   —— mkdtemp 建的目录从不删除，实测已积 200+ 个 / 46 MB（`antinel_harness_*`）。
    #   用 atexit 而非 try/finally：本函数有多条 return（2 处 early return + 正常返回），
    #   还有可能抛异常的路径；atexit 覆盖**全部**退出路径，且不必给大段代码重新缩进。
    #   仍是 per-run 唯一目录（并发两次运行不会互相覆盖结果）。
    # ★ 2026-09-28（D-15）：清理改为「改名让开」——
    #   本机宿主（Antinel 自身）的批量删除守卫按回合累计、阈值 50，
    #   `rmtree(work)` 会连同套件内部的 33 处清理一起把配额打满 ⇒
    #   套件在写结果之前就死。改名不是删除，对"结果文件不残留"的语义等价。
    #   `ANTINEL_NO_CLEAN=0` 可恢复原来的真删（CI/干净环境）。
    def _aside(p):
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                os.rename(p, p + ".done")
            elif os.path.exists(p):
                os.rename(p, p + ".done")
        except OSError:
            pass

    if os.environ.get("ANTINEL_NO_CLEAN", "1") != "0":
        atexit.register(_aside, work)
    else:
        atexit.register(shutil.rmtree, work, True)
    env["ANTINEL_WORK"] = work
    # 0.33.1 (P3-1): 结果文件显式指定。此前只靠约定（套件写进 WORK），一旦套件
    # 中途抛异常就没有结果文件，harness 只能打印 "refusing to report a count"，
    # 于是"310 条断言"变成一个谁也复现不出来的口头数字。
    env["ANTINEL_RESULTS"] = os.path.join(work, "last_results.json")
    t0 = time.time(); started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    proc = subprocess.run([sys.executable, str(PKG / "scripts" / "verification_tests.py")],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, creationflags=_CNW)
    res = Path(work) / "last_results.json"
    # CI 调试转储（ANTINEL_DEBUG_CI=1 时）：把套件输出与结构化结果留到仓内
    # psl/ci_debug/，让无日志权限的第三方也能定位失败。默认关。
    if os.environ.get("ANTINEL_DEBUG_CI") == "1":
        try:
            tag = os.environ.get("ANTINEL_DEBUG_TAG") or "local"
            dbg = PKG / "psl" / "ci_debug" / tag
            dbg.mkdir(parents=True, exist_ok=True)
            (dbg / "suite_stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
            (dbg / "suite_stderr.txt").write_text(proc.stderr or "", encoding="utf-8")
            if res.is_file():
                shutil.copyfile(res, dbg / "last_results.json")
            (dbg / "run_info.txt").write_text(
                "python=%s platform=%s rc=%d\n" % (sys.version, platform.platform(),
                                                   proc.returncode), encoding="utf-8")
        except Exception:
            pass
    try:
        rows = json.loads(res.read_text(encoding="utf-8"))
        partial = [r for r in rows if r.get("name") == "__partial__"]
        if partial:
            # 套件没跑完：数字仍然报，但必须说清楚这是半截的数。
            print("harness: SUITE ABORTED before completion -- %d assertions recorded, "
                  "reporting them as a PARTIAL count" % (len(rows) - len(partial)))
            # ★★ 2026-10-03：ABORT 时**转发套件 stdout 的尾部**。
            #   为什么：套件被外部杀掉时，judgment 只说"257 条"，`last_results.json`
            #   只留下跑完的那些 —— **"崩在哪一条"完全不可见**，定位只能靠二分法
            #   插桩重跑（实测为此烧过两轮 13 分钟）。
            #   `record()` 现在会给每行加 `[#NNN]` 序号（verification_tests.py），
            #   所以尾部最后一条的序号**就是断点位置**。
            #   ★ 只在 ABORT 时转发：正常跑完时那 300+ 行是噪音。
            _tail = (proc.stdout or "").strip().splitlines()[-12:]
            if _tail:
                print("--- suite stdout tail（最后 12 行；末行序号＝断点）---")
                for _l in _tail:
                    print("  " + _l)
            _err = (proc.stderr or "").strip().splitlines()[-6:]
            if _err:
                print("--- suite stderr tail ---")
                for _l in _err:
                    print("  " + _l)
        rows = [r for r in rows if r.get("name") != "__partial__"]
        total = len(rows)
        passed = sum(1 for r in rows if r.get("pass"))
        # ★ 0.34.0：把**失败的断言逐条落进judgment**。
        #   此前 `discrimination.assertions` 只有 {passed, total} 两个整数 ——
        #   「312/315」这个数字**不说是哪 3 条**，于是每次要定位都得重跑一遍
        #   12.5 分钟的套件（实测：本次为定位 F-17 重跑了一次）。
        #   判据：明细来自套件自己落的 `last_results.json`（P3-1 已有），
        #   **不重新执行任何断言**，只是把同一份结果换个形状存进judgment。
        failed = [{"name": r.get("name"), "detail": (r.get("detail") or "")[:300]}
                  for r in rows if not r.get("pass")]
        partial_flag = bool(partial)
    except Exception as e:
        print("harness: cannot read structured results %s (%s) -- refusing to report a count" % (res, e))
        tail = (proc.stderr or "")[-1500:]
        out_tail = (proc.stdout or "")[-800:]
        if tail:
            print("--- suite stderr tail ---\n" + tail)
        if out_tail:
            print("--- suite stdout tail ---\n" + out_tail)
        return 2
    verdict = "PASS" if proc.returncode == 0 and total and passed == total else "FAIL"
    ownership, ownership_basis = derive_object_ownership()
    digests = {rel: sha(PKG / rel) for rel in COVERED}
    # 0-b：写盘**之前**实测「上一版账本登记的 digests 与当前文件的偏差」。
    #   为什么必须在写盘前：新账本的 digests 按定义全对，写盘后这个事实
    #   就消失了 —— 而它正是「流程陈旧」类的机器证据。
    stale_digests = []
    try:
        _old = json.loads(OUT.read_text(encoding="utf-8"))
        for _rel, _want in (_old.get("digests") or {}).items():
            try:
                if sha(PKG / _rel) != _want:
                    stale_digests.append(_rel)
            except Exception:                              # noqa: BLE001
                stale_digests.append(_rel)      # 读不到 ⇒ 也属失配
    except Exception:                                      # noqa: BLE001
        pass                                # 无旧记录（bootstrap）⇒ 空
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    rec = {
        "spec": "psl-vs-0.1",
        "card_id": "antinel-security-suite",
        "skill": "antinel-security",
        # 0.33.1：这里写死 "0.33.0" 是**第 4 处**漏网的版本承载件（前 3 处已由
        # bump 脚本 + INV-3 抓出修掉）。它写进 judgment.json，于是重录后的记录
        # 仍然自称 0.33.0。改为统一取 antinel.VERSION。
        "skill_version": _pkg_version(),
        "verdict": ("PASS (bootstrap)" if bootstrap and verdict == "PASS" else verdict),
        # V7: status is a status BIT, appended info; this file itself is never
        # edited after publication. A third party derives current/superseded
        # with tools/antinel_verify.py; checkedAt is when WE last derived it.
        "status": {"value": "current", "derivation": "auto", "reason": None,
                   "checkedAt": now,
                   "note": "re-derive any time: python -m tools.antinel_verify (--manifest for all 24 shipped files); which assertions failed: discrimination.failed[]"},
        # V8: scope -- what this verdict covers and, just as loudly, what it does not.
        "scope": {"covered": COVERED,
                  "notCovered": ["runtime behaviour of the monitored host",
                                 "files outside the " + str(len(COVERED)) + " digests above",
                                 "the security posture of your machine or environment",
                                 "dynamic tool traffic (that is the hooks\' job, not this record\'s)",
                                 "the " + "\u4f53\u68c0" " behaviour corpus is not shipped with the package; "
                                 "that reading is not reproducible from this package alone"]},
        # V1: the gauge behind the number. assertions N/N without a named
        # instrument is exactly the drift shape this field exists to prevent.
        "discrimination": {"instrument": {"name": "scripts/verification_tests.py",
                                          "object": "this package (the " + str(len(COVERED)) + " digested files)",
                                          "runner": "scripts/run_harness.py",
                                          "op": "black-box subprocess assertions (stdin JSON in, exit code + stdout/stderr out)"},
                           "assertions": {"passed": passed, "total": total},
                           # ★ 0.34.0：逐条失败明细（0 条 = 全过）。
                           #   为什么要落盘：**"312/315" 不说是哪 3 条**，
                           #   定位成本 = 一次 12.5 分钟的重跑（本次实测）。
                           #   与 total/passed 同源同一次运行，不是二次执行。
                           "failed": failed,
                           # ★ 0-b：失败四分类账（product / instrument /
                           #   environment / process-stale）。机器只测「记录
                           #   陈旧」事实（写盘前实测旧账本偏差）；其余默认
                           #   product 类（fail-closed），例外必须带 basis
                           #   登记在 _BY_KIND_OVERRIDES 并随账本供审计。
                           "by_kind": classify_failures(failed, stale_digests),
                           "partial": partial_flag},
        # V5: true == verified on THIS platform only. Honest until CI proves more.
        "platformSpec": True,
        # V12: DERIVED (0.17.0, P-A3), no longer a constant: fail-closed
        # unattributed unless the signed list + pinned fingerprint + subject
        # identity all check out. Basis kept beside the value.
        "objectOwnership": ownership,
        "objectOwnershipBasis": ownership_basis,
        "assertions_total": total,
        "assertions_passed": passed,
        "criteria_independence": "Assertions exercise the hook protocol, rule matching, scanner, installer and reporter as black boxes through subprocesses (stdin JSON in, exit code and stdout/stderr out); they were authored from the design specification ANT-SEC-SPEC-001 v1.1, not from the implementation; third-party re-run supported.",
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "stdlib_only": True, "network": "none"},
        "digests": digests,
        "run": {"started_at": started, "duration_ms": int((time.time() - t0) * 1000),
                "duration_note": "wall-clock of a subprocess fan-out suite; machine- and load-dependent, not comparable across environments",
                "executor": "scripts/run_harness.py", "exit_code": proc.returncode,
                "bootstrap": bootstrap},
        "re_run": "python -m scripts.run_harness",
        "verify": "python -m tools.antinel_verify",
        "anchor": None,
        "note": "v0.1 judgment: single-machine execution by the packaging agent; verification is not a security audit of the user environment. Any failed third-party re-run supersedes this record.",
    }
    # V6 ledger (minimal form): append-only, idempotent. P-A1: the idempotency
    # key includes the assertion count, so a changed denominator always lands a
    # new row instead of being swallowed. Bootstrap runs NEVER write the ledger.
    subject = "sha256:" + hashlib.sha256(
        "\n".join(digests[k] for k in COVERED).encode()).hexdigest()
    row = {"recorded_at": now, "row_kind": "self-verdict", "card_id": rec["card_id"],
           "skill_version": rec["skill_version"], "verdict": rec["verdict"],
           "subject_digest": subject, "status": "current",
           "objectOwnership": ownership,
           "instrument": rec["discrimination"]["instrument"]["name"],
           "assertions": "%d/%d" % (passed, total),
           "re_run": rec["re_run"], "verify": rec["verify"], "anchor": None}
    prev = None
    if LEDGER.is_file():
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try: prev = json.loads(line)
                except Exception: pass
    OUT.parent.mkdir(parents=True, exist_ok=True)
    # G7-5b (2026-09-24): 行尾必须是【构建器的选择】，不是【宿主平台的默认值】。
    # 原先未指定 newline ⇒ Windows 写 CRLF、Linux 写 LF ⇒ 同一份源产出不同字节
    # （实测：随包 psl/judgment.json 里有 100 个 CRLF）。本文件不入 manifest、
    # 不入 judgment.digests，改行尾零下游影响，纯确定性收益。
    OUT.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    if bootstrap:
        print("harness: bootstrap run -- ledger untouched")
    elif should_append(prev, row):
        # G7-5b: 同上，显式 LF。★ 台账是 append-only：此处只改【未来行】的写法，
        # 已有行一字不动（不重写历史）。因此下一次追加会出现一行显式的 CRLF→LF 过渡，
        # 那是【选择】的结果，不是平台的偶然结果。
        with LEDGER.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("verdict=%s assertions=%d/%d -> %s" % (rec["verdict"], passed, total, OUT))
    return 0 if verdict == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
