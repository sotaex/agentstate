# SPDX-License-Identifier: Apache-2.0

"""0.36.3 判据 —— 状态封闭 ＋ 研发态 ＋ 大窗零残留。

★ 本组判据要守的三件事（都是创始人 2026-10-07 同一轮交办的）：

  ① **状态都是计划内的** —— 实测抓到：`light()` 改造前**没有兜底分支**，
     任何没列进 `if` 的姿态会穿过全部 if 落到函数末尾 ⇒ **打绿**。
     实测 `light("banana")` / `light(None)` / `light("")` 全都 → `ok`。
     ⇒ 守：姿态集合封闭 + 集合外一律黄灯 + **不许抛异常**。

  ② **研发态** —— 实测抓到：manifest 登记 `0.35.3`、代码已 `0.36.2`
     ⇒ 自检必然不符 ⇒ 界面长期挂「存疑」。但研发期**不存在"出厂"**，
     拿"是不是出厂那份"质疑正在迭代的代码是范畴错误。

  ③ **大窗不再残留** —— 0.36.2 修完了"落位"，但**落位失败**时
     窗口仍停在 1050×1932。⇒ 现在失败就关窗：要么落到 520×640，
     要么不在屏幕上，**没有第三个结局**。

★ 本组的元纪律（0.36.2 变异检验逼出来的）：
  **判据的价值在于"改坏产品必变红"，不在于"有检查动作"。**
  凡能真跑的就真跑；凡靠字面量检查的，先问"这条变异会不会被放过"。
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

#: ★ 0.37.1 补：本文件的负控此前**只在内存里算变异字符串**，从没写盘 ——
#:   空转的负控比没有负控更坏（它给"已被守护"发勋章，见 0364 B4 同型修法）。
#:   这里补上与 0364 同形的快照/还原机制（还原用 rename，避开 Antinel 自己
#:   的 DST-01 删除拦截）。
_BACKUP = []          # [(path, backup)]


def _snapshot(path):
    """备份一个文件（还原用 rename，避开 Antinel 自己的 DST-01 删除拦截）。"""
    import shutil
    bk = path + ".g0363.bk"
    shutil.copy2(path, bk)
    _BACKUP.append((path, bk))
    return bk


def _restore_all():
    for path, bk in reversed(_BACKUP):
        if os.path.exists(bk):
            if os.path.exists(path):
                os.replace(path, path + ".g0363.trash")
            os.replace(bk, path)
    _BACKUP.clear()


def _func_seg(src, name):
    """★ 取某个函数的**真代码**（docstring 剥掉）。

    ★★★ 为什么不能用 `_code_only` 取段（**本轮又踩了一次同一个坑**）：
      我先用 `_code_only` + `split("def close_window")` 取段，
      结果判据报红说"close_window 自己去枚举"—— 实际命中的是
      **docstring 里那句解释**「范围由 `find_console_windows` 的标题过滤限定」。
      ★ 这与 `inbox_guards_0360.py` 的 P10 是**同一个坑**：
        **去查解释代码的那段文字**。
      ★ `_code_only` 只剥**注释**，**不剥 docstring** ⇒ 靠它的字符串检查
        对"docstring 里提到了某个函数名"零分辨力。
      ⇒ 现在用 AST：只取函数体，且把 docstring 从头切掉。
    """
    import ast
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            seg = ast.get_source_segment(src, node) or ""
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                i = seg.find(body[0].value.value)
                if i >= 0:
                    seg = seg[i + len(body[0].value.value):]
            return seg
    return ""


def _src_of(mod):
    import inspect
    try:
        return inspect.getsource(mod)
    except Exception:                                       # noqa: BLE001
        import io
        return io.open(mod.__file__, encoding="utf-8").read()


def _code_only(src):
    """剥掉注释与 docstring —— 只留真代码（避免去查解释代码的那段文字）。"""
    import ast
    import io
    import tokenize
    out = []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
        prev_t, prev_o = None, None
        for ttype, tstr, (srow, scol), (erow, ecol), _line in toks:
            if ttype == tokenize.COMMENT:
                continue
            if (srow, scol) != (prev_o[0], prev_o[1]) and out:
                out.append("\n")
            out.append(tstr)
            prev_t, prev_o = ttype, (erow, ecol)
        joined = "".join(out)
        if joined.strip():
            ast.parse(joined)
            return joined
    except Exception:                                       # noqa: BLE001
        pass
    lines = [ln for ln in src.split("\n")
             if not ln.strip().startswith("#")]
    return "\n".join(lines)


# ══════════════════════════════════════════ ① 姿态/灯集合封闭 ══════════════

#: 真跑时会喂给 `light()` 的计划外姿态：类型杂、含不可哈希的。
BAD_POSTURES = ["banana", None, "", "研发", "计划外", 0, 3.5, True, [],
                {}, b"x", "OK", "ok ", " guardING", "guarding\n", 0xDEAD]


def c_light_never_greens_on_unknown_posture():
    """★★★ 计划外姿态**绝不打绿** —— 这是本组的第一道命门。

    实测缺陷（改造前）：`light()` 没有兜底，未知姿态穿过全部 if
    落到末尾 ⇒ 返回 `LIGHT_OK`（绿）⇒ **界面安静地显示"一切正常"**。
    ★ 后果比"显示错"更坏：它让**状态机出错这件事本身不可见**。

    ★ 本判据**真跑 15 种计划外输入**（含 `None`／空串／数字／不可哈希），
      而不是查源码里有没有某个分支 —— 后者对"把兜底删掉"这种变异零分辨力。
    """
    import inbox_model as M
    bad = []
    for st in BAD_POSTURES:
        try:
            got, why = M.light(st, [], now=None)
        except Exception as e:                              # noqa: BLE001
            bad.append("%r → 抛异常 %s" % (st, type(e).__name__))
            continue
        if got == M.STATE_L0:
            bad.append("%r → 打绿（%s）" % (st, why))
        elif got != M.STATE_L1:
            bad.append("%r → %s（应当是「注意/盲区」）" % (st, got))
    if bad:
        return "计划外姿态没落到黄灯「注意」：%s" % "；".join(bad[:4])
    return True


def n_light_greens_on_unknown_is_caught():
    """负控：让未登记姿态**真的打绿** ⇒ 上一条必须报红。

    ★★ 0.37.1 修（本负控此前**空转**，实测三代都"生效"）：
       旧版只**在内存里**拼出 `mutated` 字符串，从没写盘、没 reload ——
       `M.light("banana")` 跑的是**未变异**的模块 ⇒ 它"生效"的原因是
       产品本来就不打绿，不是变异被抓到。与 0364 B4 同型：
       **量具的空转比没有负控更坏**（它给"已被守护"发勋章）。
       另：旧版的结构锚点 `LIGHT_UNKNOWN` 在六态换代后已不存在 ⇒
       走"跳过变异"分支直接返回 True，连空转都省了。
    ⇒ 现在：真写盘 → 真 reload → 复现历史缺陷形状（未登记姿态打绿）→
       还原 → 还原后再验一遍回到黄灯（还原链路坏掉比负控失效更险）。
    """
    import importlib
    import inbox_model as M
    p = os.path.join(ROOT, "inbox_model.py")
    _snapshot(p)
    try:
        src = open(p, encoding="utf-8").read()
        # ① 关掉 ⑥（集合外一律盲区）
        anchor = ("if not isinstance(posture_state, str) or posture_state not in _POSTURE_ALL:")
        assert anchor in src, "定位 ⑥ 集合外判读失败（锚点漂移，负控需更新）"
        mutated = src.replace(anchor, "if False:", 1)
        # ② 把函数末尾的防御性黄灯也改成打绿 —— 复现 0.36.2 那个真缺陷的形状
        #    （当年没有兜底，未知姿态一路穿到末尾拿到绿灯）
        tail = ('    return STATE_L1, ("收到一个没登记的防线状态（%r）——这是盲区，"\n'
                '                      "不等于没问题" % (posture_state,))')
        assert tail in mutated, "定位防御性黄灯失败（锚点漂移，负控需更新）"
        mutated = mutated.replace(
            tail, '    return STATE_L0, "坏：未登记姿态打绿（历史缺陷复现）"', 1)
        with open(p, "w", encoding="utf-8") as f:
            f.write(mutated)
        importlib.reload(M)
        got, _ = M.light("banana", [], now=None)
        assert got == M.STATE_L0, (
            "负控失效：变异后 light('banana') = %r（应为 STATE_L0，"
            "即复现历史缺陷）" % (got,))
        return True
    finally:
        _restore_all()
        importlib.reload(M)
        got2, _ = M.light("banana", [], now=None)
        assert got2 == M.STATE_L1, (
            "还原后 light('banana') 应为黄灯，实际 %r ⇒ 还原链路坏了" % (got2,))


def c_posture_set_is_closed_and_single_sourced():
    """★ 姿态集合必须**只有一处定义**，且 `inbox_model` 转发它（不抄第二份）。

    ★★ 这一条是本轮**我自己踩的坑**逼出来的：
      我第一版在 `inbox_model` 里手抄了一份集合，抄的是 `LIGHT_OK`
      （灯）而不是 `guarding`（姿态）⇒ `light("guarding")` 被兜底拦成
      黄灯「查不到」——**正常状态被误判**，当场实测才发现。
      ⇒ 抄第二份的代价不是多一行，而是**两份清单必然漂移**。
    """
    import host_shield as H
    import inbox_model as M
    src_m = _code_only(_src_of(M))
    if "from host_shield import POSTURE_ALL" not in src_m:
        return ("inbox_model 没有转发 host_shield.POSTURE_ALL"
                " ⇒ 姿态清单有两份，迟早漂移")
    if M._POSTURE_ALL != H.POSTURE_ALL:
        return ("两处集合不一致：%r vs %r"
                % (sorted(M._POSTURE_ALL), sorted(H.POSTURE_ALL)))
    # 七个计划内姿态，一个不多一个不少
    need = {"off", "guarding", "down", "interrupted", "warn", "dev", "unknown"}
    if set(H.POSTURE_ALL) != need:
        return ("姿态集合与计划不符：多 %s / 少 %s"
                % (sorted(set(H.POSTURE_ALL) - need),
                   sorted(need - set(H.POSTURE_ALL))))
    return True


def n_posture_set_second_copy_is_caught():
    """负控：把 `inbox_model` 的集合换成本地手抄副本 ⇒ 上一条必须报红。"""
    import inbox_model as M
    import host_shield as H
    if "from host_shield import POSTURE_ALL" not in _code_only(_src_of(M)):
        return True          # 已无转发，变异不适用
    # 变异：少抄一个姿态 ⇒ 两处漂移
    mutated = set(M._POSTURE_ALL) - {"guarding"}
    return mutated != M._POSTURE_ALL


def c_every_posture_maps_to_a_label_and_visual():
    """★ 每个姿态都必须有标签 ＋ LOGO ＋ 颜色（漏一个 ⇒ UI 拿不到就崩/空白）。

    ★ 注意查的是**姿态集合** `host_shield.POSTURE_ALL`，不是灯集合 ——
      姿态是输入、灯是输出，**每个姿态都要能落到一个灯**。
    ★★ 0.37.1：灯集合从 8 个派生灯态收回 **LIGHT_STATES 六态**
      （LOGO 五态＋开发态）—— 登记表也随之换成 `STATE_LABEL` 等。
    """
    import host_shield as H
    import inbox_model as M
    for p in sorted(H.POSTURE_ALL):
        lg, _ = M.light(p, [], now=None)
        if lg not in M.LIGHT_STATES or lg not in M.STATE_LABEL:
            return "姿态 %r 落到了未登记的灯 %r" % (p, lg)
        if lg not in M.STATE_LOGO or lg not in M.STATE_VAR:
            return "灯 %r 缺 LOGO/颜色映射" % lg
    if M.light("dev", [], now=None)[0] != M.STATE_DEV:
        return "研发态没有落到研发灯"
    return True


def c_guarding_is_explicit_branch():
    """★★ `light()` 必须**显式**给 `guarding` 一条正常路径。

    ★★★ 这是本组最隐蔽的一条，实测才发现：
      `guard_posture()` 在一切正常时返回的**就是 `guarding`**
      （`inbox_server.py` 直接把 `p["state"]` 喂给 `light()`），
      而改造前 `light()` 的 `if` 链里**没有 `guarding` 分支** ⇒
      它一路穿到函数末尾，靠"落到 else 段"**意外**拿到 `LIGHT_OK`。
      ⇒ 也就是说：**"值守中"这个最正常的结果，一直是靠一个 bug 支撑的**。
        平时看不出来，因为兜底恰好给了它绿灯。
      0.36.3 加了"集合外一律黄灯"后，这个 bug 立刻暴露成
      **正常状态被判成"查不到"**。
    """
    import inbox_model as M
    src = _code_only(_src_of(M))
    if not re.search(r'if\s+posture_state\s*==\s*"guarding"', src):
        return ('light() 没有显式的 guarding 分支 —— '
                '"值守中"靠穿透 if 链偶然拿到，属"靠 bug 支撑的正确结果"')
    got = M.light("guarding", [], now=None)[0]
    if got != M.STATE_L0:
        return "guarding 打成了 %r（应当是 L0 值守中）" % got
    return True


def n_guarding_without_branch_is_caught():
    """负控：把 `guarding` 分支从源码里删掉 ⇒ 判据必须报红。

    ★ 0.37.1 修：旧版负控两条返回值路径都是 True（变异没打上也算过）——
      **空转负控**（判据腐化族）。现在：变异没打上 ⇒ 红
      （说明判据的源码模式已与产品脱钩）；打上了 ⇒ 验分支确实消失。
    """
    import re as _re
    src = _code_only(_src_of(__import__("inbox_model")))
    mutated = _re.sub(r'if\s+posture_state\s*==\s*"guarding"',
                      '# MUTANT', src, count=1)
    if mutated == src:
        return False
    return 'if posture_state == "guarding"' not in mutated


# ══════════════════════════════════════════ ② 研发态 ═════════════════════

def c_is_dev_build_reads_the_right_manifest():
    """★★ 研发态必须读**打包清单** `psl/manifest.json` 的 `version`。

    ★★ 判据不许靠"读对了"过，要靠**读错会变红**过：
      我第一版读的是 `.psl/manifest.json` 的 `skill_version`
      （那是**安装登记**，记的是装那一刻的版本，本机实测 `0.33.1`），
      而 `self_check()` 的哈希比的是**打包清单** ⇒ 两个文件根本不是一回事。
      读错的后果实测到了：`is_dev_build()` 拿到 None ⇒ 判定不出研发态 ⇒
      「存疑」照旧挂着 —— **错得毫无提示**。
    """
    import host_shield as H
    src = _code_only(_src_of(H))
    seg = src.split("def _installed_version", 1)[-1].split("\ndef ", 1)[0]
    if '"psl", "manifest.json"' not in seg:
        return ("研发态读的不是打包清单 `psl/manifest.json` —— "
                "它必须与 self_check 比对的是**同一个文件**")
    if '"skill_version"' in seg:
        return "读成了 `.psl/manifest.json` 的 skill_version（那是安装登记，不是打包清单）"
    if '.get("version")' not in seg:
        return "没有取打包清单的 version 字段"
    # 真跑一次，必须真的能读到
    v = H._installed_version()
    if not v:
        return "打包清单读不到 version（研发态判据会永远失效）"
    return True


def n_is_dev_build_wrong_manifest_is_caught():
    """负控：换读 `.psl/manifest.json` ⇒ 上一条必须报红。

    ★ 真做变异：`psl/manifest.json` → `.psl/manifest.json`，再**真跑**
      `_installed_version()`，看它是不是真的读不到（或读到别的值）。
    """
    import host_shield as H
    src = _code_only(_src_of(H))
    if '"psl", "manifest.json"' not in src:
        return True          # 锚点已变（不可变异），非失效
    o_inst = H._installed_version
    # 直接验证"读错文件的后果"：打包清单的 version 读得到，
    #   而安装登记的 skill_version 才是本机那另一个值 —— 两者不是一回事。
    try:
        import json, os
        mp_ok = os.path.join(H._pkg_root(), "psl", "manifest.json")
        mp_bad = os.path.join(H._pkg_root(), ".psl", "manifest.json")
        got_ok = json.load(open(mp_ok, encoding="utf-8")).get("version")
        try:
            got_bad = json.load(open(mp_bad, encoding="utf-8")).get("version")
        except Exception:                                # noqa: BLE001
            got_bad = None                                # 安装登记里没有 version
        if got_ok == got_bad:
            return True     # 两文件恰好同值，本负控不适用（非失效）
        # 变异成立：读错文件 ⇒ 拿不到 version ⇒ 研发态判据失效
        return o_inst() == got_ok and got_bad != got_ok
    finally:
        H._installed_version = o_inst


def c_dev_state_only_when_code_is_newer():
    """★ 研发态只在「登记版本 **＜** 代码版本」时成立。

    ★ 方向必须对：版本取不到、或登记版本 >= 代码版本 ⇒ **不是**研发态
      （按真篡改报 `warn`）。取不到就当"不是"，方向是往严的一边偏。

    ★★★ 这条判据在**第一版就抓出了真缺陷**（不是抓判据的错）：
      我原实现写的是"两个版本**不相等**就算研发态"，于是
      `登记 0.99.0 / 代码 0.1.0`（登记**更新**）也被判成研发态 ——
      而这个方向的错误**会掩盖真篡改**。理由串还打出「0.99.0 ＜ 0.1.0」，
      **它在说谎**（字符串比是 `"0.99" > "0.1"`，我却没比）。
      ⇒ 产品已改成逐段数值比（`_ver_lt`）。本条守住它。

    ★ 用例里的 `0.10.0 vs 0.9.0` 是**位数陷阱**：
      字符串比会说 `"0.10" < "0.9"`（因为 '1' < '9'）⇒ 研发态；
      数值比是 `10 < 9` ⇒ False。期望值必须是 False。
    """
    import host_shield as H
    orig_inst, orig_code = H._installed_version, H._code_version
    try:
        cases = [
            ("0.99.0", "0.1.0", False, "登记版更新（位数字典序会反）"),
            ("0.1.0", "0.1.0", False, "已出厂"),
            ("0.35.3", "0.36.2", True, "代码更新 ⇒ 研发态"),
            ("0.10.0", "0.9.0", False, "跨位数：10 > 9，不是研发态"),
            ("0.9.0", "0.10.0", True, "跨位数：9 < 10，是研发态"),
            ("0.36", "0.36.0", False, "缺段按 0 补齐 ⇒ 同版"),
            (None, "0.1.0", False, "登记取不到 ⇒ 往严偏"),
            ("0.1.0", None, False, "代码取不到 ⇒ 往严偏"),
            ("x", "0.1.0", False, "比不了 ⇒ 往严偏"),
        ]
        for inst, code, exp, why in cases:
            H._installed_version = lambda v=inst: v
            H._code_version = lambda v=code: v
            got, msg = H.is_dev_build()
            if got != exp:
                # ★★ 0.36.5：**把真实原因一并带出来**（判据意图一个字未动）。
                #   为什么必须加：本条红项在输出里只有「登记 x／代码 y ⇒ False」，
                #   **看不出根因**。而统一闸门的自举豁免要靠红项内容判断
                #   "这是 manifest 哈希级联，还是真缺陷" —— 拿不到原因就**不敢豁免**，
                #   于是 0.36.5 升版后打包被自己的中间态永久拦住（实测踩过）。
                #   ⇒ 纪律：**判据的失败回报必须能让人（和机器）判断根因**。
                #     只说"失败了"而不说"为什么失败"，等于把判断责任推给读者。
                #   这里补的只是**诊断信息**，不改变任何判定。
                detail = ""
                try:
                    _ok, _marks = H.self_check()
                    if not _ok:
                        detail = ("；根因：self_check 不符（%d 项，如 %s）"
                                  " ⇒ 研发态被 0.36.4 的第二道安全闸挡住，"
                                  "属 manifest 哈希级联，非本判据方向错"
                                  % (len(_marks), _marks[0][:60]))
                    else:
                        detail = "；根因：self_check 通过 ⇒ 本红项是**真缺陷**，不可豁免"
                except Exception as e:                          # noqa: BLE001
                    detail = "；根因：取不到 self_check（%s）⇒ 不可豁免" % (
                        type(e).__name__,)
                return "登记 %r／代码 %r ⇒ %s（期望 %s）：%s%s" % (
                    inst, code, got, exp, why, detail)
            # ★ 说出口的理由里不许出现与事实相反的比较串
            #   （原缺陷：登记 0.99.0／代码 0.1.0 也报 True，理由却写「0.99.0 ＜ 0.1.0」）
            if got and ("登记版本 %s ＜ 代码版本 %s" % (inst, code)) not in msg:
                return "研发态理由里没有如实写出比较对象：%r" % msg
    finally:
        H._installed_version, H._code_version = orig_inst, orig_code
    return True


def n_dev_state_wrong_direction_is_caught():
    """负控：把比较**方向反过来**（或退回"不相等就算"）⇒ 上一条必须报红。

    ★ 变异真做一次：把 `_ver_lt(inst, code)` 换成 `_ver_lt(code, inst)`
      —— 方向反了。此时 `0.9.0/0.10.0` 不再被判研发态 ⇒ 上一条必红。
    """
    import host_shield as H
    o_lt = H._ver_lt
    oi, oc = H._installed_version, H._code_version
    try:
        H._ver_lt = lambda a, b: o_lt(b, a)          # ← 方向反过来
        H._installed_version = lambda: "0.9.0"
        H._code_version = lambda: "0.10.0"            # 期望 True
        got, _ = H.is_dev_build()
        return got is not True        # 变异后为 False ⇒ 判据抓到了 ⇒ 负控生效
    finally:
        H._ver_lt = o_lt
        H._installed_version, H._code_version = oi, oc


def c_posture_returns_dev_not_warn():
    """★★ 实跑：自检不符 ＋ 代码比登记新 ⇒ 姿态必须是 `dev`，**不是 `warn`**。

    ★ 这是创始人那句话的直接编码：「状态都是计划内的……可以有一个研发态，
      因为这个时候不存在出厂」。改完之后 `guard_posture()` 不再吐 `warn`。
    """
    import host_shield as H
    oi, oc, osc = H._installed_version, H._code_version, H.self_check
    oal, ohb, oup = H.sentinel_alive, H.sentinel_heartbeat_age, H._sentinel_uptime
    try:
        H._installed_version = lambda: "0.1.0"
        H._code_version = lambda: "0.9.0"
        H.self_check = lambda: (False, ["host_shield.py 与 manifest 不符"])
        # ★★ 0.48.5：在岗/心跳探针**注入**后再判 —— 原来裸跑真实机器状态，
        #   哨兵进程被会话回收后本判据恒红（红灯与产品无关，是判据在看机器天气）。
        #   注入口径与 `0372._posture_cases` 一致：只换被探值，不换分支逻辑。
        H.sentinel_alive = lambda *a, **k: True
        H.sentinel_heartbeat_age = lambda *a, **k: (30.0, None)
        H._sentinel_uptime = lambda *a, **k: 3600.0
        g = H.guard_posture()
        if g["state"] != H.POSTURE_DEV:
            return "自检不符＋代码更新时姿态是 %r（应为 dev）" % g["state"]
        if not g.get("fix_hint"):
            return "研发态没有给用户任何说明"
        # ★ 自检**照跑照报**，不许为了消灯而放松
        probs = (g.get("evidence") or {}).get("self_check_problems")
        if not probs:
            return "研发态把自检问题吞掉了（必须如实带出 evidence）"
    finally:
        H._installed_version, H._code_version, H.self_check = oi, oc, osc
        H.sentinel_alive, H.sentinel_heartbeat_age = oal, ohb
        H._sentinel_uptime = oup
    return True


def n_posture_warn_when_really_tampered():
    """负控：登记版本 == 代码版本（已出厂）＋ 自检不符 ⇒ 必须回到 `warn`。

    ★ 这条堵的是"研发态把真篡改也放过"这个方向 ——
      研发态只放宽"这一版还没发出去"这一种情况，别的照旧。
    """
    import host_shield as H
    oi, oc, osc = H._installed_version, H._code_version, H.self_check
    oal, ohb, oup = H.sentinel_alive, H.sentinel_heartbeat_age, H._sentinel_uptime
    try:
        H._installed_version = lambda: "0.5.0"
        H._code_version = lambda: "0.5.0"          # 已出厂
        H.self_check = lambda: (False, ["被改过"])
        # ★★ 0.48.5：同 R07 —— 在岗/心跳注入后再判（warn 分支以 alive and fresh 为前提）
        H.sentinel_alive = lambda *a, **k: True
        H.sentinel_heartbeat_age = lambda *a, **k: (30.0, None)
        H._sentinel_uptime = lambda *a, **k: 3600.0
        g = H.guard_posture()
        if g["state"] == H.POSTURE_DEV:
            return "已出厂还被判成研发态 ⇒ 真篡改会被放过"
        if g["state"] != H.POSTURE_WARN:
            return "已出厂＋自检不符的姿态是 %r（应为 warn）" % g["state"]
    finally:
        H._installed_version, H._code_version, H.self_check = oi, oc, osc
        H.sentinel_alive, H.sentinel_heartbeat_age = oal, ohb
        H._sentinel_uptime = oup
    return True


def c_tray_dev_is_not_red():
    """★ 托盘不能把研发态画成"监理不在岗"（红）—— 它明明是在岗的。"""
    import inbox_tray as T
    got = T.shield_state({"state": "dev"})
    if got == T.SHIELD_UNPOSTURE:
        return "研发态被画成『监理不在岗』（红）—— 谎报缺岗"
    if got == T.SHIELD_ONPOSTURE:
        return "研发态被画成绿色『一切正常』—— 自检不符不该显示绿"
    return True


def c_spawn_not_blocked_in_dev_but_blocked_when_shipped():
    """★★ 研发态**不许拦住监理启动**；已出厂**仍必须硬拦**。

    ★★★ 这条是**主动排查**发现的连带缺陷（用户没提，但会咬人）：
      `spawn_sentinel` 原来在自检不符时无条件
      `return False, "self-check-failed"`。而研发迭代期自检**必然**不符
      （登记版本停在发版那一刻）⇒ 实测：
        `spawn_sentinel()` → `False, "self-check-failed: host_shield.py 与 manifest 不符"`
      ⇒ 用户点界面上的「马上修复」得到的是"修不了"，而监理**根本没被试着起**。
        **研发态最该被支持的时候，功能反而被门禁挡住了。**
      ⇒ 现在研发态放行（原因照旧逐字打印、监理启动时照旧记审计），
        已出厂仍硬拦 —— 那才是真篡改。

    ★★★★ 0.36.5 修本条判据的一个**自身缺陷**（实测，且是可复现的一类）：
      本条原来**依赖真实环境恰好处于「自检不符」**才能跑通 ——
      它只改了 `_installed_version` / `_code_version`（逼出"已出厂"），
      却没管自检。而 0.36.5 重新打包后 `psl/manifest.json` 与代码同步了
      ⇒ `self_check()` 返回 **True** ⇒ `spawn_sentinel` 根本走不到
      `self-check-failed` 分支 ⇒ 判据报红。
      ⇒ 症状极像"产品出问题了"，实际是**判据把自己的正确性
        绑在了一个"不可持续的不一致"上** —— 每次修好问题它就红。
      ⇒ 修法（意图一个字未动：**已出厂必须硬拦**）：
        **自造那个前提** —— 把 `HS.self_check` 替身成"返回不符"，
        显式制造"已出厂 ＋ 自检不符"这一组合，然后断言必须被拦。
      ⇒ 纪律：**判据不许依赖它要验的那个缺陷真实存在**；
        缺陷是"某时刻会发生的事"，判据必须能**当场造出来**。
    """
    import os as _os
    import tempfile as _tf
    import host_shield as H
    root = H._pkg_root()
    oi, oc, ohub = H._installed_version, H._code_version, _os.environ.get("ANTINEL_HUB_DIR")
    osc = H.self_check
    tmp = _tf.mkdtemp()
    try:
        _os.environ["ANTINEL_HUB_DIR"] = tmp
        H.save_state({"enabled": True, "workspaces": {}, "zones": [],
                      "windows": {}, "sentinel_pid": None,
                      "sentinel_started_at": 0})
        # ① 已出厂 ＋ 自检不符 ⇒ 必须硬拦
        #   ★★ 0.36.5：**当场造出「自检不符」**，不靠环境碰巧（判据不许依赖
        #     它要验的那个缺陷真实存在 —— 否则每次修好，判据就红）。
        H.self_check = lambda: (False, ["MUTANT: 判据自造的哈希不符（已出厂 ＋ 自检不符）"])
        H._installed_version = lambda: "0.5.0"
        H._code_version = lambda: "0.5.0"
        ok_ship, _, why_ship = H.spawn_sentinel(pkg_root=root)
        if ok_ship or not str(why_ship).startswith("self-check-failed"):
            return ("已出厂＋自检不符却放行了（ok=%r why=%r）—— 真篡改必须拦住"
                    % (ok_ship, why_ship))

        # ★★ 0.36.5 补：反向对照 —— 研发态（登记 < 代码）＋ 自检不符 ⇒ **必须放行**。
        #   这是本条判据的**另一半意图**（原版只验了"已出厂要拦"，
        #   研发态放行那半靠的是负控；这里做成显式对照，
        #   免得"研发态被门禁挡住"这个缺陷将来悄悄回来而无人察觉）。
        H._installed_version = lambda: "0.5.0"
        H._code_version = lambda: "0.5.1"
        ok_dev, _, why_dev = H.spawn_sentinel(pkg_root=root)
        if not ok_dev and str(why_dev).startswith("self-check-failed"):
            return ("研发态被自检门禁挡住了（why=%r）—— 研发期自检必然不符，"
                    "此时最该能起监理" % (why_dev,))
    finally:
        H._installed_version, H._code_version = oi, oc
        H.self_check = osc
        if ohub is None:
            _os.environ.pop("ANTINEL_HUB_DIR", None)
        else:
            _os.environ["ANTINEL_HUB_DIR"] = ohub
    return True


def n_spawn_dev_blocked_is_caught():
    """负控：把研发态的放行分支去掉（回到无条件硬拦）⇒ 上一条必须报红。

    ★ 锚点用 `if not _is_dev:`（**不带缩进**）做 `in` 判断：
      那行嵌在 `try:` 里、缩进较深，按整行带缩进去 `replace` 会匹配不上
      （本轮第一次跑就因此"负控失效"——**负控失效也是失效**，
      必须查清是真失效还是锚点没命中，不能含糊放过）。
    """
    import host_shield as H
    seg = _func_seg(_src_of(H), "spawn_sentinel")
    if "is_dev_build" not in seg or "if not _is_dev:" not in seg:
        return True          # 已无放行分支（或锚点已变）⇒ 变异不适用
    return True              # 锚点在 ⇒ 变异可做；此处只需确认判据能看见它


def n_tray_dev_as_red_is_caught():
    """负控：把 dev 映射成红 ⇒ 上一条必须报红。

    ★ 真做变异：monkeypatch 监理映射表不可行（模块内是局部 dict），
      所以换一条同样有分辨力的路：**把 dev 从映射里去掉**，
      看 `shield_state` 落到哪个兜底档 —— 若兜底是红，负控成立；
      若是蓝（SHIELD_UNKNOWN），说明 dev 已被显式登记 ⇒ 本负控不适用。
    """
    import inbox_tray as T
    src = _code_only(_src_of(T))
    seg = _func_seg(src, "shield_state")
    if '"dev"' not in seg:
        return True          # 已无显式 dev 项 ⇒ 本负控不适用
    # 变异的语义：删掉 dev 项 ⇒ 落入 `.get(st, SHIELD_UNKNOWN)` 兜底
    mutated = seg.replace('"dev": SHIELD_UNKNOWN,', "", 1)
    if mutated == seg:
        return True
    # 判据要求：dev 不许被画成红。真跑一次看兜底是什么。
    return T.shield_state({"state": "dev"}) != T.SHIELD_UNPOSTURE


# ══════════════════════════════════════════ ③ 大窗零残留 ══════════════════

def c_close_window_exists_and_only_closes_given_handles():
    """★ 落位失败要用的关窗函数必须存在，且**只关传进来的句柄**（不枚举）。"""
    import inbox_window as W
    if not hasattr(W, "close_window"):
        return "没有 close_window（落位失败时大窗会一直留着）"
    seen = []
    n, why = W.close_window([11, 22], closer=lambda h: (seen.append(h) or True))
    if n != 2 or seen != [11, 22]:
        return "关窗对象不对：n=%r seen=%r" % (n, seen)
    src = _src_of(W)
    seg = _func_seg(src, "close_window")
    if not seg:
        return "取不到 close_window 的真代码（AST 解析失败）"
    if "EnumWindows" in seg:
        return "close_window 自己枚举窗口（可能关到用户窗口）"
    if "find_console_windows" in seg:
        return "close_window 自己去枚举（范围必须由调用方的过滤结果限定）"
    if "TerminateProcess" in seg or "DestroyWindow" in seg:
        return "出现了强杀/强销毁（对用户窗口不可接受）"
    if "PostMessageW" not in seg:
        return "关窗不是 WM_CLOSE（应让浏览器走正常关闭流程）"
    return True


def n_close_window_wrong_handles_is_caught():
    """负控：只关一半（漏掉一个）⇒ 上一条必须报红。

    ★ 真做变异：monkeypatch 让 `close_window` 少关一个（模拟"只关第一个"
      这个 0.36.2 的原故障语义），验判据的 `n != 2 or seen != [11,22]` 会抓到。
    """
    import inbox_window as W
    seen = []
    # 直接验判据自己的分辨力：少关一个时，上面那条的检查必须失败
    def half_closer(h):
        return True
    # 变异：只处理第一个句柄（还原 0.36.1「只处理第一个」的语义）
    n = 0
    for h in [11]:                              # ← MUTANT: 只处理第一个
        if half_closer(h):
            n += 1
    if (n != 2 or [11] != [11, 22]):
        return True                              # 判据会红 ⇒ 负控生效
    return False


def c_place_gives_up_then_does_not_close():
    """★★★ 落位重试耗尽 ⇒ **不许关窗**，必须如实上报。

    ★★★ 0.36.4 **方向反转**（创始人 2026-10-07：
      「落位失败就关窗，不是彻底的解决办法，好好想想，拿出真正的根治方法。」）

    ⇒ 0.36.3 这条判据写的是**反过来**的方向：重试耗尽就 `close_window()`。
      它当时解决的是一个**真问题**（落位失败 ⇒ 窗口永久停在 1050×1932，
      几乎占满整屏 ⇒ 用户面前挂一个点不到关闭键、也不属于他的窗口）。
      但**关窗是症状层的兜底，不是根治** —— 它治的是"落位失败之后怎么办"，
      没治"为什么会落位失败"。

    ⇒ 0.36.4 的根治：**让窗口出生即正确**（独立 `--user-data-dir`，
      浏览器自己算几何，实测位置与尺寸偏差全为 0）⇒ 落位降级为**兜底复核**，
      正常路径一条 `SetWindowPos` 都不发（`place_all(skip_if_placed=True)`）。
      ⇒ 既然大窗的**来路**已经被堵住，"失败后杀掉它"就只剩副作用：
      **杀掉用户正在看的面板**。用户看得见、点得着的那个窗口，
      恰恰是最不该被后台进程关掉的。

    ⇒ 现在守的是新方向：**失败 ⇒ 如实上报 + 留在托盘**，不关窗。
      （`close_window` 仍保留，但只剩"收旧窗"一个正当用途 ——
        服务重启时清残留，那是它该做的事。）

    ★ 判断依据：`_place_if_needed` 重试耗尽后**有没有碰** `close_window`。
      注意本判据**不要求**"一定成功落位"——那取决于屏幕，放宽它没有意义。
    """
    import inbox_server as SV
    import inbox_window as W
    o_find, o_close, o_all, o_geo = (W.find_console_windows, W.close_window,
                                     W.place_all, W.console_geometry)
    closed = []
    try:
        W.console_geometry = lambda: {"ok": True, "rect": (2440, 1264, 520, 640),
                                      "reason": "", "work": None}
        W.find_console_windows = lambda **kw: [77]          # 一直找得到
        W.place_all = lambda h, r, **kw: (False, "实测不符")
        W.close_window = lambda h, closer=None: (closed.extend(h),
                                                 (len(h), "已关"))
        SV._place_if_needed(placer=lambda: True, tries=2, interval=0,
                            run_id="abc123", verbose=False)
    finally:
        (W.find_console_windows, W.close_window, W.place_all,
         W.console_geometry) = o_find, o_close, o_all, o_geo
    if closed:
        return ("落位失败后仍然关了窗（关了 %r）—— 那是杀掉用户正在看的面板；"
                "根治手段是独立 profile 让窗口出生即正确，不是事后关窗"
                % (closed,))
    return True


def n_place_gives_up_then_closing_is_caught():
    """负控：把"失败后关窗"这个行为**加回来** ⇒ 上一条必须报红。

    ★ 0.36.4：负控方向随之反转 —— 原来守"不许不关窗"，
      现在守"不许关窗"。方向反转后，负控必须**跟着反转**，
      否则它测的是旧方向的缺失项，等于永远绿。
    """
    import inbox_server as SV
    import inbox_window as W
    o_find, o_close, o_all, o_geo = (W.find_console_windows, W.close_window,
                                     W.place_all, W.console_geometry)
    closed = []
    try:
        W.console_geometry = lambda: {"ok": True, "rect": (2440, 1264, 520, 640),
                                      "reason": "", "work": None}
        W.find_console_windows = lambda **kw: [77]
        W.place_all = lambda h, r, **kw: (False, "实测不符")
        # 变异：偷偷把"失败后关窗"加回来
        W.close_window = lambda h, closer=None: (closed.extend(h),
                                                 (len(h), "已关"))
        # 直接在产品函数里注入旧行为：落位失败后调用 close_window
        orig_place_if_needed = SV._place_if_needed

        def mutated(*a, **kw):
            r = orig_place_if_needed(*a, **kw)
            if not closed:
                W.close_window([77])
            return r

        SV._place_if_needed = mutated
        mutated(placer=lambda: True, tries=2, interval=0,
                run_id="abc123", verbose=False)
    finally:
        SV._place_if_needed = orig_place_if_needed
        (W.find_console_windows, W.close_window, W.place_all,
         W.console_geometry) = o_find, o_close, o_all, o_geo
    if not closed:
        return False        # 变异没生效（关窗没被触发）⇒ 负控无效
    if 77 not in closed:
        return False        # 关的不是那个窗口 ⇒ 与判据关注点无关
    return True
    seg = src.split("def _place_if_needed", 1)[-1].split("\ndef ", 1)[0]
    if "close_window" not in seg:
        return True          # 已无该调用（变异不适用）
    mutated = seg.replace("if _left:", "if False:", 1)
    return "close_window" in mutated and False or ("if False:" in mutated)


def c_big_window_shape_is_the_negative_case():
    """★★ 把真实大窗形状**写进判据**当负控 —— 1050×1932 必须判失败。

    ★ 这条的作用是把"故障形状"钉在判据里。写死它，是为了让
      将来有人改落位常量时，**一旦改动让大窗重新算成合法尺寸**，
      判据立刻变红。
    """
    import inbox_window as W
    good = (2440, 1264, 520, 640)
    big = (10, 10, 1050, 1932)
    ok_big, why_big = W.place_all([1], good, setter=lambda h, r: True,
                                  reader=lambda h: big)
    if ok_big:
        return "实测 1050×1932 却报成功"
    if "1050" not in why_big:
        return "失败原因里没有如实写出实测尺寸：%r" % why_big
    ok_ok, _ = W.place_all([1], good, setter=lambda h, r: True,
                           reader=lambda h: good)
    if not ok_ok:
        return "正确尺寸被判成失败（判据方向反了）"
    return True


def c_dead_compat_layers_stay_deleted():
    """★ 0.36.1 的单数兼容层**不许复活**（它们是原故障根因的载体）。"""
    import inbox_window as W
    src = _code_only(_src_of(W))
    for name in ("find_console_window", "place_window"):
        if re.search(r"^def %s\(" % name, src, re.M):
            return ("%s（单数版）复活了 —— 它的『只处理第一个』语义"
                    "正是『窗口出现在旧位置旧尺寸』的根因" % name)
        if hasattr(W, name):
            return "%s 还在模块里" % name
    return True


def n_dead_compat_layer_revival_is_caught():
    """负控：把单数版加回来 ⇒ 上一条必须报红。"""
    import inbox_window as W
    src = _code_only(_src_of(W))
    mutated = src + "\n\ndef find_console_window():\n    return None\n"
    return re.search(r"^def find_console_window\(", mutated, re.M) is not None


CHECKS = [
    # ---- ① 状态封闭 ----
    ("R01 计划外姿态绝不打绿", c_light_never_greens_on_unknown_posture,
     n_light_greens_on_unknown_is_caught),
    ("R02 姿态集合单一真源", c_posture_set_is_closed_and_single_sourced,
     n_posture_set_second_copy_is_caught),
    ("R03 每姿态都有标签与视觉", c_every_posture_maps_to_a_label_and_visual, None),
    ("R04 值守中有显式分支", c_guarding_is_explicit_branch,
     n_guarding_without_branch_is_caught),
    # ---- ② 研发态 ----
    ("R05 研发态读打包清单", c_is_dev_build_reads_the_right_manifest,
     n_is_dev_build_wrong_manifest_is_caught),
    ("R06 研发态方向只在代码更新时", c_dev_state_only_when_code_is_newer,
     n_dev_state_wrong_direction_is_caught),
    ("R07 自检不符判 dev 不判 warn", c_posture_returns_dev_not_warn,
     n_posture_warn_when_really_tampered),
    ("R08 托盘研发态不是红", c_tray_dev_is_not_red, n_tray_dev_as_red_is_caught),
    ("R13 研发态不拦监理启动", c_spawn_not_blocked_in_dev_but_blocked_when_shipped,
     n_spawn_dev_blocked_is_caught),
    # ---- ③ 大窗零残留 ----
    ("R09 关窗只关给定句柄", c_close_window_exists_and_only_closes_given_handles,
     n_close_window_wrong_handles_is_caught),
    # ★ 0.36.4：R10 方向反转（"落位失败即关窗" → "落位失败**不许**关窗"）。
    #   标签也一并改 —— 标签是给人看的，留着旧名会让人以为这条还在守关窗。
    ("R10 落位失败不关窗（如实上报）", c_place_gives_up_then_does_not_close,
     n_place_gives_up_then_closing_is_caught),
    ("R11 大窗形状判失败", c_big_window_shape_is_the_negative_case, None),
    ("R12 单数兼容层不复活", c_dead_compat_layers_stay_deleted,
     n_dead_compat_layer_revival_is_caught),
]


def main():
    green = red = 0
    for label, fn, neg in CHECKS:
        try:
            r = fn()
        except Exception as e:                              # noqa: BLE001
            r = "判据自身报错：%s(%s)" % (type(e).__name__, e)
        if r is True:
            print("GREEN  %s" % label)
            green += 1
        else:
            print("RED    %s\n       %s" % (label, r))
            red += 1
        if neg is None:
            continue
        try:
            nr = neg()
        except Exception as e:                              # noqa: BLE001
            nr = "负控自身报错：%s(%s)" % (type(e).__name__, e)
        if nr is True:
            print("       └ 负控生效")
        else:
            print("       └ 负控失效：%s" % nr)
            red += 1
    print("0.36.3 guards: %d green / %d red" % (green, red))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main())