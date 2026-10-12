# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""J2：PyPI 下载后全流程模拟（用户旅程可复跑版）。

为什么要有它：27 套闸门 + 315 条断言 + 发布验收回答的都是「包对不对」；
`scripts/verify_release.py` 的 [D] 步只回答「装得上、导得进」；
`ci/j1_install_test.py` 是从**本地路径**装。没有任何一条回答
「用户从索引下载之后，全流程通不通、体验够不够好」。本件补这一段。

用法：
    python ci/j2_pypi_e2e.py --wheel dist/antinel-0.48.1-py3-none-any.whl
    python ci/j2_pypi_e2e.py --find-links dist        # 最接近索引语义
    python ci/j2_pypi_e2e.py --from-pypi              # 轨道 B：真索引（上传后）

证据全部落 _uxtest2/<时间戳>/（**不删**，零删除纪律）。
退出码 0 = 全部判据绿。
"""
import io, os, re, sys, json, time, shutil, subprocess, tempfile, venv, glob

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TS = time.strftime("%Y%m%d-%H%M%S")
EVID = os.path.join(ROOT, "_uxtest2", TS)
os.makedirs(EVID, exist_ok=True)

RESULTS = []      # (判据, 状态, 明细)


def rec(jid, ok, detail, skipped=False):
    st = "SKIP" if skipped else ("PASS" if ok else "FAIL")
    RESULTS.append((jid, st, detail))
    print("  [%s] %-4s %s" % (st, jid, detail))
    return ok


def run(cmd, cwd=None, timeout=180, env=None):
    t0 = time.time()
    e = dict(os.environ)
    e["PYTHONIOENCODING"] = "utf-8"
    if env:
        e.update(env)
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout, env=e)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = 124, b"", b"[TIMEOUT %ds]" % timeout
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), time.time() - t0


def dump(name, text):
    with io.open(os.path.join(EVID, name), "w", encoding="utf-8") as f:
        f.write(text)


def venv_py(vd):
    return os.path.join(vd, "Scripts", "python.exe") if os.name == "nt" else os.path.join(vd, "bin", "python")


def venv_ant(vd):
    return os.path.join(vd, "Scripts", "antinel.exe") if os.name == "nt" else os.path.join(vd, "bin", "antinel")


def make_venv(tag, parent=None):
    vd = tempfile.mkdtemp(prefix="j2venv_%s_" % tag, dir=parent)
    t0 = time.time()
    venv.create(vd, with_pip=True)
    print("   venv(%s): %s（%.1fs）" % (tag, vd, time.time() - t0))
    return vd


def install(vd, mode, dist=None):
    """mode: wheel | find-links | pypi"""
    py = venv_py(vd)
    if mode == "wheel":
        cmd = [py, "-m", "pip", "install", "--quiet", "--no-input", dist]
    elif mode == "find-links":
        cmd = [py, "-m", "pip", "install", "--quiet", "--no-input",
               "--no-index", "--find-links", os.path.join(ROOT, "dist"), "antinel"]
    else:
        cmd = [py, "-m", "pip", "install", "--quiet", "--no-input", "antinel"]
    rc, out, err, dt = run(cmd, timeout=600)
    return rc, out, err, dt


def site_pkgs(vd):
    py = venv_py(vd)
    rc, out, _e, _d = run([py, "-c", "import sysconfig;print(sysconfig.get_paths()['purelib'])"], timeout=60)
    return out.strip().splitlines()[-1] if rc == 0 else ""


# ---------------------------------------------------------------- 主流程
def main():
    argv = sys.argv[1:]
    mode = "wheel"
    dist = None
    if "--wheel" in argv:
        dist = argv[argv.index("--wheel") + 1]
    elif "--find-links" in argv:
        mode = "find-links"
    elif "--from-pypi" in argv:
        mode = "pypi"
    else:
        cands = sorted(f for f in os.listdir(os.path.join(ROOT, "dist")) if f.endswith(".whl"))
        if not cands:
            print("dist/ 里没有 wheel —— 先用 scripts/release.py 出包"); return 2
        dist = os.path.join(ROOT, "dist", cands[-1])

    # ★ 夹具修正（0.48.2）：--find-links 模式此前不设 exp_ver ⇒ J2 假红。
    #   期望版本应由**待装的那件 wheel** 推得（index 语义下就是 dist 里最新的本包轮）。
    if mode == "find-links" and not dist:
        wheels = [f for f in os.listdir(os.path.join(ROOT, "dist")) if f.endswith(".whl")]
        if wheels:
            def _vt(name):
                m = re.search(r"antinel-([0-9.]+)-py3", name)
                return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)
            dist = os.path.join(ROOT, "dist", sorted(wheels, key=_vt)[-1])

    exp_ver = None
    if dist:
        # ★ 0.48.4：正则必须同时认两件产物。PyPI 上 wheel 与 sdist 都会发，
        #   而 sdist 路径此前**测不到**：文件名叫 `antinel-0.48.4.tar.gz`，
        #   只认 `-py3` 的正则解析出 None ⇒ J2「antinel -V」当场假红
        #   （实测输出 `antinel 0.48.4` 明明是对的，判据说"期望含 None"）。
        m = re.search(r"antinel-([0-9.]+)(?:-py3|\.tar\.gz)", os.path.basename(dist))
        exp_ver = m.group(1) if m else None
    elif mode == "pypi":
        # 轨道 B：期望版本＝本次待发版（workspace_facts.target_version）
        try:
            _wf = json.load(open(os.path.join(ROOT, "psl", "workspace_facts.json"), encoding="utf-8"))
            exp_ver = _wf["release"]["pypi"]["target_version"]
        except Exception:
            exp_ver = None

    print("== J2 · PyPI 下载后全流程模拟 ==")
    print("   模式=%s  期望版本=%s  证据目录=%s" % (mode, exp_ver, EVID))

    # ---- 装两处：仓内（ASCII 路径）＋ 家目录（中文路径，本机天然样本）
    v_ascii = make_venv("ascii")
    v_cn = make_venv("cn", parent=os.path.expanduser("~"))

    print("\n-- M2 安装 --")
    rc, out, err, dt = install(v_ascii, mode, dist)
    dump("install_ascii.txt", out + "\n---stderr---\n" + err)
    rec("J1a", rc == 0, "仓内 ASCII 路径安装 rc=%d（%.1fs）" % (rc, dt))
    rc2, out2, err2, dt2 = install(v_cn, mode, dist)
    dump("install_cn.txt", out2 + "\n---stderr---\n" + err2)
    rec("J1b", rc2 == 0, "家目录中文路径安装 rc=%d（%.1fs）" % (rc2, dt2))

    ant = venv_ant(v_ascii)
    py = venv_py(v_ascii)
    sp = site_pkgs(v_ascii)
    print("   site-packages=%s" % sp)

    # ---- M3 首次运行
    print("\n-- M3 首次运行 --")
    rc, out, err, dt = run([ant, "-V"], timeout=60)
    got = (out or err).strip()
    dump("m3_version.txt", out + err)
    rec("J2", rc == 0 and exp_ver and exp_ver in got,
        "antinel -V -> rc=%d %r（期望含 %s）" % (rc, got[:60], exp_ver))
    rc, out, err, dt = run([ant, "help"], timeout=60)
    dump("m3_help.txt", out + err)
    rec("J3", rc == 0 and len(out) > 200, "antinel help -> rc=%d 输出 %d 字符（%.1fs）" % (rc, len(out), dt))
    rc, out, err, dt = run([ant, "-h"], timeout=60)
    dump("m3_h.txt", out + err)
    h_ok = rc == 0
    rec("J4a", h_ok, "antinel -h -> rc=%d %r" % (rc, (err or out).strip()[:70]))
    rc, out, err, dt = run([ant, "--help"], timeout=60)
    dump("m3_helpflag.txt", out + err)
    rec("J4b", rc == 0, "antinel --help -> rc=%d %r" % (rc, (err or out).strip()[:70]))

    # ---- M4 接入宿主（未初始化项目的报错文案 + 文档命令可达性）
    print("\n-- M4 接入宿主 / 文档命令可达性 --")
    proj = tempfile.mkdtemp(prefix="j2proj_")
    rc, out, err, dt = run([ant, "morning"], cwd=proj, timeout=120)
    dump("m4_morning_uninit.txt", out + "\n---stderr---\n" + err)
    msg = (err or out).strip()
    rec("J4c", ("scripts/install.py" not in msg) and ("scripts" not in msg or "-m" in msg),
        "未初始化项目报错文案 -> rc=%d %r" % (rc, msg.replace("\n", " ")[:110]))

    doc_cmds = scan_doc_commands(sp)
    dump("m4_doc_commands.json", json.dumps(doc_cmds, ensure_ascii=False, indent=2))
    bad = [c for c in doc_cmds if not c["reachable"]]
    # ★★ 0.48.3：加**非空洞**判据 —— 命中 0 条 ⇒ FAIL。
    #   0.48.2 实测：README 全改成 `-m` 形态后旧正则扫到 0 条，J4d 照样亮绿灯
    #   （"共 0 条，不可达 0 条"）⇒ 一条**什么都不测**的守卫冒充"通过"。
    rec("J4d", (len(doc_cmds) > 0) and not bad,
        "文档命令可达性：共 %d 条（0 条＝扫描器失效，判红），不可达 %d 条 %s"
        % (len(doc_cmds), len(bad), [c["cmd"] for c in bad][:6]))

    # ★ 夹具修正：先**初始化一个项目**（.psl），否则 verify/digest 类 act
    #   在空目录里必然 rc≠0（那是夹具缺陷，不是产品缺陷）。
    rc, out, err, dt = run([py, "-m", "scripts.install", "--root", proj], cwd=proj, timeout=300)
    dump("m4_install.txt", out + "\n---stderr---\n" + err)
    rec("J4init", rc in (0, 1), "python -m scripts.install --root <proj> 初始化 rc=%d" % rc)

    rc, out, err, dt = run([py, "-m", "scripts.install", "--check"], cwd=proj, timeout=180)
    dump("m4_install_check.txt", out + "\n---stderr---\n" + err)
    rec("J4e", rc in (0, 1, 3), "python -m scripts.install --check -> rc=%d（约定 0/1/3）%r"
        % (rc, (out or err).strip()[:70]))

    # ---- M5 日常使用（在**已初始化**的项目里）
    print("\n-- M5 日常使用 --")
    # ★ 夹具修正：`antinel report` 的子命令参数是 --session/--write（不是 --days）；
    #   按 README 口径的「日报」是 `antinel digest --days N`。
    # ★★ 0.48.3：J5b 的**期望值**修正 —— `antinel verify` 在**新项目**里返回 rc=1
    #   是**正确行为**：链里 0 条记录 ≠ "没问题"，它打印的正是这句
    #   （"这不是『没问题』，是『这里没有东西可查』"）。原期望 rc==0 是**模拟自己
    #   的夹具缺陷**，不是产品缺陷。约定：0=current / 1=链为空或无结论。
    for jid, args, okrc in (("J5a", ["inbox", "list"], (0,)),
                            ("J5b", ["verify"], (0, 1)),
                            ("J5c", ["digest", "--days", "1"], (0,))):
        rc, out, err, dt = run([ant] + args, cwd=proj, timeout=180)
        dump("m5_%s.txt" % jid, out + "\n---stderr---\n" + err)
        rec(jid, rc in okrc, "antinel %s -> rc=%d（约定 %s；%.1fs，输出 %d 字符）"
            % (" ".join(args), rc, "/".join(str(x) for x in okrc), dt, len(out)))

    # ---- M6 信任核验（README 承诺的「自己验」）
    print("\n-- M6 信任核验 --")
    # ★★ 0.48.3：断言从「rc 落在约定集合内」收紧为「**必须 current**」。
    #   旧写法 `rc in (0,1,2)` 是**假绿**：0.48.2 的纯净安装返回 rc=1 且打印
    #   `[SUPERSEDED] 1 of 21 covered files are missing`，旧判据照样放行；
    #   而 README 第 24 行自己定义「1＝superseded」⇒ 等于放过"自己验当场喊狼来了"。
    #   现在三条 README「自己验」命令逐条断言（对应 README 第 16/17/18 行）。
    rc, out, err, dt = run([py, "-m", "tools.antinel_verify"], cwd=proj, timeout=300)
    dump("m6_verify.txt", out + "\n---stderr---\n" + err)
    _o = (out + err).strip()
    rec("J6", rc == 0 and "[OK]" in _o,
        "python -m tools.antinel_verify -> rc=%d（须 [OK]/current）%r" % (rc, _o[:80]))
    rc, out, err, dt = run([py, "-m", "tools.antinel_verify", "--manifest"], cwd=proj, timeout=300)
    dump("m6_verify_manifest.txt", out + "\n---stderr---\n" + err)
    _o = (out + err).strip()
    rec("J6m", rc == 0 and "[OK]" in _o,
        "python -m tools.antinel_verify --manifest -> rc=%d（须 [OK]/current）%r" % (rc, _o[:80]))
    rc, out, err, dt = run([py, "-m", "tools.verify_namespaces"], cwd=proj, timeout=120)
    dump("m6_verify_ns.txt", out + "\n---stderr---\n" + err)
    _o = (out + err).strip()
    rec("J6n", rc == 0 and "unreadable" not in _o,
        "python -m tools.verify_namespaces -> rc=%d（须读得到清单且指纹匹配）%r" % (rc, _o[:80]))
    ch = os.path.join(sp, "challenge", "verify.py")
    rec("J5challenge", os.path.exists(ch), "challenge/verify.py 随包：%s" % ("在" if os.path.exists(ch) else "缺失"))
    # ★ P0-3 修正后的口径：A6 声明**不随 wheel**（docs/ 不进 wheel），但**随 sdist**。
    #   所以「安装态不可达」是**预期**；要断言的是「指针诚实」＋「sdist 里真在」。
    _doc_srcs = [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "NOTICE")]
    _doc_srcs += glob.glob(os.path.join(sp, "antinel-*.dist-info", "METADATA"))
    _doc_srcs += glob.glob(os.path.join(sp, "antinel-*.dist-info", "licenses", "NOTICE"))
    _doc_txt = ""
    for _p in _doc_srcs:
        if os.path.exists(_p):
            _doc_txt += io.open(_p, encoding="utf-8", errors="replace").read()
    pointer_ok = ("A6收入边界声明.md" in _doc_txt) and ("不随 wheel" in _doc_txt or "随 sdist" in _doc_txt)
    rec("J5a6", pointer_ok, "A6 指针诚实（明说随 sdist / 不随 wheel）：%s" % ("是" if pointer_ok else "否"))
    import tarfile
    _sd = sorted(glob.glob(os.path.join(ROOT, "dist", "*.tar.gz")))
    if _sd:
        with tarfile.open(_sd[-1]) as _tf:
            _has = any(n.endswith("docs/A6收入边界声明.md") for n in _tf.getnames())
        rec("J5a6s", _has, "A6 声明随 sdist（%s）：%s" % (os.path.basename(_sd[-1]), "在" if _has else "缺失"))

    # ---- ★ 0.48.4 · M8 **Agent 旅程**（这一幕是 v1.1 新增的：装包的人里
    #      Agent 占大多数，而它失败一次就不会再推荐你）
    #      判据取「Agent 装完 pip 包后，手里只有 `antinel` 一个词」这个真实约束：
    #      四条都必须能从这个词出发走到，不许要求它先知道 `python -m scripts.x`。
    print("\n-- M8 Agent 旅程 --")
    rc, out, err, dt = run([ant, "agent", "--json"], timeout=60)
    dump("m8_agent_json.txt", out + "\n---stderr---\n" + err)
    _d = None
    if rc == 0 and out.strip():
        try:
            _d = json.loads(out)
        except Exception:
            _d = None
    rec("J8a", rc == 0 and isinstance(_d, dict),
        "antinel agent --json -> rc=%d 可解析=%s（%.1fs）" % (rc, _d is not None, dt))
    rec("J8b", bool(_d) and set(("installed", "next_steps", "host_detected",
                                 "package_version", "skill_md")) <= set(_d),
        "agent --json 字段齐（installed/next_steps/host_detected/package_version/skill_md）：%s"
        % ("齐" if _d else "缺"))
    # 版本号不许自相矛盾：agent 报的包版本必须与 `antinel -V` 一致
    rc_v, out_v, _e, _t = run([ant, "-V"], timeout=60)
    _vv = (out_v or "").strip()
    rec("J8c", bool(_d) and rc_v == 0 and _d.get("package_version") in _vv,
        "包版本一致：agent=%r vs -V=%r" % (_d.get("package_version") if _d else None, _vv[:40]))

    rc, out, err, dt = run([ant, "skill", "--path"], timeout=60)
    _sk = (out or err).strip()
    dump("m8_skill_path.txt", out + err)
    rec("J8d", rc == 0 and bool(_sk) and os.path.isfile(_sk),
        "antinel skill --path -> rc=%d 路径存在=%s：%r" % (rc, os.path.isfile(_sk), _sk[-60:]))
    # ★ 反向对照的味道：SKILL.md 必须**随 wheel**，不是只在源码树里有
    rec("J8e", bool(_sk) and os.path.abspath(_sk).startswith(os.path.abspath(sp)),
        "SKILL.md 落在**包内**（不是源码树）：%s" % ("是" if _sk and os.path.abspath(_sk).startswith(os.path.abspath(sp)) else "否"))

    rc, out, err, dt = run([ant, "install", "--check"], timeout=120)
    dump("m8_install_check.txt", out + "\n---stderr---\n" + err)
    # 约定：0=一致 / 1=未安装 / 3=漂移。新项目里 1 是正确答案。
    rec("J8f", rc in (0, 1, 3), "antinel install --check -> rc=%d（约定 0/1/3）%r"
        % (rc, (out or err).strip()[:70]))
    # 帮助里必须给 Agent 一个路口（否则它读完 60 行中文还是不知道下一步）
    rc, out, err, dt = run([ant, "--help"], timeout=60)
    rec("J8g", rc == 0 and "agent --json" in out and "pip install antinel" in out,
        "--help 含 Agent 路口与包名澄清：%s"
        % ("是" if (rc == 0 and "agent --json" in out and "pip install antinel" in out) else "否"))

    # ---- M7 升级与卸载
    print("\n-- M7 卸载与残留 --")
    rc, out, err, dt = run([py, "-m", "pip", "uninstall", "-y", "antinel"], timeout=180)
    dump("m7_uninstall.txt", out + err)
    left = [n for n in ("antinel.py", "hooks", "psl", "rules", "challenge", "scripts", "tools")
            if os.path.exists(os.path.join(sp, n))]
    rec("J7", rc == 0 and not left, "卸载 rc=%d；site-packages 残留 %s" % (rc, left or "无"))

    # ---- 汇总
    ok = sum(1 for _j, s, _d in RESULTS if s == "PASS")
    fail = [r for r in RESULTS if r[1] == "FAIL"]
    skip = sum(1 for _j, s, _d in RESULTS if s == "SKIP")
    summary = {"ts": TS, "mode": mode, "expected_version": exp_ver,
               "results": [{"id": j, "status": s, "detail": d} for j, s, d in RESULTS],
               "pass": ok, "fail": len(fail), "skip": skip}
    dump("summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
    print("\n== 合计：PASS %d / FAIL %d / SKIP %d ==" % (ok, len(fail), skip))
    for j, s, d in fail:
        print("   FAIL %s %s" % (j, d))
    print("证据目录（不删）：%s" % EVID)
    return 0 if not fail else 1


def scan_doc_commands(sp):
    """扫描 README / 帮助正文里**教用户敲**的命令，判断在安装态是否可达。

    ★★ 0.48.3：必须同时认**两种形态**。第一版只认旧的裸路径形态
      （「python ＋ scripts/ 相对路径」）；0.48.2 把 README 全部改成 `python -m scripts.x`
      之后，它匹配到 **0 条** ⇒ J4d 变成**空过的绿灯**（"共 0 条，不可达 0 条"）。
      空过的守卫比没有守卫更坏（本项目第 ① 条硬判据）⇒ 现在：
        · 两种形态都扫；
        · `-m` 形态的判据 = **该模块在安装态存在**（用户就是那样敲的）；
        · 命中 0 条由调用方判 FAIL（见 J4d），不许"没扫到"冒充"没问题"。
    可达性判据 = 该路径**相对于安装目录**是否存在（用户敲的就是这个）；
    同时给出该文件在 site-packages 内的位置（解释为什么不可达）。
    ★ 0.48.2：README.md 是 **REPO-OWNED**（构建器不写），故这里扫仓根 README.md；
      再补扫安装态的 METADATA（PyPI 长描述就是从 README.md 生成的，二者应一致）。
    """
    pat_bare = re.compile(r"python\s+((?:scripts|tools)[\\/][A-Za-z_]+\.py)")
    pat_m = re.compile(r"python\s+-m\s+((?:scripts|tools)\.[A-Za-z_][\w.]*)")
    out, seen = [], set()
    srcs = [os.path.join(ROOT, "README.md")]
    srcs += glob.glob(os.path.join(sp, "antinel-*.dist-info", "METADATA"))
    for src in srcs:
        if not os.path.exists(src):
            continue
        with io.open(src, encoding="utf-8", errors="replace") as f:
            for i, ln in enumerate(f, 1):
                for m in pat_bare.finditer(ln):
                    rel = m.group(1).replace("\\", "/")
                    if ("bare", rel) in seen:
                        continue
                    seen.add(("bare", rel))
                    out.append({"src": os.path.basename(src), "line": i,
                                "cmd": "python " + rel, "form": "bare",
                                "reachable": os.path.exists(os.path.join(sp, rel)),
                                "in_sitepkgs": os.path.exists(os.path.join(sp, rel))})
                for m in pat_m.finditer(ln):
                    mod = m.group(1)
                    rel = mod.replace(".", "/") + ".py"
                    if ("m", mod) in seen:
                        continue
                    seen.add(("m", mod))
                    out.append({"src": os.path.basename(src), "line": i,
                                "cmd": "python -m " + mod, "form": "m",
                                "reachable": os.path.exists(os.path.join(sp, rel)),
                                "in_sitepkgs": os.path.exists(os.path.join(sp, rel))})
    return out


if __name__ == "__main__":
    sys.exit(main())
