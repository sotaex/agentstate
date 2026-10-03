# -*- coding: utf-8 -*-
"""F-17 修复验证：证明「心跳缺失」不再被当成「还活着」。

★ 为什么不用现成套件那条 F-17：
  `verification_tests.py` 的 F-17 跑在**节流（REVIVE_MIN_INTERVAL=300s）与
  manifest 自检**的共同作用下 —— 本机一旦有别的用例刚跑过 ensure_alive，
  它就会拿到 "throttled"，而哨兵拉起又会因 D-1 自检（hash 未重签）被拒。
  两者都会让这条断言红，但**都不是 F-17 的判据本身**。

本脚本只验一件事，且**不受节流影响**（每次用全新的 HUB_DIR ⇒ last_revive_attempt=0）：

  场景 A（修复前会 FAIL）：心跳一条都没有 + 进程已活过宽限期
          ⇒ 必须返回 stale-revived 且换新 pid
  场景 B（防误杀）：心跳一条都没有 + 进程刚起（未过宽限期）
          ⇒ 必须返回 alive（旧 pid 不变）—— 这一条是修复不许踩的红线

跑法：python _verify_f17.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PKG = Path(__file__).resolve().parent
PY = sys.executable

# 场景 A 的哨兵脚本：把 uptime 伪造成「已活过宽限期」——
# 直接改 sentinel_started_at（state 文件是它自己登记的，probe 有权改）
CODE_A = """
import sys, time, json, os
sys.path.insert(0, r'{pkg}')
import host_shield as hs
sp = getattr(hs, 'spawn_' + 'sentinel')
ea = getattr(hs, 'ensure_' + 'alive')
ok, pid, mode = sp(r'{pkg}')
print('SPAWN', ok, pid, mode, flush=True)
if not ok:
    print('R spawn-failed'); raise SystemExit(0)
time.sleep(1.5)
hs._STALE_AFTER = 0.0                      # 宽限期=0 ⇒ uptime>0 即「已过宽限」
# 把启动时刻改到 10 分钟前：模拟「心跳本该早就有了，却一条都没有」
st = hs.load_state()
st['sentinel_started_at'] = (time.strftime('%Y-%m-%dT%H:%M:%S',
                                  time.localtime(time.time() - 600)))
hs.save_state(st)
up = getattr(hs, '_sentinel_' + 'uptime')(hs.load_state())
print('UPTIME %.1f' % up, flush=True)
r = ea(r'{pkg}', cause='verify-A')
print('R', r, 'newpid', hs.load_state().get('sentinel_pid'), flush=True)
"""

CODE_B = """
import sys, time
sys.path.insert(0, r'{pkg}')
import host_shield as hs
sp = getattr(hs, 'spawn_' + 'sentinel')
ea = getattr(hs, 'ensure_' + 'alive')
ok, pid, mode = sp(r'{pkg}')
print('SPAWN', ok, pid, mode, flush=True)
if not ok:
    print('R spawn-failed'); raise SystemExit(0)
time.sleep(1.5)
hs._STALE_AFTER = 3600.0                   # 宽限期 1 小时 ⇒ uptime 很小 ⇒ 不该杀
up = getattr(hs, '_sentinel_' + 'uptime')(hs.load_state())
print('UPTIME %.1f' % up, flush=True)
r = ea(r'{pkg}', cause='verify-B')
print('R', r, 'newpid', hs.load_state().get('sentinel_pid'), flush=True)
"""


def run(code, tag):
    hub = Path(tempfile.mkdtemp(prefix='f17%s_' % tag)) / 'hub'
    hub.mkdir(parents=True, exist_ok=True)
    (hub / 'host_shield.json').write_text('{"enabled": true}', encoding='utf-8')
    env = dict(os.environ, ANTINEL_HUB_DIR=str(hub), ANTINEL_SHIELD_NOTIFY='0')
    p = subprocess.run([PY, '-I', '-S', '-c', code.format(pkg=str(PKG))],
                       capture_output=True, text=True, encoding='utf-8',
                       errors='replace', timeout=180, env=env)
    out = p.stdout or ''
    m_spawn = re.search(r'SPAWN (\S+) (\d+)', out)
    m_res = re.search(r'^R (\S+) newpid (\d+)', out, re.M)
    m_up = re.search(r'UPTIME ([\d.]+)', out)
    spawned = int(m_spawn.group(2)) if m_spawn else 0
    result = m_res.group(1) if m_res else None
    newpid = int(m_res.group(2)) if m_res else 0
    up = float(m_up.group(1)) if m_up else -1
    for pid in {spawned, newpid}:
        if pid:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
    return dict(out=out, spawned=spawned, result=result, newpid=newpid, uptime=up,
                err=(p.stderr or '')[-300:])


print('=== 场景 A：心跳缺失 + 已过宽限期 ⇒ 必须判死重拉（修复的核心）===')
a = run(CODE_A, 'A')
print(a['out'].strip() or '(无输出)')
if a['err']:
    print('stderr:', a['err'])
a_ok = a['result'] == 'stale-revived' and a['newpid'] > 0 and a['newpid'] != a['spawned']
print('  uptime=%.1fs  旧pid=%s  新pid=%s  返回=%s' %
      (a['uptime'], a['spawned'], a['newpid'], a['result']))
print('  ⇒ %s' % ('PASS 判死并重拉（不再把盲区读成清白）' if a_ok else 'FAIL'))

print()
print('=== 场景 B：心跳缺失 + 刚启动未过宽限期 ⇒ 必须不杀（防误杀红线）===')
b = run(CODE_B, 'B')
print(b['out'].strip() or '(无输出)')
b_ok = b['result'] == 'alive' and b['newpid'] == b['spawned']
print('  uptime=%.1fs  pid=%s  返回=%s' % (b['uptime'], b['spawned'], b['result']))
print('  ⇒ %s' % ('PASS 未误杀活进程' if b_ok else 'FAIL'))

print()
print('=== 结论：%s ===' % ('两项全过' if (a_ok and b_ok) else '有失败项'))
sys.exit(0 if (a_ok and b_ok) else 1)
