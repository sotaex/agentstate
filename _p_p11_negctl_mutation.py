# -*- coding: utf-8 -*-
"""★ 量具自检验：P11「忽略R0端到端要备注」的**负控是不是活的**。

判据不是"它现在绿"，而是"产品被改坏时它会不会红"。
这里做变异：把 `NOTE_REQUIRED_TO_IGNORE` 从 ("R0",) 扩成 ("R0","L2")，
即"产品错误地把备注要求扩大到 L2" —— 负控**必须**由 True 变 False。

若变异后负控仍 True ⇒ 这条负控是恒真的装饰品，等于没守卫。
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "ci"))

import inbox_guards as G
import inbox_model as M

ORIG = M.NOTE_REQUIRED_TO_IGNORE

print("原值 NOTE_REQUIRED_TO_IGNORE =", ORIG)

# ① 常态：正控真、负控真
c0 = G.c_cli_ignore_r0_needs_note()
n0 = G.n_cli_ignore_r0_needs_note()
print("常态      : 正控=%s 负控=%s" % (c0, n0))

# ② 变异一：把备注要求扩大到 L2（产品变严）⇒ 负控必须变红
M.NOTE_REQUIRED_TO_IGNORE = ("R0", "L2")
n1 = G.n_cli_ignore_r0_needs_note()
print("变异→L2严 : 负控=%s  （期望 False：产品把 L2 也要求备注，负控应报警）" % n1)

# ③ 变异二：干脆取消备注要求（产品放松）⇒ 正控必须变红
M.NOTE_REQUIRED_TO_IGNORE = ()
c2 = G.c_cli_ignore_r0_needs_note()
print("变异→取消 : 正控=%s  （期望 False：R0 无备注也能忽略，正控应报警）" % c2)

M.NOTE_REQUIRED_TO_IGNORE = ORIG

ok = (c0 is True) and (n0 is True) and (n1 is False) and (c2 is False)
print()
print("结论：%s" % ("负控是活的（变异能让它红）✔" if ok else "★ 量具不合格：存在恒真/恒假分支"))
sys.exit(0 if ok else 1)
