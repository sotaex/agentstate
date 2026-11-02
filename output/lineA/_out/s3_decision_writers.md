# S3 decision 写入点定性（2026-11-03 06:08）

扫描 124 个 .py；写入点 112（运行时 89 ＋ 判据 23）；读取点 33。

| 路径 | 行 | 形态 | 右值类型 | 右值 | 引用 action |
|---|---|---|---|---|---|
| `antinel.py` | 278 | W2-dictkey | literal | `'allow'` |  |
| `antinel.py` | 559 | W2-dictkey | literal | `'allow'` |  |
| `antinel.py` | 821 | W2-dictkey | literal | `'allow'` |  |
| `antinel.py` | 1049 | W2-dictkey | literal | `'allow'` |  |
| `antinel.py` | 1820 | W1-kwarg | literal | `'allow'` |  |
| `antinel.py` | 2163 | W1-kwarg | literal | `'allow'` |  |
| `antinel.py` | 2307 | W1-kwarg | literal | `'allow'` |  |
| `antinel.py` | 2425 | W1-kwarg | literal | `'allow'` |  |
| `antinel.py` | 2499 | W1-kwarg | ifexp | `'allow' if dec.startswith('allow') else 'deny'` |  |
| `hooks/post_tool_use.py` | 391 | W2-dictkey | literal | `'alert'` |  |
| `hooks/post_tool_use.py` | 497 | W2-dictkey | literal | `'alert'` |  |
| `hooks/pre_tool_use.py` | 1289 | W2-dictkey | literal | `'config_fallback'` |  |
| `hooks/pre_tool_use.py` | 1316 | W2-dictkey | literal | `'config_fallback'` |  |
| `hooks/pre_tool_use.py` | 3989 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 4015 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 4076 | W2-dictkey | literal | `'block'` |  |
| `hooks/pre_tool_use.py` | 4540 | W1-kwarg | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 4546 | W1-kwarg | literal | `'deny'` |  |
| `hooks/pre_tool_use.py` | 4563 | W1-kwarg | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 4570 | W1-kwarg | literal | `'deny'` |  |
| `hooks/pre_tool_use.py` | 5239 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5344 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5418 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5445 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5466 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5474 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5490 | W2-dictkey | call | `_v.get('decision', 'allow')` |  |
| `hooks/pre_tool_use.py` | 5505 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5516 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5530 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5549 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5568 | W2-dictkey | literal | `'alert'` |  |
| `hooks/pre_tool_use.py` | 5590 | W2-dictkey | literal | `'config_rejected'` |  |
| `hooks/pre_tool_use.py` | 5607 | W1-kwarg | ifexp | `'block' if h['action'] == 'block' else 'alert'` | 是 |
| `hooks/pre_tool_use.py` | 5615 | W2-dictkey | name | `decision` |  |
| `hooks/pre_tool_use.py` | 5623 | W1-kwarg | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5634 | W2-dictkey | literal | `'allow'` |  |
| `hooks/pre_tool_use.py` | 5735 | W2-dictkey | literal | `'allow'` |  |
| `hooks/session_start_banner.py` | 203 | W2-dictkey | literal | `'allow'` |  |
| `host_shield.py` | 336 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 1715 | W2-dictkey | call | `kw.pop('decision', 'allow')` |  |
| `host_shield.py` | 2650 | W2-dictkey | literal | `'config_skip'` |  |
| `host_shield.py` | 2689 | W2-dictkey | literal | `'config_refresh'` |  |
| `host_shield.py` | 2941 | W2-dictkey | literal | `'config_refresh'` |  |
| `host_shield.py` | 3986 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4034 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4042 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4062 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4086 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 4091 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4113 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 4118 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4940 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 4945 | W1-kwarg | literal | `'alert'` |  |
| `host_shield.py` | 4982 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5021 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5031 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5036 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5084 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5099 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 5116 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 5163 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5183 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5191 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5292 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 5321 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5327 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5337 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5414 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 5446 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5471 | W1-kwarg | literal | `'deny'` |  |
| `host_shield.py` | 5496 | W1-kwarg | literal | `'allow'` |  |
| `host_shield.py` | 5514 | W1-kwarg | literal | `'deny'` |  |
| `inbox_notify.py` | 381 | W2-dictkey | literal | `'allow'` |  |
| `inbox_tray.py` | 358 | W2-dictkey | literal | `'allow'` |  |
| `inbox_tray.py` | 463 | W2-dictkey | literal | `'allow'` |  |
| `scripts/install.py` | 856 | W2-dictkey | literal | `'alert'` |  |
| `scripts/report.py` | 390 | W2-dictkey | boolop | `ev.get('decision') or ev.get('action') or ''` | 是 |
| `scripts/report.py` | 408 | W2-dictkey | literal | `'finding'` |  |
| `scripts/report.py` | 739 | W2-dictkey | subscript | `f['decision']` |  |
| `scripts/verification_tests.py` | 1372 | W2-dictkey | literal | `'allow'` |  |
| `scripts/verification_tests.py` | 1375 | W2-dictkey | literal | `'allow'` |  |
| `scripts/verification_tests.py` | 2748 | W2-dictkey | literal | `'allow'` |  |
| `scripts/verification_tests.py` | 3078 | W2-dictkey | literal | `'block'` |  |
| `scripts/verification_tests.py` | 3098 | W2-dictkey | literal | `'allow'` |  |
| `scripts/verification_tests.py` | 3361 | W2-dictkey | literal | `'allow'` |  |
| `scripts/verification_tests.py` | 3516 | W2-dictkey | literal | `'block'` |  |
| `scripts/verification_tests.py` | 3532 | W2-dictkey | literal | `'block'` |  |
| `scripts/verification_tests.py` | 3640 | W2-dictkey | literal | `'allow'` |  |

## 判据/测试里的写入点（不参与收敛）

- `ci/inbox_guards.py:114` W2-dictkey → `'allow'`
- `ci/inbox_guards.py:123` W2-dictkey → `'block'`
- `ci/inbox_guards.py:304` W1-kwarg → `'allow'`
- `ci/inbox_guards_0353.py:102` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:366` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:723` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1217` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1255` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1279` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1305` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1335` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1407` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1726` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1728` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1787` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:1789` W2-dictkey → `'allow'`
- `ci/inbox_guards_0353.py:3864` W2-dictkey → `'allow'`
- `ci/inbox_guards_0372.py:1376` W2-dictkey → `'allow'`
- `ci/inbox_guards_0400.py:429` W2-dictkey → `'deny'`
- `ci/inbox_guards_0400.py:861` W2-dictkey → `'deny'`
- `ci/inbox_guards_0420.py:97` W2-dictkey → `'allow'`
- `ci/inbox_guards_0420.py:100` W2-dictkey → `'allow'`
- `ci/inbox_guards_0420.py:102` W2-dictkey → `'allow'`
