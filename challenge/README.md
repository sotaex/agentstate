# 篡改挑战 · Try to fool the auditor

> **这是一条真实的 Antinel 审计链：14 条记录，其中 3 条是当场拦截的危险操作。**
> 规则很简单——**改掉任何记录里的任何字符，骗过验证器，就算你赢。**

## 挑战步骤（三条命令，Python 标准库，零依赖）

```bash
# 1) 验证原始链是完好的
python verify.py
#    → verdict: CLEAN — 链完好，未被改动

# 2) 动手：把第 2 条记录里的 'echo hello' 改成 'fcHo hello'（同长度，JSON 仍合法）
python tamper.py

# 3) 验证器当场指出改的是哪一条
#    → !! L2: 自哈希不符 → 该记录内容被改动过（EDITED）
#    → verdict: TAMPERED — 检出篡改
```

不满意这个改法？随便换：改时间戳、改命令文本、改severity、删一整条、
在中间插一条自己算好 hash 的假记录——验证器在 `verify.py`，总共 60 行，
**读懂它你就能构造任何攻击**。构造出来算你赢，欢迎提 Issue。

## 为什么改不动

每条记录的 `hash = sha256(前一条的完整 hash + 本条内容的规范化 JSON)`。
改任何一个字符 → 本条 hash 对不上；重算本条 hash → 与下一条的 `prev` 对不上；
全链重算 → 末行 hash 与链外的 `day_manifest.json`（日锚）对不上。
**要无声无息地改一条记录，你必须伪造从那条到今天的整条链，外加链外锚。**

## 这条链是怎么来的

`generate_challenge.py` 在一次性沙箱里用**真实的 Antinel 钩子**跑了 7 个事件
（含 `rm -rf`、读 SSH 私钥、读带提示注入的 SKILL.md——3 个被当场拦截），
钩子一边拦截一边把每次调用写进这条链。**它不是示例数据，是真实运行的产物。**

## 格式

记录的字段级契约见 [chain/meta.json](chain/meta.json) 与 Antinel 的 AUDIT_SCHEMA。
链的算术只有两行，任何人可以独立实现验证器（本目录的 `verify.py` 就是一个）。

---

*AgentState（Antinel 旗下行为审计线）—— 你的 Agent 昨晚干了什么、花了多少、拦了什么。本地运行，零上云，逐条可复算。*
