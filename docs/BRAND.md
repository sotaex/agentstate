# Antinel 品牌架构 v1.0（2026-09-23 定稿）

**Antinel** = 母品牌（公司/信任伞）。

| 产品线 | 粒度/域 | 首条产品 |
|---|---|---|
| **AgentState** | Agent 行为状态（连续） | 本仓：行为审计 + 账本（原 Antinel Security Suite） |
| **DayState** | 按日公共状态 | BTC 日度链上计量（psl.antinel.com）；**未来所有按日产品均归 DayState 线** |

命名规范：产品线名驼峰（AgentState/DayState）；格式/包/服务名小写（agentstate/daystate）；
CLI 命令保留 `antinel`（短，类 gcloud 惯例）。
