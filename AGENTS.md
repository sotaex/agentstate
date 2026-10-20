<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# 给并行工作的 AI：先读这一份

**开工前读最好，中途读到也照做** —— 下面这四条是自包含的，不需要你读过别的。

本仓库**常有两条以上 AI 同时改代码**：主工作区（分支 `main`）＋ `.worktrees/night`（分支 `night-t1t5`）＋ `.worktrees/b`（分支 `stream-b`）。

**完整约定（含为什么、检查清单、共享文件表、冲突处置）**：
`docs/Antinel·并行协作约定 v1.0（2026-10-21）.md`

## 四条（照做即可）

1. **有自己的 worktree，就在自己的 worktree 里改**；不写主工作区、不提交进 `main`。
2. **提交只 `git add` 你改的那几个具体文件** —— 禁用 `git add -A`／`git commit -a`。
3. **共享文件动之前先知会一声**：`inbox_server.py`、`inbox_report.py`、`ci/inbox_guards_0514.py`、`psl/manifest.json`、`assets/logo/antinel.ico`。
4. **在飞改动不许裸在工作区**：要暂停／收工就 `git switch -c wip/<线>-<日期>` 提交一次。

## 为什么要这四条

损失只发生在**"谁有未提交改动"的那段窗口里**。2026-10-21 02:50 实测：一条线从主工作区提交进 `main`（4 个文件），而另一条线的在飞改动就在同一个目录里——这次没丢，是因为那一条线的批次已经先提交了。把窗口压到零，就没有事会丢。
