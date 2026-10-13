@echo off
REM SPDX-License-Identifier: Apache-2.0
REM ---------------------------------------------------------------------------
REM Antinel 值守台 · 一键入口（0.48.5 B1）
REM
REM 为什么要有它（遗留问题清单 2026-10-13 B1）：
REM   值守台原来是"会话里拉的前台进程"—— 会话一结束服务就没了，窗口还开着，
REM   点一下全是失败。用户要的是一步就能"服务常驻 + 开独立窗口"。
REM
REM 做两件事（都不自己实现逻辑，全部委托 CLI）：
REM   ① `antinel inbox daemon --supervise`：守护进程（单例；顺带每 15 秒判一次
REM      值守台服务的活，被杀掉就按**记录里的原端口/口令**重拉 ⇒ URL 不变）；
REM   ② `antinel inbox window`：确保服务在跑，再开独立窗口（app 模式）。
REM
REM 关掉窗口**不会**带走服务；再双击本文件 ⇒ URL 不变、窗口重新开出来。
REM 卸载常驻：任务管理器结束 "antinel-daemon" 那个 cmd 即可（本文件不装任何
REM 计划任务/服务/注册表项 —— 那类持久化按本仓纪律必须由你本人显式操作）。
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PY=python"
where %PY% >nul 2>nul
if errorlevel 1 (
    echo [antinel] 找不到 python（PATH 里没有）—— 请先装 Python 3.11+ 并加进 PATH。
    exit /b 3
)

REM ① 守护进程：单例（已在跑时第二份会自己安静退出），最小化窗口起
start "antinel-daemon" /min cmd /c "%PY% antinel.py inbox daemon --supervise --interval 2"

REM ② 确保服务在跑 + 开独立窗口（前台等它开完）
%PY% antinel.py inbox window
set RC=%ERRORLEVEL%

endlocal & exit /b %RC%
