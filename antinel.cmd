@echo off
REM SPDX-License-Identifier: Apache-2.0
REM ---------------------------------------------------------------------------
REM Antinel guard console - one-click entry
REM
REM Why this file is ASCII-only + CRLF (measured 2026-10-14, see
REM ci/inbox_guards_0515.py): cmd.exe reads .cmd files in the console OEM
REM codepage. On a Chinese system (CP936) UTF-8 Chinese inside REM comments is
REM byte-misaligned into fragments that cmd tries to EXECUTE -- CRLF alone does
REM not save it (probe: zh-comments + CRLF at CP936 => fragments executed).
REM ASCII content is the only machine-independent safe form. The full Chinese
REM rationale lives in ci/inbox_guards_0515.py and inbox_cli.py docstrings.
REM
REM What it does (all logic delegated to the CLI, no reimplementation):
REM   1. `antinel inbox daemon --supervise`: resident daemon (singleton; it also
REM      checks the console service every 15s and re-pulls it on the recorded
REM      port/token if it was killed => URL unchanged);
REM   2. `antinel inbox window`: ensure the service is running, then open an
REM      independent window (app mode).
REM
REM Closing the window does NOT stop the service; double-click again => same
REM URL, window reopens. To stop the resident daemon: end the "antinel-daemon"
REM cmd in Task Manager (this file installs no scheduled task / service /
REM registry entry -- such persistence must be done by you explicitly).
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PY=python"
where %PY% >nul 2>nul
if errorlevel 1 (
    echo [antinel] python not found on PATH -- install Python 3.11+ and add it to PATH.
    exit /b 3
)

REM 1. daemon: singleton (a second copy exits quietly), starts minimized
start "antinel-daemon" /min cmd /c "%PY% antinel.py inbox daemon --supervise --interval 2"

REM 2. ensure the service is running + open an independent window (foreground)
%PY% antinel.py inbox window
set RC=%ERRORLEVEL%

endlocal & exit /b %RC%
