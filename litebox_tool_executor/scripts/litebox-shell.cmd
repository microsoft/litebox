@echo off
setlocal EnableDelayedExpansion
REM Copyright (c) Microsoft Corporation.
REM Licensed under the MIT license.
REM
REM Shell wrapper for LiteBox tool executor.
REM Designed to be used as a VS Code terminal profile so that coding agents
REM (e.g., Copilot agent mode) run commands inside a LiteBox sandbox.
REM
REM Environment variables:
REM   LITEBOX_ROOTFS   - Path to the rootfs .tar  (required)
REM   LITEBOX_POLICY   - Path to a JSON policy file (optional)
REM   LITEBOX_AUDIT    - Path to write audit log    (optional)
REM
REM Usage as a VS Code terminal profile:
REM   "terminal.integrated.profiles.windows": {
REM       "LiteBox Sandbox": {
REM           "path": "C:\\path\\to\\litebox-shell.cmd",
REM           "env": { "LITEBOX_ROOTFS": "C:\\path\\to\\busybox-minimal.tar" }
REM       }
REM   }

if "%LITEBOX_ROOTFS%"=="" (
    echo ERROR: LITEBOX_ROOTFS environment variable must point to a rootfs .tar file.
    exit /b 1
)

REM Locate the executor binary: check workspace target dirs, then PATH.
set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%..\.."
if exist "%REPO_ROOT%\target\debug\litebox_tool_executor.exe" (
    set "EXECUTOR=%REPO_ROOT%\target\debug\litebox_tool_executor.exe"
) else if exist "%REPO_ROOT%\target\release\litebox_tool_executor.exe" (
    set "EXECUTOR=%REPO_ROOT%\target\release\litebox_tool_executor.exe"
) else (
    set "EXECUTOR=litebox_tool_executor.exe"
)

REM Build the command line.
set "ARGS=--rootfs "%LITEBOX_ROOTFS%""

if not "%LITEBOX_POLICY%"=="" (
    set "ARGS=%ARGS% --policy "%LITEBOX_POLICY%""
)

REM Audit events and debug messages go to stderr. In interactive mode this
REM floods the terminal, so we redirect stderr to a log file.
REM Set LITEBOX_AUDIT to control where the log goes, or leave it unset for
REM a default location next to the rootfs tar.
if "%LITEBOX_AUDIT%"=="" (
    set "LITEBOX_AUDIT=%LITEBOX_ROOTFS%.audit.jsonl"
)

REM Interactive REPL mode: each line the user (or agent) types is run as a
REM separate LiteBox invocation. This avoids the need for fork(), which is not
REM yet implemented. Each command gets a fresh sandbox.
if "%~1"=="" (
    goto :repl
) else (
    set "CMD=%~1"
    "%EXECUTOR%" %ARGS% /bin/busybox sh -c "!CMD!" 2>>"%LITEBOX_AUDIT%"
    echo.
    echo [LiteBox] Audit log: %LITEBOX_AUDIT%
    goto :eof
)

:repl
echo LiteBox Sandbox Shell (each command runs in a fresh sandbox)
echo Type 'exit' to quit. Commands are executed via busybox.
echo.
:prompt
set "CMD="
set /p "CMD=/ $ "
if /i "!CMD!"=="exit" goto :eof
if "!CMD!"=="" goto :prompt
REM Use a temporary file to avoid CMD quote-mangling issues with
REM double quotes inside the user's command.
echo !CMD!> "%TEMP%\litebox_cmd.txt"
set /p CMDLINE=<"%TEMP%\litebox_cmd.txt"
"%EXECUTOR%" %ARGS% /bin/busybox sh -c "!CMDLINE!" 2>>"%LITEBOX_AUDIT%"
goto :prompt
