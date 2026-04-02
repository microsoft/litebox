@echo off
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

REM If arguments were passed, run in direct mode.
REM If no arguments, launch an interactive busybox shell.
if "%~1"=="" (
    "%EXECUTOR%" %ARGS% /bin/busybox sh
) else (
    "%EXECUTOR%" %ARGS% /bin/busybox sh -c %*
)

REM Redirect audit log if requested.
REM Note: audit events go to stderr. To capture them:
REM   litebox-shell.cmd "echo hello" 2>>%LITEBOX_AUDIT%
