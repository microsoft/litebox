# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

param(
    [Parameter(Mandatory)][ValidateSet('alone', 'with-python')][string]$Mode,
    [switch]$UnderDebugger
)

$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This investigation requires a disposable GitHub-hosted runner.'
}

$statusFile = "$env:RUNNER_TEMP\node-nextest-$Mode.exit"
$selection = @('--locked', '--profile', 'ci', '-p', 'litebox_runner_linux_on_windows_userland', '--test', 'run')
if ($UnderDebugger) {
    $PSNativeCommandUseErrorActionPreference = $false
    $filter = 'test(=test_node_with_rewriter)'
    if ($Mode -eq 'with-python') { $filter += ' or test(=test_runner_with_python)' }
    cargo nextest run --color never @selection -E $filter --test-threads 2 --stress-duration 20m `
        --retries 0 --fail-fast --no-tests fail --status-level pass --failure-output immediate
    $result = $LASTEXITCODE
    Set-Content -LiteralPath $statusFile -Value $result
    exit $result
}

$cdb = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe"
if (!(Test-Path -LiteralPath $cdb)) {
    $installer = "$env:RUNNER_TEMP\winsdksetup.exe"
    Invoke-WebRequest 'https://go.microsoft.com/fwlink/?linkid=2272610' -OutFile $installer
    $signature = Get-AuthenticodeSignature $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation,') {
        throw 'Invalid Windows SDK installer signature'
    }
    $setup = Start-Process $installer -ArgumentList '/features OptionId.WindowsDesktopDebuggers /quiet /norestart' -Wait -PassThru
    if ($setup.ExitCode -notin 0,3010) { throw "Windows debugger setup exited $($setup.ExitCode)" }
}

cargo nextest run @selection --no-run
if ($LASTEXITCODE) { exit $LASTEXITCODE }
if (Test-Path -LiteralPath $statusFile) { Remove-Item -LiteralPath $statusFile }

# The platform handles first-chance access violations. Only collect an exception
# that escaped those handlers, then pass it on so nextest sees the real exit.
$commands = "$env:RUNNER_TEMP\node-cdb.txt"
@'
sxi ld
sxi ud
sxi cpr
sxi ibp
sxi -c2 ".echo === Unhandled access violation ===; |.; ~.; .exr -1; r; ln @rip; u @rip L1; ~* k; gn" av
g
'@ | Set-Content -Encoding ascii -LiteralPath $commands
$pwsh = (Get-Command pwsh -CommandType Application).Source
& $cdb -o -G -hd -lines -y "$PWD\target\debug;$PWD\target\debug\deps" -cf $commands `
    $pwsh -NoLogo -NoProfile -NonInteractive -File $PSCommandPath -Mode $Mode -UnderDebugger
if (!(Test-Path -LiteralPath $statusFile)) {
    throw "Debugger exited $LASTEXITCODE before nextest recorded a result"
}
exit [int](Get-Content -Raw -LiteralPath $statusFile)
