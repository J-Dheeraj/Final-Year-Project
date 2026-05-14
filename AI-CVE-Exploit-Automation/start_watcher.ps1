# start_watcher.ps1
# Starts cve_watcher.py as a hidden background process.
# Output goes to watcher_stdout.log and watcher_stderr.log.
# Automatically placed in Startup folder by run_watcher_silent.vbs.

$dir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$outLog  = Join-Path $dir "watcher_stdout.log"
$errLog  = Join-Path $dir "watcher_stderr.log"
$pidFile = Join-Path $dir "watcher.pid"

# Kill any already-running instance
if (Test-Path $pidFile) {
    $oldPid = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($oldPid) {
        Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
    }
}

$proc = Start-Process python `
    -ArgumentList "-u", "cve_watcher.py", "--no-probe", "--format", "text", "--workers", "2" `
    -WorkingDirectory $dir `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError  $errLog `
    -WindowStyle Hidden `
    -PassThru

if ($proc) {
    $proc.Id | Out-File $pidFile -Encoding ascii
}
