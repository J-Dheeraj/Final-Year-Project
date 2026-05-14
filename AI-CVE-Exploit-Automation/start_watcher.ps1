# start_watcher.ps1
# Starts cve_watcher.py as a hidden background process.
# Full output (stdout + stderr) is recorded to watcher_stderr.log.
# Probes are ENABLED — every CVE gets full pass/fail + bypass analysis.
# A transcript of this launch session is saved to launch_transcript.log.

$dir        = Split-Path -Parent $MyInvocation.MyCommand.Path
$errLog     = Join-Path $dir "watcher_stderr.log"
$outLog     = Join-Path $dir "watcher_stdout.log"
$pidFile    = Join-Path $dir "watcher.pid"
$transcript = Join-Path $dir "launch_transcript.log"

# Start transcript so everything printed here is saved
Start-Transcript -Path $transcript -Append -NoClobber:$false | Out-Null

Write-Host "========================================================"
Write-Host "  CVE Watcher — Full Probe Mode"
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "========================================================"

# Kill any already-running instance
if (Test-Path $pidFile) {
    $oldPid = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($oldPid) {
        $running = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
        if ($running) {
            Write-Host "Stopping previous watcher (PID $oldPid)..."
            Stop-Process -Id $oldPid -Force
            Start-Sleep -Seconds 1
        }
    }
}

# Clear old logs so fresh run is clean
"" | Out-File $outLog -Encoding utf8
"" | Out-File $errLog -Encoding utf8

# Launch watcher — probes ON, 2 workers, text format
$proc = Start-Process python `
    -ArgumentList "-u", "cve_watcher.py", "--format", "text", "--workers", "2" `
    -WorkingDirectory $dir `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError  $errLog `
    -WindowStyle Hidden `
    -PassThru

if ($proc) {
    $proc.Id | Out-File $pidFile -Encoding ascii
    Write-Host "Watcher started — PID $($proc.Id)"
    Write-Host "Probes     : ENABLED (SSRF, SQLi, XSS, CMDi, Path Traversal, Deserialization)"
    Write-Host "Bypass     : Theoretical + live tests against patched mode"
    Write-Host "Reports    : $dir\reports\"
    Write-Host "Probe log  : $errLog"
    Write-Host "Transcript : $transcript"
    Write-Host ""

    # Tail the log for 30s so user sees the first poll live
    Write-Host "--- Live output (first 30s) ---"
    $deadline = (Get-Date).AddSeconds(30)
    $lastSize = 0
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        if (Test-Path $errLog) {
            $content = Get-Content $errLog -Raw -ErrorAction SilentlyContinue
            if ($content -and $content.Length -gt $lastSize) {
                $newLines = $content.Substring($lastSize)
                Write-Host $newLines -NoNewline
                $lastSize = $content.Length
            }
        }
    }
    Write-Host ""
    Write-Host "--- Watcher is running in the background ---"
    Write-Host "Check reports\  for CVE output files."
    Write-Host "Run: Get-Content '$errLog' -Tail 30  to see latest activity."
} else {
    Write-Host "ERROR: Failed to start watcher process."
}

Stop-Transcript | Out-Null
