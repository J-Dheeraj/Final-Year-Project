@echo off
:: Runs cve_watcher.py silently in the background.
:: Double-click or launch from Task Scheduler — no console window stays open.

cd /d "%~dp0"
start "" /b pythonw -u cve_watcher.py --no-probe --format text --workers 2 >> watcher_boot.log 2>&1
