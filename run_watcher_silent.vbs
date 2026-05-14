' Launches CVE Watcher silently at Windows startup.
' Put a shortcut to this file in your Startup folder.

Dim wsh, scriptDir, cmd
Set wsh = CreateObject("WScript.Shell")

scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
scriptDir = Left(scriptDir, Len(scriptDir) - 1)   ' strip trailing backslash

cmd = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass " & _
      "-File """ & scriptDir & "\start_watcher.ps1"""

wsh.Run cmd, 0, False
Set wsh = Nothing
