Option Explicit

Dim shell
Dim psCommand

Set shell = CreateObject("WScript.Shell")

psCommand = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\OpsCheck\scripts\poc_health_report.ps1"""

' 0 = hidden window, False = do not wait
shell.Run psCommand, 0, False
