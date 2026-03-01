Option Explicit

Dim shell
Dim psCommand

Set shell = CreateObject("WScript.Shell")
psCommand = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\OpsCheck\Scripts\update_opscheck_from_github.ps1"" -AccessMode private -RepoOwner ""1500man"" -RepoName ""OpsCheck"" -Branch ""main"""

' 0 = hidden window, False = do not wait
shell.Run psCommand, 0, False
