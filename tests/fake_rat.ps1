# harmless stand-in for rat-style persistence, used to sanity check ratwatch
# without needing an actual malware sample lying around. all it does:
#  1. drops a copy of notepad into appdata under a weird name
#  2. adds a run key pointing at it
#  3. starts a dummy process (just ping, looping) with a parent that looks
#     like word, by literally renaming a copy of cmd.exe to winword.exe
#     and using it to launch things - nothing here actually touches word
#
# run tests/cleanup_fake_rat.ps1 afterwards to undo everything.
# meant to be run inside the throwaway vm, not a real machine.

$dropName = "svchost_update.exe"
$dropDir = "$env:APPDATA\SystemCache"
New-Item -ItemType Directory -Force -Path $dropDir | Out-Null
Copy-Item "$env:WINDIR\System32\notepad.exe" "$dropDir\$dropName" -Force

Write-Host "dropped fake payload at $dropDir\$dropName"

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $runKeyPath -Name "SystemCacheUpdate" -Value "$dropDir\$dropName"

Write-Host "added run key SystemCacheUpdate"

# fake the office-spawns-shell pattern by making a renamed cmd.exe play
# the part of winword.exe, then having it launch powershell. purely for
# testing the parent/child detector, doesn't touch the real office apps.
$fakeOfficeDir = "$env:TEMP\fakeoffice"
New-Item -ItemType Directory -Force -Path $fakeOfficeDir | Out-Null
Copy-Item "$env:WINDIR\System32\cmd.exe" "$fakeOfficeDir\WINWORD.EXE" -Force

Start-Process -FilePath "$fakeOfficeDir\WINWORD.EXE" -ArgumentList "/c powershell -Command `"Start-Sleep -Seconds 120`""

Write-Host "started fake winword.exe -> powershell chain (will sit for 2 min, kill it manually if needed)"
Write-Host ""
Write-Host "now run ratwatch.exe scan and you should see at least 3 findings:"
Write-Host " - new autorun entry: SystemCacheUpdate"
Write-Host " - process running from a drop-style folder (the fake svchost_update.exe)"
Write-Host " - WINWORD.EXE spawned powershell.exe"
