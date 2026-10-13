# undoes everything fake_rat.ps1 did. run this after you're done testing.

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SystemCacheUpdate" -ErrorAction SilentlyContinue

Remove-Item -Recurse -Force "$env:APPDATA\SystemCache" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:TEMP\fakeoffice" -ErrorAction SilentlyContinue

Get-Process -Name "WINWORD" -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*fakeoffice*"
} | Stop-Process -Force -ErrorAction SilentlyContinue

Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {
    $_.StartTime -gt (Get-Date).AddMinutes(-5)
} | ForEach-Object {
    Write-Host "heads up, found a recent powershell process (pid $($_.Id)), not killing automatically, check it's the test one before closing"
}

Write-Host "cleanup done"
