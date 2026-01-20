# ============================
# Watson Toolkit - Low Visibility Triage (XSIAM Friendly)
# - No Desktop output
# - Minimal console output
# - Writes to ProgramData
# ============================
# Author: Jason Wall
# Date: January 20, 2026

$ReportTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutDir = "C:\ProgramData\Watson_Triage_$ReportTime"
New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

# --- Full Process Inventory (with directory) ---
$procInventory = Get-Process | ForEach-Object {
  $path = $null
  $folder = $null

  try {
    $path = $_.Path
    if ($path) { $folder = Split-Path -Path $path -Parent }
  } catch {}

  [PSCustomObject]@{
    Name       = $_.ProcessName
    Id         = $_.Id
    CPU        = $_.CPU
    WS_MB      = [Math]::Round(($_.WorkingSet64 / 1MB), 2)
    Path       = $path
    FolderPath = $folder
  }
}

$procInventory |
  Sort-Object CPU -Descending |
  Export-Csv "$OutDir\Processes_FullInventory.csv" -NoTypeInformation

# --- Network Connections (Established) + PID mapping ---
Get-NetTCPConnection |
  Where-Object { $_.State -eq "Established" } |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
  Export-Csv "$OutDir\Network_Established.csv" -NoTypeInformation

$net = Import-Csv "$OutDir\Network_Established.csv"
$mapped = foreach ($c in $net) {
  $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
  $pPath = $null
  $pFolder = $null

  try {
    $pPath = $p.Path
    if ($pPath) { $pFolder = Split-Path -Path $pPath -Parent }
  } catch {}

  [PSCustomObject]@{
    Local       = "$($c.LocalAddress):$($c.LocalPort)"
    Remote      = "$($c.RemoteAddress):$($c.RemotePort)"
    PID         = $c.OwningProcess
    ProcessName = $p.ProcessName
    FolderPath  = $pFolder
    Path        = $pPath
  }
}
$mapped | Export-Csv "$OutDir\Network_MappedToProcess.csv" -NoTypeInformation

# --- Persistence: Run keys ---
@(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
) | ForEach-Object {
  "`n=== $_ ===" | Out-File "$OutDir\Persistence_RunKeys.txt" -Append
  Get-ItemProperty $_ -ErrorAction SilentlyContinue |
    Out-String | Out-File "$OutDir\Persistence_RunKeys.txt" -Append
}

# --- Scheduled Tasks (basic) ---
Get-ScheduledTask |
  Select-Object TaskName, TaskPath, State |
  Out-File "$OutDir\ScheduledTasks_Basic.txt"

# No Write-Host
