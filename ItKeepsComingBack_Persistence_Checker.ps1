<#
.SYNOPSIS
  Persistence sweep for common Windows autorun mechanisms.

.DESCRIPTION
  Comprehensive blue team persistence checker that scans Windows systems for common
  persistence mechanisms used by attackers. Enumerates and exports all persistence
  indicators from registry autorun keys, startup folders, scheduled tasks, services,
  WMI event subscriptions, and IFEO debugger entries.
  
  Collects:
  - Run / RunOnce keys (HKCU/HKLM + Wow6432Node)
  - Startup folders (common + per-user)
  - Scheduled tasks (name/path + action command/args/user)
  - Services (image path + start type + account)
  - WMI event subscriptions (if accessible)
  - IFEO debugger (common abuse)

  Output:
  - CSV (easy to sort/filter)
  - JSON (easy to ingest)

.AUTHOR
  Jason Wall

.NOTES
  Designed for blue team triage / IR. Read-only.
#>

param(
  [string]$OutDir = "C:\ProgramData\PersistAndPerish_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')",
  [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

function Write-Note($msg) {
  if (-not $Quiet) { Write-Host $msg }
}

function Add-Result {
  param(
    [string]$Category,
    [string]$Location,
    [string]$Name,
    [string]$Value,
    [string]$User = "",
    [string]$Extra = ""
  )
  [PSCustomObject]@{
    Timestamp = (Get-Date).ToString("s")
    Category  = $Category
    Location  = $Location
    Name      = $Name
    Value     = $Value
    User      = $User
    Extra     = $Extra
  }
}

New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]

# -------------------------
# 1) Run / RunOnce Keys
# -------------------------
$runKeyPaths = @(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $runKeyPaths) {
  $item = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
  if (-not $item) { continue }

  foreach ($p in $item.PSObject.Properties) {
    if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
    $results.Add((Add-Result -Category "RegistryRun" -Location $path -Name $p.Name -Value ($p.Value | Out-String).Trim()))
  }
}

# -------------------------
# 2) Startup Folders
# -------------------------
$startupPaths = @(
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
  "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($sp in $startupPaths) {
  if (-not (Test-Path $sp)) { continue }
  Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue | ForEach-Object {
    $results.Add((Add-Result -Category "StartupFolder" -Location $sp -Name $_.Name -Value $_.FullName))
  }
}

# -------------------------
# 3) Scheduled Tasks (with actions)
# -------------------------
try {
  Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
    $task = $_
    $taskName = $task.TaskName
    $taskPath = $task.TaskPath
    $principal = $null
    try { $principal = $task.Principal.UserId } catch { $principal = "" }

    # Actions can be multiple; capture command + args when present
    foreach ($a in ($task.Actions | ForEach-Object { $_ })) {
      $cmd  = ""
      $args = ""
      try { $cmd = $a.Execute } catch {}
      try { $args = $a.Arguments } catch {}

      $value = ($cmd + " " + $args).Trim()
      $extra = "State=$($task.State)"
      $results.Add((Add-Result -Category "ScheduledTask" -Location ($taskPath) -Name $taskName -Value $value -User $principal -Extra $extra))
    }
  }
} catch {
  $results.Add((Add-Result -Category "ScheduledTask" -Location "Get-ScheduledTask" -Name "ERROR" -Value $_.Exception.Message))
}

# -------------------------
# 4) Services (ImagePath + StartMode + Account)
# -------------------------
try {
  Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
    $svc = $_
    $value = ($svc.PathName | Out-String).Trim()
    $extra = "StartMode=$($svc.StartMode); State=$($svc.State)"
    $results.Add((Add-Result -Category "Service" -Location "Win32_Service" -Name $svc.Name -Value $value -User $svc.StartName -Extra $extra))
  }
} catch {
  $results.Add((Add-Result -Category "Service" -Location "Win32_Service" -Name "ERROR" -Value $_.Exception.Message))
}

# -------------------------
# 5) IFEO Debugger (often abused)
# -------------------------
$ifeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoBase) {
  Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue | ForEach-Object {
    $sub = $_.PsPath
    $dbg = (Get-ItemProperty -Path $sub -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
    if ($dbg) {
      $results.Add((Add-Result -Category "IFEO" -Location $ifeoBase -Name $_.PSChildName -Value $dbg))
    }
  }
}

# -------------------------
# 6) WMI Event Subscriptions (advanced persistence)
# -------------------------
try {
  $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop
  foreach ($f in $filters) {
    $results.Add((Add-Result -Category "WMI_EventFilter" -Location "root\subscription" -Name $f.Name -Value ($f.Query | Out-String).Trim()))
  }

  $consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
  foreach ($c in $consumers) {
    $results.Add((Add-Result -Category "WMI_Consumer" -Location "root\subscription" -Name $c.Name -Value ($c.CommandLineTemplate | Out-String).Trim()))
  }

  $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
  foreach ($b in $bindings) {
    $results.Add((Add-Result -Category "WMI_Binding" -Location "root\subscription" -Name "Binding" -Value ($b.Filter + " -> " + $b.Consumer)))
  }
} catch {
  # Access may be blocked; that's ok
  $results.Add((Add-Result -Category "WMI" -Location "root\subscription" -Name "INFO" -Value "WMI subscription query failed or not accessible in this context."))
}

# -------------------------
# Output
# -------------------------
$csvPath  = Join-Path $OutDir "PersistAndPerish.csv"
$jsonPath = Join-Path $OutDir "PersistAndPerish.json"

$results |
  Sort-Object Category, Location, Name |
  Export-Csv -Path $csvPath -NoTypeInformation

$results |
  Sort-Object Category, Location, Name |
  ConvertTo-Json -Depth 5 |
  Out-File -FilePath $jsonPath -Encoding utf8

Write-Note "✅ Done. Output:"
Write-Note "  $csvPath"
Write-Note "  $jsonPath"
