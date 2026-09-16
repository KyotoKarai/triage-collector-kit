<#
.SYNOPSIS
    Triage Collector Kit - Windows collector.
.DESCRIPTION
    Collects incident response artifacts from a Windows host:
    processes, network connections, services, scheduled tasks,
    local administrators, event logs, short network trace, file hashes.
.NOTES
    Run as Administrator for full collection.
    The script is read-only: it only collects data, it does not modify the system.
#>

# --- 0. Settings ---
$PcapSeconds = 15

# --- 1. Admin check ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some artifacts (Security log, network trace) may be unavailable."
}

# --- 2. Output directory ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME
$outDir    = Join-Path -Path $PWD -ChildPath "Triage_${hostname}_${timestamp}"
New-Item -ItemType Directory -Path $outDir | Out-Null

$timelineFile = Join-Path $outDir "00_Timeline_Summary.txt"
"=== TRIAGE COLLECTION SUMMARY ===" | Out-File $timelineFile
"Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $timelineFile -Append
"Host    : $hostname" | Out-File $timelineFile -Append
"Admin   : $isAdmin" | Out-File $timelineFile -Append

Write-Host "=== TRIAGE COLLECTION STARTED ===" -ForegroundColor Cyan
Write-Host "Output: $outDir"

# --- 3. Processes ---
# Get-CimInstance Win32_Process gives CommandLine and ParentProcessId,
# which Get-Process does not provide reliably. This is critical for SOC analysis.
Write-Host "[1/7] Processes..."
Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId,
        @{Name="Owner";Expression={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}},
        CreationDate |
    Sort-Object CreationDate |
    Export-Csv -Path (Join-Path $outDir "01_Processes.csv") -NoTypeInformation -Encoding UTF8
"Processes collected" | Out-File $timelineFile -Append

# --- 4. Network connections ---
Write-Host "[2/7] Network connections..."
Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
        @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Export-Csv -Path (Join-Path $outDir "02_NetworkConnections.csv") -NoTypeInformation -Encoding UTF8
"Network connections collected" | Out-File $timelineFile -Append

# --- 5. Services and scheduled tasks ---
Write-Host "[3/7] Services and scheduled tasks..."
Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' } |
    Select-Object Name, DisplayName, State, StartName, PathName |
    Export-Csv -Path (Join-Path $outDir "03_Services_Auto.csv") -NoTypeInformation -Encoding UTF8

Get-ScheduledTask |
    Where-Object { $_.State -ne 'Disabled' } |
    Select-Object TaskName, TaskPath, State,
        @{Name="Actions";Expression={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}} |
    Export-Csv -Path (Join-Path $outDir "04_ScheduledTasks.csv") -NoTypeInformation -Encoding UTF8
"Services and tasks collected" | Out-File $timelineFile -Append

# --- 6. Local administrators ---
Write-Host "[4/7] Local administrators..."
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Select-Object Name, PrincipalSource, ObjectClass |
    Export-Csv -Path (Join-Path $outDir "05_LocalAdmins.csv") -NoTypeInformation -Encoding UTF8
"Local admins collected" | Out-File $timelineFile -Append

# --- 7. Event logs export ---
# wevtutil epl copies the binary EVTX natively and fast.
# Converting through Get-WinEvent would be slow and lossy on big logs.
Write-Host "[5/7] Event logs export..."
$logsToCollect = @(
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-PrintService/Admin",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
)
$logList = wevtutil el
foreach ($log in $logsToCollect) {
    $safeName = $log -replace '/', '_' -replace '-', '_'
    $evtxPath = Join-Path $outDir "Log_${safeName}.evtx"
    if ($logList -contains $log) {
        wevtutil epl $log $evtxPath /overwrite | Out-Null
        Write-Host "   [+] $log"
    } else {
        Write-Host "   [-] $log (not present)" -ForegroundColor DarkGray
    }
}
"Event logs exported" | Out-File $timelineFile -Append

# --- 8. Network trace ---
# netsh trace is built into Windows, no third-party capture driver needed.
Write-Host "[6/7] Network trace (${PcapSeconds}s)..."
$etlPath = Join-Path $outDir "06_NetworkTrace.etl"
netsh trace start capture=yes tracefile=$etlPath maxSize=50 report=disabled | Out-Null
Start-Sleep -Seconds $PcapSeconds
netsh trace stop | Out-Null
"Network trace captured" | Out-File $timelineFile -Append

# --- 9. Integrity hashes ---
Write-Host "[7/7] SHA256 hashes..."
$hashFile = Join-Path $outDir "07_FileHashes_SHA256.txt"
Get-ChildItem -Path $outDir -File |
    Where-Object { $_.Name -ne "07_FileHashes_SHA256.txt" } |
    Get-FileHash -Algorithm SHA256 |
    Format-List |
    Out-File $hashFile

"Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $timelineFile -Append

Write-Host "=== COLLECTION FINISHED ===" -ForegroundColor Green
Write-Host "Output: $outDir" -ForegroundColor Yellow
