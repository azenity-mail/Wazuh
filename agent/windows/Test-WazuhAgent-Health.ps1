# ==========================
# Wazuh - Health Check (Windows)
# ==========================
$ErrorActionPreference = "Continue"

$BaseDir = "C:\TempFolder\Wazuh"
$LogDir  = Join-Path $BaseDir "Logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$hostname = $env:COMPUTERNAME
$stamp    = (Get-Date).ToString("yyyyMMdd-HHmmss")
$logFile  = Join-Path $LogDir ("Wazuh_Health_{0}_{1}.log" -f $hostname,$stamp)

function Write-Log {
  param([string]$Message,[string]$Level="INFO")
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
  $line = "[{0}] [{1}] {2}" -f $ts,$Level,$Message
  $line | Tee-Object -FilePath $logFile -Append | Out-Null
  Write-Host $line
}

function Get-PrimaryIPv4 {
  try {
    $cfg = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" |
      Where-Object { $_.IPAddress } | Select-Object -First 1
    if($cfg -and $cfg.IPAddress){
      $ip = $cfg.IPAddress | Where-Object { $_ -and ($_ -notlike "169.254.*") -and ($_ -ne "127.0.0.1") } | Select-Object -First 1
      return $ip
    }
  } catch {}
  return $null
}

function Test-Tcp {
  param([string]$Host,[int]$Port,[int]$TimeoutMs=3000)
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($Host,$Port,$null,$null)
    $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs,$false)
    if($ok -and $client.Connected){
      $client.EndConnect($iar) | Out-Null
      $client.Close()
      return $true
    }
    $client.Close()
  } catch {}
  return $false
}

# ===== HEADER =====
Write-Log "==== WAZUH HEALTH CHECK - INÍCIO ===="
Write-Log ("Hostname: {0}" -f $hostname)
Write-Log ("IP Primário: {0}" -f (Get-PrimaryIPv4))
Write-Log ("Data/Hora: {0}" -f (Get-Date))
Write-Log ("PowerShell: {0}" -f $PSVersionTable.PSVersion)

# ===== TARGETS =====
$destIP  = "3.19.177.148"
$manager = "ls8lj27cyp3a.cloud.wazuh.com"
$ports   = 1514,1515,55000

Write-Log "Targets: IP=$destIP | FQDN=$manager | Portas=$($ports -join ',')" "INFO"

# DNS evidence
try {
  $ips = Resolve-DnsName $manager -ErrorAction Stop | Where-Object {$_.IPAddress} | Select-Object -ExpandProperty IPAddress
  Write-Log ("DNS {0} -> {1}" -f $manager,($ips -join ", ")) "INFO"
} catch {
  Write-Log ("DNS falhou para {0}: {1}" -f $manager,$_.Exception.Message) "WARN"
}

# Connectivity tests (TcpClient)
Write-Log "Testes TCP (socket) - IP fixo:" "INFO"
foreach($p in $ports){
  $ok = Test-Tcp -Host $destIP -Port $p
  Write-Log ("{0}:{1} Tcp={2}" -f $destIP,$p,$ok) ($(if($ok){"OK"}else{"WARN"}))
}

Write-Log "Testes TCP (socket) - FQDN (caminho real do agente):" "INFO"
foreach($p in $ports){
  $ok = Test-Tcp -Host $manager -Port $p
  Write-Log ("{0}:{1} Tcp={2}" -f $manager,$p,$ok) ($(if($ok){"OK"}else{"WARN"}))
}

# ===== SERVICE =====
Write-Log "Serviço WazuhSvc:" "INFO"
try {
  $svc = Get-Service -Name WazuhSvc -ErrorAction Stop
  Write-Log ("Status atual: {0}" -f $svc.Status) "INFO"

  $svcWmi = Get-WmiObject Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
  if($svcWmi){
    Write-Log ("StartMode={0} | State={1} | ExitCode={2} | Path={3}" -f $svcWmi.StartMode,$svcWmi.State,$svcWmi.ExitCode,$svcWmi.PathName) "INFO"
  }

  if($svc.Status -ne "Running"){
    Write-Log "Tentando Start-Service WazuhSvc + StartupType Automatic..." "WARN"
    try { Set-Service -Name WazuhSvc -StartupType Automatic } catch {}
    try { Start-Service -Name WazuhSvc -ErrorAction Stop; Start-Sleep 3 } catch { Write-Log ("Start falhou: {0}" -f $_.Exception.Message) "ERROR" }
    $svc2 = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    if($svc2){ Write-Log ("Status pós-start: {0}" -f $svc2.Status) ($(if($svc2.Status -eq "Running"){"OK"}else{"ERROR"})) }
  }
} catch {
  Write-Log ("Serviço WazuhSvc não encontrado: {0}" -f $_.Exception.Message) "ERROR"
}

# ===== AGENT LOG =====
$ossecLog = "C:\Program Files (x86)\ossec-agent\ossec.log"
if(Test-Path $ossecLog){
  Write-Log ("Tail ossec.log: {0}" -f $ossecLog) "INFO"
  Get-Content $ossecLog -Tail 120 | ForEach-Object { Write-Log ("  " + $_) "INFO" }
} else {
  Write-Log ("ossec.log não encontrado em {0}" -f $ossecLog) "WARN"
}

# ===== EVENTS =====
Write-Log "Eventos SCM (últimas 24h):" "INFO"
try {
  Get-WinEvent -FilterHashtable @{
    LogName='System'; ProviderName='Service Control Manager'; Id=7031,7034,7036; StartTime=(Get-Date).AddHours(-24)
  } -ErrorAction SilentlyContinue | Select-Object -First 50 TimeCreated,Id,Message |
    ForEach-Object { Write-Log ("  {0} | {1} | {2}" -f $_.TimeCreated,$_.Id,(($_.Message -replace "\s+"," ") )) "INFO" }
} catch {}

Write-Log "Crashes (Application 1000/1001 - últimas 24h):" "INFO"
try {
  Get-WinEvent -FilterHashtable @{
    LogName='Application'; Id=1000,1001; StartTime=(Get-Date).AddHours(-24)
  } -ErrorAction SilentlyContinue | Select-Object -First 30 TimeCreated,Id,Message |
    ForEach-Object { Write-Log ("  {0} | {1} | {2}" -f $_.TimeCreated,$_.Id,(($_.Message -replace "\s+"," ") )) "INFO" }
} catch {}

Write-Log ("LOG GERADO: {0}" -f $logFile) "OK"
Write-Log "==== WAZUH HEALTH CHECK - FIM ====" "OK"
