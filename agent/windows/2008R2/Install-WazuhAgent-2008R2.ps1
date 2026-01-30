<#
.SYNOPSIS
  Instala e valida Wazuh Agent no Windows Server 2008 R2 (PowerShell 2.0/.NET 3.5) com evidências em log.

.NOTES
  - Firewall outbound via netsh (compatível 2008 R2)
  - Teste TCP via TcpClient (sem Test-NetConnection)
  - Download via WebClient
  - Instalação MSI silenciosa com log /l*v
  - Start/verify service
  - Log com hostname, IP, data/hora
  - NÃO grava senha em log (REDACTED)
#>

[CmdletBinding()]
param(
  [string]$DestinationIP = "3.19.177.148",
  [int[]]$Ports = @(1514,1515,55000),

  [string]$MsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi",
  [string]$Manager = "ls8lj27cyp3a.cloud.wazuh.com",
  [string]$AgentGroup = "servidores_windows",

  [string]$RegistrationPassword = $env:WAZUH_REG_PASSWORD,

  [string]$BaseDir = "C:\TempFolder\Wazuh"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

$script:LogFile = $null
$script:TranscriptPath = $null

function Is-Blank {
  param([string]$s)
  if ($s -eq $null) { return $true }
  if ($s.Trim().Length -eq 0) { return $true }
  return $false
}

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet("INFO","WARN","ERROR","OK")][string]$Level = "INFO"
  )
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
  $line = "[$ts] [$Level] $Message"

  # Unicode => abre “bonito” no Notepad do Windows antigo
  if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding Unicode }

  Write-Host $line
}

function Assert-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p=New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Execute este script como Administrador."
  }
}

function Ensure-Dirs {
  New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "Logs") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "Bin")  | Out-Null
}

function Get-PrimaryIPv4_WMI {
  $nics = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
  foreach ($n in $nics) {
    foreach ($ip in @($n.IPAddress)) {
      if ($ip -and $ip -match '^\d{1,3}(\.\d{1,3}){3}$' -and $ip -ne '127.0.0.1' -and $ip -notmatch '^169\.254\.') {
        return $ip
      }
    }
  }
  return $null
}

function New-FirewallRules_Netsh {
  Write-Log -Message ("ETAPA 1 - Firewall OUTBOUND para {0} portas TCP {1}" -f $DestinationIP, ($Ports -join ",")) -Level "INFO"

  foreach ($p in $Ports) {
    $name = "WazuhCloud-Out-TCP-$p"
    & netsh advfirewall firewall delete rule name="$name" | Out-Null
    & netsh advfirewall firewall add rule name="$name" dir=out action=allow protocol=TCP remoteip=$DestinationIP remoteport=$p profile=any | Out-Null
    Write-Log -Message ("Regra criada: {0} -> {1}:{2}" -f $name,$DestinationIP,$p) -Level "OK"
  }

  Write-Log -Message "Evidência (netsh show rule):" -Level "INFO"
  foreach ($p in $Ports) {
    $name = "WazuhCloud-Out-TCP-$p"
    $out = & netsh advfirewall firewall show rule name="$name"
    ($out | Out-String).Trim().Split("`n") | ForEach-Object { Write-Log -Message ("  " + $_.Trim()) -Level "INFO" }
  }
}

function Test-TcpPort {
  # NÃO use parâmetro chamado Host (é variável automática read-only)
  param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][int]$Port,
    [int]$TimeoutMs = 3000
  )

  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $client.BeginConnect($ComputerName,$Port,$null,$null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs,$false)) { return $false }
    $client.EndConnect($iar) | Out-Null
    return $true
  } catch {
    return $false
  } finally {
    try { $client.Close() } catch {}
  }
}

function Test-Connectivity {
  Write-Log -Message ("ETAPA 2 - Teste TCP para {0} portas {1}" -f $DestinationIP, ($Ports -join ",")) -Level "INFO"
  foreach ($p in $Ports) {
    $ok = Test-TcpPort -ComputerName $DestinationIP -Port $p -TimeoutMs 3000
    if ($ok) { Write-Log -Message ("OK: {0}:{1} conectou" -f $DestinationIP,$p) -Level "OK" }
    else     { Write-Log -Message ("WARN: {0}:{1} sem conexão (timeout/blocked)" -f $DestinationIP,$p) -Level "WARN" }
  }
}

function Ensure-RegistrationPassword {
  if (Is-Blank $RegistrationPassword) {
    Write-Log -Message "ETAPA 3 - env:WAZUH_REG_PASSWORD vazio. Solicitando senha (não será logada)..." -Level "WARN"
    $RegistrationPassword = Read-Host "Informe WAZUH_REGISTRATION_PASSWORD"
    if (Is-Blank $RegistrationPassword) { throw "RegistrationPassword não informado." }
  } else {
    Write-Log -Message "ETAPA 3 - Senha carregada do env:WAZUH_REG_PASSWORD (REDACTED)" -Level "OK"
  }
}

function Download-MSI {
  $msiPath = Join-Path (Join-Path $BaseDir "Bin") "wazuh-agent-4.14.1-1.msi"
  Write-Log -Message ("ETAPA 4 - Download MSI: {0}" -f $MsiUrl) -Level "INFO"

  $wc = New-Object Net.WebClient
  $wc.DownloadFile($MsiUrl, $msiPath)

  if (-not (Test-Path $msiPath)) { throw "Download falhou: $msiPath" }

  $fi = Get-Item $msiPath
  Write-Log -Message ("MSI baixado: {0} (Size={1} bytes)" -f $fi.FullName, $fi.Length) -Level "OK"
  return $msiPath
}

function Install-Wazuh {
  param([Parameter(Mandatory=$true)][string]$MsiPath)

  Write-Log -Message "ETAPA 5 - Instalação MSI (silenciosa)" -Level "INFO"
  Write-Log -Message ("Parâmetros: Manager={0}; Group={1}; Password=REDACTED" -f $Manager,$AgentGroup) -Level "INFO"

  $msiLog = Join-Path (Join-Path $BaseDir "Logs") ("msiexec_{0}.log" -f (Get-Date -Format yyyyMMdd-HHmmss))

  $args = @(
    "/i", "`"$MsiPath`"",
    "/qn", "/norestart",
    "/l*v", "`"$msiLog`"",
    "WAZUH_MANAGER=$Manager",
    "WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword",
    "WAZUH_AGENT_GROUP=$AgentGroup"
  )

  $start = Get-Date
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  $end = Get-Date

  Write-Log -Message ("msiexec finalizado. ExitCode={0}. Duração={1}s" -f $p.ExitCode, [int]($end-$start).TotalSeconds) -Level "INFO"
  Write-Log -Message ("Log do MSI: {0}" -f $msiLog) -Level "INFO"

  if ($p.ExitCode -ne 0) { throw "Instalação falhou (msiexec ExitCode=$($p.ExitCode)). Verifique: $msiLog" }

  Write-Log -Message "MSI instalado com sucesso." -Level "OK"
  $script:RegistrationPassword = $null
}

function Find-WazuhService {
  $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match "wazuh|ossec" -or $_.DisplayName -match "wazuh|ossec"
  } | Select-Object -First 1
  return $svc
}

function Start-And-VerifyService {
  Write-Log -Message "ETAPA 6 - Detectar/Iniciar serviço do agente" -Level "INFO"

  $svc = Find-WazuhService
  if (-not $svc) { throw "Serviço do Wazuh/OSSEC não encontrado após instalação." }

  Write-Log -Message ("Serviço: Name={0} DisplayName={1} Status={2}" -f $svc.Name,$svc.DisplayName,$svc.Status) -Level "INFO"

  if ($svc.Status -ne "Running") {
    Start-Service -Name $svc.Name
    Start-Sleep -Seconds 3
  }

  $svc2 = Get-Service -Name $svc.Name
  if ($svc2.Status -eq "Running") {
    Write-Log -Message ("Serviço Running: {0}" -f $svc2.Name) -Level "OK"
  } else {
    throw "Serviço não ficou Running (Status=$($svc2.Status))."
  }
}

try {
  Assert-Admin
  Ensure-Dirs

  $hostname = $env:COMPUTERNAME
  $ip = Get-PrimaryIPv4_WMI
  $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
  $ipTag = $(if ($ip) { $ip } else { "NOIP" })

  $script:LogFile = Join-Path (Join-Path $BaseDir "Logs") ("Wazuh_2008R2_{0}_{1}_{2}.log" -f $hostname,$ipTag,$stamp)
  $script:TranscriptPath = [IO.Path]::ChangeExtension($script:LogFile, ".transcript.txt")

  try { Start-Transcript -Path $script:TranscriptPath -Force | Out-Null } catch {}

  Write-Log -Message "==== WAZUH AGENT INSTALL (2008 R2) - INÍCIO ====" -Level "INFO"
  Write-Log -Message ("Hostname: {0}" -f $hostname) -Level "INFO"
  Write-Log -Message ("IP Primário: {0}" -f $ipTag) -Level "INFO"
  Write-Log -Message ("Data/Hora início: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -Level "INFO"
  Write-Log -Message ("Destino Firewall: {0} | Portas TCP: {1}" -f $DestinationIP, ($Ports -join ",")) -Level "INFO"
  Write-Log -Message ("Manager: {0} | Group: {1}" -f $Manager, $AgentGroup) -Level "INFO"

  New-FirewallRules_Netsh
  Test-Connectivity
  Ensure-RegistrationPassword

  $msi = Download-MSI
  Install-Wazuh -MsiPath $msi
  Start-And-VerifyService

  Write-Log -Message ("Data/Hora fim: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -Level "INFO"
  Write-Log -Message "==== SUCESSO ====" -Level "OK"
}
catch {
  Write-Log -Message ("FALHA: {0}" -f $_.Exception.Message) -Level "ERROR"
  throw
}
finally {
  try { Stop-Transcript | Out-Null } catch {}
  if ($null -ne $script:LogFile -and $script:LogFile -ne "") {
    Write-Host ""
    Write-Host ("LOG:        {0}" -f $script:LogFile)
    if ($script:TranscriptPath) { Write-Host ("TRANSCRIPT: {0}" -f $script:TranscriptPath) }
  }
}
