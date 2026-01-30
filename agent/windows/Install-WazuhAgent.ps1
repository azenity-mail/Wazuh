<#
.SYNOPSIS
  Wazuh Agent - instalação + firewall + validações, com evidência em log (PS 5.1).

.DESCRIPTION
  ETAPA 0: Pré-check (Admin, versão do PowerShell, coleta Hostname/IP/Datetime)
  ETAPA 1: Criação de pastas e arquivo de log (com hostname/IP/data/hora)
  ETAPA 2: Firewall Windows - libera OUTBOUND para 3.19.177.148 TCP 1514/1515/55000
  ETAPA 3: Teste de conectividade TCP (Test-NetConnection)
  ETAPA 4: Download do MSI (com hash SHA256)
  ETAPA 5: Instalação silenciosa do MSI (msiexec), sem logar senha (prompt interativo se faltar)
  ETAPA 6: Descoberta do serviço, start e validação
  ETAPA 7: Evidências pós: regras firewall, conexões TCP, logs do agente, eventos MSI

.NOTES
  - Compatível com PowerShell 5.1
  - GPO AllSigned: assine o script após alterar
  - Log em UTF-8 com BOM para evitar "InstalaÃ§Ã£o"
#>

[CmdletBinding()]
param(
  [string]$DestinationIP = "3.19.177.148",
  [int[]]$Ports = @(1514,1515,55000),

  [string]$MsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi",
  [string]$Manager = "ls8lj27cyp3a.cloud.wazuh.com",
  [string]$AgentGroup = "servidores_windows",

  # Pode vir do env var. Se faltar, script pede interativamente.
  [string]$RegistrationPassword = $env:WAZUH_REG_PASSWORD,

  [string]$BaseDir = "C:\TempFolder\Wazuh"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# FUNÇÕES BÁSICAS
# =========================

function New-Utf8BomFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path $Path)) {
    $utf8Bom = New-Object System.Text.UTF8Encoding($true) # BOM=True
    [System.IO.File]::WriteAllText($Path, "", $utf8Bom)
  }
}

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet("INFO","WARN","ERROR","OK")][string]$Level = "INFO"
  )
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
  $line = "[$ts] [$Level] $Message"

  # grava sempre UTF-8 BOM (arquivo já criado com BOM)
  $utf8Bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::AppendAllText($script:LogFile, $line + [Environment]::NewLine, $utf8Bom)

  Write-Host $line
}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Execute este script em PowerShell como Administrador (Run as Administrator)."
  }
}

function Ensure-Dirs {
  New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "Logs") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "Bin")  | Out-Null
}

function Get-PrimaryIPv4 {
  $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.IPAddress -and
      $_.IPAddress -notlike "169.254.*" -and
      $_.IPAddress -ne "127.0.0.1" -and
      $_.ValidLifetime -gt 0
    } | Sort-Object -Property InterfaceMetric

  $first = $ips | Select-Object -First 1
  if ($null -ne $first) { return $first.IPAddress }
  return $null
}

function Get-RegistrationPasswordPlain {
  <#
    Retorna a senha em texto plano SOMENTE para passar ao msiexec.
    - Não loga.
    - Se não vier em parâmetro/env var, pede interativamente (SecureString).
  #>
  if (-not [string]::IsNullOrWhiteSpace($script:RegistrationPassword)) {
    return $script:RegistrationPassword
  }

  # Prompt interativo (não grava nada em log)
  $sec = Read-Host "Informe WAZUH_REGISTRATION_PASSWORD (input oculto)" -AsSecureString
  if ($null -eq $sec) { throw "Senha não informada." }

  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }

  if ([string]::IsNullOrWhiteSpace($plain)) { throw "Senha vazia não é permitida." }

  return $plain
}

# =========================
# ETAPA 2 - FIREWALL
# =========================

function New-WazuhFirewallRules {
  Write-Log ("ETAPA 2 - Firewall: criando regras OUTBOUND para {0} TCP {1}" -f $DestinationIP, ($Ports -join ",")) "INFO"

  $group = "Wazuh Agent"
  foreach ($port in $Ports) {
    $name = "WazuhCloud-Out-TCP-$port"

    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    New-NetFirewallRule `
      -DisplayName $name `
      -Group $group `
      -Direction Outbound `
      -Action Allow `
      -Enabled True `
      -Profile Any `
      -Protocol TCP `
      -RemoteAddress $DestinationIP `
      -RemotePort $port | Out-Null

    Write-Log ("Regra criada: {0} (Outbound TCP -> {1}:{2})" -f $name, $DestinationIP, $port) "OK"
  }

  Write-Log "Evidência Firewall - regras do grupo 'Wazuh Agent':" "INFO"
  $rules = Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
  if ($rules) {
    foreach ($r in $rules) {
      $pf = $r | Get-NetFirewallPortFilter
      $af = $r | Get-NetFirewallAddressFilter
      Write-Log (" - {0} | Dir={1} | Action={2} | Proto={3} | RemoteAddr={4} | RemotePort={5}" -f `
        $r.DisplayName, $r.Direction, $r.Action, $pf.Protocol, ($af.RemoteAddress -join ","), ($pf.RemotePort -join ",")) "INFO"
    }
  } else {
    Write-Log " - Nenhuma regra encontrada no grupo (GPO pode estar bloqueando regras locais)." "WARN"
  }

  Write-Log "Evidência Firewall - perfis:" "INFO"
  Get-NetFirewallProfile | ForEach-Object {
    Write-Log (" - {0}: Enabled={1} DefaultOutbound={2} AllowLocalFirewallRules={3}" -f `
      $_.Name, $_.Enabled, $_.DefaultOutboundAction, $_.AllowLocalFirewallRules) "INFO"
  }
}

# =========================
# ETAPA 3 - CONECTIVIDADE
# =========================

function Test-WazuhConnectivity {
  Write-Log ("ETAPA 3 - Conectividade: Test-NetConnection para {0} portas {1}" -f $DestinationIP, ($Ports -join ",")) "INFO"
  foreach ($port in $Ports) {
    try {
      $r = Test-NetConnection -ComputerName $DestinationIP -Port $port -WarningAction SilentlyContinue
      if ($r.TcpTestSucceeded) {
        Write-Log ("OK: {0}:{1} TcpTestSucceeded=True SourceAddress={2}" -f $DestinationIP, $port, $r.SourceAddress) "OK"
      } else {
        Write-Log ("WARN: {0}:{1} TcpTestSucceeded=False (verificar rota/ACL/proxy/firewall upstream)" -f $DestinationIP, $port) "WARN"
      }
    } catch {
      Write-Log ("WARN: falha Test-NetConnection {0}:{1} -> {2}" -f $DestinationIP, $port, $_.Exception.Message) "WARN"
    }
  }
}

# =========================
# ETAPA 4 - DOWNLOAD MSI
# =========================

function Download-MSI {
  $msiPath = Join-Path (Join-Path $BaseDir "Bin") "wazuh-agent-4.14.1-1.msi"
  Write-Log ("ETAPA 4 - Download: {0}" -f $MsiUrl) "INFO"

  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
  Invoke-WebRequest -Uri $MsiUrl -OutFile $msiPath -UseBasicParsing

  if (-not (Test-Path $msiPath)) { throw ("Download falhou: arquivo não encontrado em {0}" -f $msiPath) }

  $hash = Get-FileHash -Path $msiPath -Algorithm SHA256
  $fi   = Get-Item $msiPath

  Write-Log ("MSI baixado: {0} | Size={1}MB" -f $fi.FullName, [Math]::Round($fi.Length/1MB,2)) "OK"
  Write-Log ("SHA256: {0}" -f $hash.Hash) "INFO"

  return $msiPath
}

# =========================
# ETAPA 5 - INSTALAÇÃO
# =========================

function Install-WazuhAgent {
  param([Parameter(Mandatory=$true)][string]$MsiPath)

  Write-Log "ETAPA 5 - Instalação MSI (silenciosa)" "INFO"

  $plainPwd = Get-RegistrationPasswordPlain
  Write-Log ("Parâmetros: Manager={0} | Group={1} | Password=REDACTED" -f $Manager, $AgentGroup) "INFO"

  $args = @(
    "/i", "`"$MsiPath`"",
    "/qn", "/norestart",
    "WAZUH_MANAGER=$Manager",
    ("WAZUH_REGISTRATION_PASSWORD={0}" -f $plainPwd),
    "WAZUH_AGENT_GROUP=$AgentGroup"
  )

  $start = Get-Date
  $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  $exitCode = $proc.ExitCode
  $seconds = [int]((Get-Date) - $start).TotalSeconds

  # higiene: apaga variável local
  $plainPwd = $null

  if ($exitCode -eq 0) {
    Write-Log ("msiexec concluído com sucesso. ExitCode=0 | Duração={0}s" -f $seconds) "OK"
  } else {
    Write-Log ("msiexec falhou. ExitCode={0} | Duração={1}s" -f $exitCode, $seconds) "ERROR"
  }

  Write-Log "Evidência: Application log / Provider=MsiInstaller (últimos 15 min, até 20 eventos)" "INFO"
  try {
    $events = Get-WinEvent -FilterHashtable @{
      LogName="Application"; ProviderName="MsiInstaller"; StartTime=(Get-Date).AddMinutes(-15)
    } -ErrorAction SilentlyContinue | Select-Object -First 20

    if ($events) {
      foreach ($e in $events) {
        $msg = ($e.Message -replace "\s+"," ")
        if ($msg.Length -gt 250) { $msg = $msg.Substring(0,250) + "..." }
        Write-Log (" - {0} | EventID={1} | {2}" -f $e.TimeCreated, $e.Id, $msg) "INFO"
      }
    } else {
      Write-Log " - Nenhum evento encontrado nessa janela (pode acontecer)." "WARN"
    }
  } catch {
    Write-Log (" - Falha ao ler eventos MsiInstaller: {0}" -f $_.Exception.Message) "WARN"
  }

  if ($exitCode -ne 0) { throw ("Instalação falhou (msiexec ExitCode={0})." -f $exitCode) }
}

# =========================
# ETAPA 6 - SERVIÇO
# =========================

function Find-WazuhService {
  $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match "wazuh|ossec" -or $_.DisplayName -match "wazuh|ossec"
  } | Select-Object -First 1
  if ($svc) { return $svc }

  $svcCim = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match "wazuh|ossec" -or $_.DisplayName -match "wazuh|ossec"
  } | Select-Object -First 1
  if ($svcCim) { return (Get-Service -Name $svcCim.Name -ErrorAction SilentlyContinue) }

  return $null
}

function Start-And-Verify {
  Write-Log "ETAPA 6 - Serviço: localizar, iniciar e validar" "INFO"

  $svc = Find-WazuhService
  if (-not $svc) { throw "Serviço do Wazuh Agent não encontrado após instalação. Verifique MSI/versão." }

  Write-Log ("Serviço detectado: Name={0} | DisplayName={1} | Status={2}" -f $svc.Name, $svc.DisplayName, $svc.Status) "INFO"

  if ($svc.Status -ne "Running") {
    Write-Log ("Iniciando serviço: {0}" -f $svc.Name) "INFO"
    Start-Service -Name $svc.Name
    Start-Sleep -Seconds 3
  }

  $svc2 = Get-Service -Name $svc.Name
  if ($svc2.Status -eq "Running") { Write-Log ("Status OK: {0} = Running" -f $svc2.Name) "OK" }
  else { Write-Log ("Status ERROR: {0} = {1}" -f $svc2.Name, $svc2.Status) "ERROR" }

  try {
    $c = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $svc2.Name) -ErrorAction SilentlyContinue
    if ($c) { Write-Log ("BinPath: {0}" -f $c.PathName) "INFO" }
  } catch {}
}

# =========================
# ETAPA 7 - EVIDÊNCIAS
# =========================

function Post-Evidence {
  Write-Log "ETAPA 7 - Evidências pós-instalação" "INFO"

  Write-Log ("Evidência: conexões TCP atuais para {0} (pode estar vazio)" -f $DestinationIP) "INFO"
  try {
    $conns = Get-NetTCPConnection -RemoteAddress $DestinationIP -ErrorAction SilentlyContinue |
      Select-Object -First 25 -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess

    if ($conns) {
      foreach ($c in $conns) {
        Write-Log (" - {0}:{1} -> {2}:{3} [{4}] PID={5}" -f $c.LocalAddress,$c.LocalPort,$c.RemoteAddress,$c.RemotePort,$c.State,$c.OwningProcess) "INFO"
      }
    } else {
      Write-Log " - Nenhuma conexão listada no momento (normal em alguns cenários)." "WARN"
    }
  } catch {
    Write-Log (" - Falha Get-NetTCPConnection: {0}" -f $_.Exception.Message) "WARN"
  }

  Write-Log "Evidência: tail do log do agente (se existir)" "INFO"
  $possibleLogs = @(
    "C:\Program Files (x86)\ossec-agent\ossec.log",
    "C:\Program Files\ossec-agent\ossec.log",
    "C:\Program Files (x86)\Wazuh\wazuh-agent\ossec.log",
    "C:\Program Files\Wazuh\wazuh-agent\ossec.log"
  ) | Where-Object { Test-Path $_ }

  $possibleLogs = @($possibleLogs)
  if ($possibleLogs.Length -gt 0) {
    $logPath = $possibleLogs[0]
    Write-Log ("Log encontrado: {0}" -f $logPath) "OK"
    Get-Content -Path $logPath -Tail 40 -ErrorAction SilentlyContinue |
      ForEach-Object { Write-Log ("   " + $_) "INFO" }
  } else {
    Write-Log " - Log do agente não localizado nos caminhos padrão." "WARN"
  }

  Test-WazuhConnectivity
}

# =========================
# MAIN
# =========================

try {
  Assert-Admin
  Ensure-Dirs

  $hostname = $env:COMPUTERNAME
  $ip = Get-PrimaryIPv4
  $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
  $ipTag = $ip
  if ([string]::IsNullOrWhiteSpace($ipTag)) { $ipTag = "NOIP" }

  $script:LogFile = Join-Path (Join-Path $BaseDir "Logs") ("WazuhInstall_{0}_{1}_{2}.log" -f $hostname, $ipTag, $stamp)
  New-Utf8BomFile -Path $script:LogFile

  $transcriptPath = [IO.Path]::ChangeExtension($script:LogFile, ".transcript.txt")
  try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch {}

  Write-Log "==== WAZUH AGENT INSTALL - INÍCIO ====" "INFO"
  Write-Log ("Hostname: {0}" -f $hostname) "INFO"
  Write-Log ("IP Primário: {0}" -f $ipTag) "INFO"
  Write-Log ("Data/Hora início: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) "INFO"
  Write-Log ("Destino Wazuh Cloud: {0}" -f $DestinationIP) "INFO"
  Write-Log ("Portas: TCP/{0}" -f ($Ports -join ", TCP/")) "INFO"
  Write-Log ("Manager: {0} | Group: {1} | Password=REDACTED" -f $Manager, $AgentGroup) "INFO"
  Write-Log ("PowerShell: {0}" -f $PSVersionTable.PSVersion) "INFO"

  New-WazuhFirewallRules
  Test-WazuhConnectivity

  $msi = Download-MSI
  Install-WazuhAgent -MsiPath $msi

  Start-And-Verify
  Post-Evidence

  Write-Log ("Data/Hora fim: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) "INFO"
  Write-Log "==== WAZUH AGENT INSTALL - SUCESSO ====" "OK"

} catch {
  try { if ($script:LogFile) { Write-Log ("FALHA: {0}" -f $_.Exception.Message) "ERROR"; Write-Log ("Stack: {0}" -f $_.ScriptStackTrace) "ERROR" } } catch {}
  throw
} finally {
  try { Stop-Transcript | Out-Null } catch {}
  if ($script:LogFile) {
    Write-Host ""
    Write-Host ("LOG PRINCIPAL: {0}" -f $script:LogFile)
    Write-Host ("TRANSCRIPT:   {0}" -f ([IO.Path]::ChangeExtension($script:LogFile, ".transcript.txt")))
  }
}

