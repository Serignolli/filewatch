<#
  Laboratório local do FileWatch (Windows / PowerShell 5.1+).

  Tudo acontece dentro desta pasta do projeto:
    - o monitor só observa ./sandbox (que tem o marcador .filewatch-sandbox);
    - o simulador só escreve em ./sandbox/victims/run-<timestamp>/;
    - o estado fica em ./baseline.json e ./alerts.log; os logs do demo em ./target/.
  Nada pede administrador, nada abre rede, nada roda fora desta pasta.

  Uso:  .\lab.cmd <comando>     (o .cmd evita bloqueio da ExecutionPolicy)
    check    confere Java e Maven
    test     roda os testes unitários
    demo     sobe o monitor, roda o simulador e mostra se o alerta HIGH saiu (recomendado)
    monitor  sobe só o monitor em primeiro plano (Ctrl+C para parar)
    attack   roda o simulador benigno (use com o monitor aberto em outro terminal)
    clean    apaga só as pastas geradas pelo simulador
    reset    clean + apaga baseline.json e alerts.log
#>
param([string]$Command = "help")

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Sandbox = Join-Path $Root "sandbox"
$Jar = Join-Path $Root "target\filewatch-0.1.0-SNAPSHOT.jar"
$Simulator = Join-Path $Root "tools\RansomwareSimulator.java"
$Alerts = Join-Path $Root "alerts.log"
$Utf8 = @("-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
# Limita a JVM do monitor: ele não precisa de mais que isso.
$MonitorJvm = @("-Xmx256m") + $Utf8

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location $Root

function Say($text, $color = "Cyan") { Write-Host "==> $text" -ForegroundColor $color }

function Require-Tools {
    foreach ($tool in "java", "mvn") {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool não encontrado no PATH. Instale Java 17+ e Maven 3.9+."
        }
    }
}

function Require-Sandbox {
    if (-not (Test-Path (Join-Path $Sandbox ".filewatch-sandbox") -PathType Leaf)) {
        throw "Marcador sandbox\.filewatch-sandbox não encontrado. Rode a partir de um clone completo do projeto."
    }
}

function Build {
    Say "Compilando (mvn package, sem testes)"
    & mvn -q -DskipTests package
    if ($LASTEXITCODE -ne 0) { throw "Falha no build" }
}

function Invoke-Simulator([string[]]$SimArgs) {
    & java @Utf8 $Simulator $Sandbox @SimArgs
    if ($LASTEXITCODE -ne 0) { throw "Simulador terminou com erro ($LASTEXITCODE)" }
}

# O "java" do PATH pode ser um atalho (ex.: Oracle javapath) que abre o java.exe real como processo filho.
# Para conseguir encerrar o monitor com segurança, lançamos o java.exe real do java.home.
function Resolve-Java {
    $ErrorActionPreference = "Continue" # no PS 5.1, stderr de exe com 2>&1 vira erro
    $settings = & java -XshowSettings:properties -version 2>&1 | ForEach-Object { "$_" }
    $line = $settings | Where-Object { $_ -match '^\s*java\.home\s*=' } | Select-Object -First 1
    if ($line) {
        $exe = Join-Path ($line -replace '^\s*java\.home\s*=\s*', '').Trim() "bin\java.exe"
        if (Test-Path $exe) { return $exe }
    }
    return (Get-Command java).Source
}

function Count-Alerts {
    if (Test-Path $Alerts) { return @(Get-Content $Alerts -Encoding UTF8).Count }
    return 0
}

function Wait-ForLog($file, $pattern, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $file) -and (Select-String -Path $file -Pattern $pattern -Quiet)) { return $true }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

function Demo {
    Require-Tools; Require-Sandbox; Build
    $log = Join-Path $Root "target\lab-monitor.log"
    $err = Join-Path $Root "target\lab-monitor.err.log"
    Remove-Item $log, $err -ErrorAction SilentlyContinue
    # Começa do zero: execuções antigas do simulador e um baseline velho fariam a varredura inicial
    # alertar sobre arquivos de antes, e o cooldown silenciaria o alerta desta execução.
    Say "Limpando execuções anteriores e o baseline"
    Invoke-Simulator @("--clean", "--confirm")
    Remove-Item (Join-Path $Root "baseline.json"), (Join-Path $Root "baseline.json.tmp") -ErrorAction SilentlyContinue
    $before = Count-Alerts

    Say "Subindo o monitor em segundo plano (log: target\lab-monitor.log)"
    $jvmArgs = $MonitorJvm + @("-jar", "`"$Jar`"")
    $monitor = Start-Process (Resolve-Java) -ArgumentList $jvmArgs -WorkingDirectory $Root -NoNewWindow -PassThru `
        -RedirectStandardOutput $log -RedirectStandardError $err
    try {
        if (-not (Wait-ForLog $log "Varredura inicial" 60)) {
            Get-Content $log, $err -ErrorAction SilentlyContinue | Select-Object -Last 30
            throw "O monitor não terminou a varredura inicial em 60 s"
        }
        Say "Monitor pronto. Rodando o simulador benigno"
        Invoke-Simulator @("--confirm")

        Say "Aguardando o alerta"
        $deadline = (Get-Date).AddSeconds(20)
        $high = $null
        while ((Get-Date) -lt $deadline -and -not $high) {
            Start-Sleep -Milliseconds 500
            if ((Count-Alerts) -gt $before) {
                $high = Get-Content $Alerts -Encoding UTF8 | Select-Object -Skip $before |
                    Where-Object { $_ -match '"severity":"HIGH"' } | Select-Object -First 1
            }
        }
        Write-Host ""
        if ($high) {
            $alert = $high | ConvertFrom-Json
            Say "PASSOU: alerta HIGH detectado" "Green"
            $alert.reasons | ForEach-Object { Write-Host "    - $_" }
            Write-Host "    ($($alert.involvedFiles.Count) arquivos envolvidos; detalhes em alerts.log)"
        } else {
            Say "FALHOU: nenhum alerta HIGH em 20 s. Veja target\lab-monitor.log" "Red"
            exit 1
        }
    } finally {
        if (-not $monitor.HasExited) {
            # /T encerra também processos filhos, caso o java.exe ainda seja um atalho.
            & taskkill.exe /PID $monitor.Id /T /F | Out-Null
        }
        Say "Monitor encerrado. Para apagar os arquivos gerados: .\lab.cmd clean"
    }
}

switch ($Command) {
    "check" {
        Require-Tools
        & java -version
        & mvn -v | Select-Object -First 1
        Require-Sandbox
        Say "Ambiente ok" "Green"
    }
    "test" { Require-Tools; & mvn test; exit $LASTEXITCODE }
    "demo" { Demo }
    "monitor" {
        Require-Tools; Require-Sandbox; Build
        Say "Monitor observando $Sandbox (Ctrl+C para parar)"
        & java @MonitorJvm -jar $Jar
    }
    "attack" { Require-Tools; Require-Sandbox; Invoke-Simulator @("--confirm") }
    "clean" { Require-Tools; Require-Sandbox; Invoke-Simulator @("--clean", "--confirm") }
    "reset" {
        Require-Tools; Require-Sandbox; Invoke-Simulator @("--clean", "--confirm")
        foreach ($f in "baseline.json", "baseline.json.tmp", "alerts.log") {
            $p = Join-Path $Root $f
            if (Test-Path $p -PathType Leaf) { Remove-Item $p; Say "Removido $f" }
        }
    }
    default {
        Get-Content $PSCommandPath -Encoding UTF8 | Select-Object -Skip 1 -First 18 | ForEach-Object { Write-Host $_ }
    }
}
