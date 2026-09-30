[CmdletBinding()]
param(
    [ValidateSet('start', 'status', 'stop', 'admin', 'check')]
    [string]$Action = 'start',
    [ValidateSet('auto', 'online', 'offline')]
    [string]$BuildMode = 'auto',
    [string]$Username = 'admin',
    [switch]$SkipAdmin,
    [switch]$HealthOnly
)

# Windows PowerShell 5.1 compatible; paths are always relative to this script.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $ProjectRoot '.env'
$BaseImage = 'python:3.12.14-slim-bookworm'
$ComposeArguments = @(
    'compose', '--project-name', 'aegis-soc', '--project-directory', $ProjectRoot,
    '--env-file', $EnvFile, '-f', (Join-Path $ProjectRoot 'compose.yaml')
)

function Find-Docker {
    $command = Get-Command docker -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($candidate in @(
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'Brak Docker Desktop. Zainstaluj Docker Desktop z obsluga kontenerow Linux.'
}

function Test-Engine {
    $ErrorActionPreference = 'Continue'
    $kind = & $script:DockerPath info --format '{{.OSType}}' 2>$null
    return ($LASTEXITCODE -eq 0 -and $kind -eq 'linux')
}

function Assert-Engine {
    if (Test-Engine) { return }
    if ($Action -ne 'start') {
        throw 'Docker z kontenerami Linux nie dziala. Najpierw uruchom projekt.'
    }
    foreach ($candidate in @(
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Write-Host 'Uruchamiam Docker Desktop; czekam na silnik Linux...'
            Start-Process -FilePath $candidate -WindowStyle Hidden | Out-Null
            break
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Engine) { return }
        Start-Sleep -Seconds 2
    }
    throw 'Docker nie jest gotowy. Sprawdz Docker Desktop i wlacz kontenery Linux.'
}

function Invoke-Docker {
    param([string[]]$Arguments)
    # Native stderr is progress output in Compose, not a PowerShell exception.
    $ErrorActionPreference = 'Continue'
    & $script:DockerPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Polecenie Docker nie powiodlo sie. Zobacz komunikat powyzej i docs/local-start.md.'
    }
}

function Find-Python {
    $candidates = @(
        (Join-Path $ProjectRoot '.venv\Scripts\python.exe'),
        (Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
    )
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($command -and $command.Source -notlike '*\WindowsApps\*') {
        $candidates += $command.Source
    }
    $ErrorActionPreference = 'Continue'
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        $launched = & $launcher.Source -3.12 -c 'import sys; print(sys.executable)' 2>$null
        if ($LASTEXITCODE -eq 0 -and $launched) { $candidates += $launched }
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            & $candidate -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        }
    }
    return $null
}

function Initialize-Environment {
    if (Test-Path -LiteralPath $EnvFile) { return }
    Write-Host 'Tworze lokalna konfiguracje z losowymi sekretami...'
    Invoke-Docker (@('run', '--rm', '--network', 'none', '--mount',
        "type=bind,source=$ProjectRoot,target=/workspace", $BaseImage,
        'python', '/workspace/scripts/bootstrap_env.py', '--output', '/workspace/.env'))
}

function Get-PublicOrigin {
    $originLines = @(Get-Content -LiteralPath $EnvFile | Where-Object {
        $_ -match '^AEGIS_PUBLIC_ORIGIN='
    })
    if ($originLines.Count -ne 1) { throw 'Brak poprawnego AEGIS_PUBLIC_ORIGIN w .env.' }
    $origin = ($originLines[0] -split '=', 2)[1].Trim().Trim('"').Trim("'").TrimEnd('/')
    $uri = $null
    if (-not [Uri]::TryCreate($origin, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'http' -or $uri.Port -ne 8080 -or
        $uri.Host -notin @('localhost', '127.0.0.1', '[::1]', '::1') -or
        $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') {
        throw 'Launcher obsluguje lokalny HTTP na porcie 8080. Sprawdz AEGIS_PUBLIC_ORIGIN w .env.'
    }
    return $origin
}

function Build-Backend {
    $mode = $BuildMode
    $wheelhouse = Join-Path $ProjectRoot 'backend\.wheelhouse'
    if ($mode -eq 'auto') {
        $wheels = @(Get-ChildItem -LiteralPath $wheelhouse -Filter '*.whl' -ErrorAction SilentlyContinue)
        if ($wheels.Count -gt 0) { $mode = 'offline' } else { $mode = 'online' }
    }
    if ($mode -eq 'online') {
        Write-Host 'Buduje backend z przypietymi zaleznosciami...'
        $ErrorActionPreference = 'Continue'
        & $script:DockerPath @ComposeArguments build api
        if ($LASTEXITCODE -eq 0) { return }
        if ($BuildMode -eq 'online') { throw 'Budowanie online nie powiodlo sie.' }
        Write-Host 'Probuje zaleznosci Linux pobrane z zaufaniem do certyfikatow Windows...'
    }
    $python = Find-Python
    if (-not $python) {
        throw 'Tryb offline wymaga Python 3.12 z pip. Zobacz docs/local-start.md.'
    }
    & $python (Join-Path $PSScriptRoot 'prepare_wheelhouse.py')
    if ($LASTEXITCODE -ne 0) { throw 'Przygotowanie zaleznosci nie powiodlo sie; TLS pozostaje wlaczony.' }
    $offline = $ComposeArguments + @('-f', (Join-Path $ProjectRoot 'compose.offline.yaml'))
    Invoke-Docker ($offline + @('build', 'api'))
}

function Test-Readiness {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8080/ready' -TimeoutSec 10
        return ($response.StatusCode -eq 200)
    } catch { return $false }
}

function Test-HasUsers {
    $probe = 'from sqlalchemy import select; from app.core.config import get_settings; from app.infrastructure.database import Database; from app.modules.users.models import User; db=Database(get_settings()); session=db.sessions(); print(1 if session.scalar(select(User.id).limit(1)) is not None else 0); session.close(); db.close()'
    $ErrorActionPreference = 'Continue'
    $state = & $script:DockerPath @ComposeArguments exec -T api python -c $probe
    if ($LASTEXITCODE -ne 0 -or $state -notin @('1', '0')) {
        throw 'Nie mozna sprawdzic pierwszego konta. Sprawdz stan uslug.'
    }
    return ($state -eq '1')
}

function Initialize-Admin {
    if (Test-HasUsers) {
        Write-Host 'Konta juz istnieja. Zachowuje dotychczasowe hasla i uprawnienia.'
        return
    }
    Write-Host "Ustaw pierwszego administratora: $Username. Haslo: 15-128 znakow."
    Invoke-Docker ($ComposeArguments + @('exec', 'api', 'python', '-m', 'app.bootstrap', '--username', $Username))
}

function Check-Runtime {
    param([switch]$OnlyHealth)
    $python = Find-Python
    $arguments = @('--base-url', 'http://127.0.0.1:8080', '--origin', $script:PublicOrigin)
    if ($OnlyHealth) { $arguments += '--health-only' } else { $arguments += @('--username', $Username) }
    if ($python) {
        & $python (Join-Path $PSScriptRoot 'check_runtime.py') @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Kontrola przeplywu nie powiodla sie.' }
        return
    }
    # No host Python is required for checking a normally built installation.
    $arguments[1] = 'http://host.docker.internal:8080'
    $container = @('run', '--rm', '-i', '--mount',
        "type=bind,source=$PSScriptRoot,target=/checks,readonly", $BaseImage,
        'python', '/checks/check_runtime.py') + $arguments
    if ($OnlyHealth) { Invoke-Docker $container; return }
    $secure = Read-Host 'Haslo administratora (ukryte)' -AsSecureString
    $pointer = [IntPtr]::Zero
    $plaintext = $null
    try {
        # PowerShell 5.1 defaults native stdin to ASCII; preserve Unicode passwords.
        $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $ErrorActionPreference = 'Continue'
        $plaintext | & $script:DockerPath @container --password-stdin
        if ($LASTEXITCODE -ne 0) { throw 'Kontrola przeplywu nie powiodla sie.' }
    } finally {
        $plaintext = $null
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $secure.Dispose()
    }
}

try {
    $script:DockerPath = Find-Docker
    Assert-Engine
    if ($Action -eq 'start') { Initialize-Environment }
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        throw 'Brak .env. Uruchom najpierw Uruchom Aegis.cmd.'
    }
    Invoke-Docker ($ComposeArguments + @('config', '--quiet'))
    $script:PublicOrigin = Get-PublicOrigin
    switch ($Action) {
        'start' {
            Build-Backend
            Write-Host 'Uruchamiam bazy, migracje, API i przetwarzanie zdarzen...'
            Invoke-Docker ($ComposeArguments + @('up', '-d', '--no-build', '--wait', '--wait-timeout', '180'))
            if (-not (Test-Readiness)) { throw 'API nie jest gotowe przez lokalny proxy.' }
            if ($SkipAdmin) {
                if (-not (Test-HasUsers)) {
                    Write-Host 'Brak kont. Utworz administratora: scripts/aegis.ps1 -Action admin'
                }
            } else { Initialize-Admin }
            Check-Runtime -OnlyHealth
            Write-Host 'Backend dziala. API: http://localhost:8080/api/v1'
            Write-Host 'Nie ma jeszcze panelu SOC. Pelna kontrola zdarzen: scripts/aegis.ps1 -Action check'
        }
        'status' {
            Invoke-Docker ($ComposeArguments + @('ps', '--all'))
            Check-Runtime -OnlyHealth
        }
        'stop' {
            Invoke-Docker ($ComposeArguments + @('stop', '--timeout', '30'))
            Write-Host 'Uslugi zatrzymane. Konfiguracja i dane zostaly zachowane.'
        }
        'admin' { Initialize-Admin }
        'check' { Check-Runtime -OnlyHealth:$HealthOnly }
    }
    exit 0
} catch {
    Write-Host "Aegis: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
