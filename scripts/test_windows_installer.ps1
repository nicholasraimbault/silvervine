# Exercise the generated public installer against local release artifacts.
# All installation, receipt, cache, and PATH changes stay in a temporary tree.
param([string]$DistDirectory = 'target/distrib')
$ErrorActionPreference = 'Stop'
$dist = (Resolve-Path $DistDirectory).Path
$temporary = Join-Path $env:RUNNER_TEMP ('silvervine-installer-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $temporary
$server = $null
try {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $server = Start-Process python -ArgumentList @('-m', 'http.server', "$port", '--bind', '127.0.0.1', '--directory', ('"{0}"' -f $dist)) -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $temporary 'server.log') -RedirectStandardError (Join-Path $temporary 'server-error.log')
    $url = "http://127.0.0.1:$port"
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        try { $null = Invoke-WebRequest $url -TimeoutSec 1; $ready = $true; break }
        catch { Start-Sleep -Milliseconds 200 }
    }
    if (-not $ready) { throw 'Local artifact server did not start' }

    $env:CARGO_HOME = Join-Path $temporary 'cargo home with spaces'
    $install = Join-Path $env:CARGO_HOME 'bin'
    $env:SILVERVINE_DOWNLOAD_URL = $url
    Remove-Item Env:SILVERVINE_INSTALL_DIR -ErrorAction SilentlyContinue
    $env:SILVERVINE_NO_MODIFY_PATH = '1'
    $env:XDG_CONFIG_HOME = Join-Path $temporary 'config'
    $env:XDG_CACHE_HOME = Join-Path $temporary 'cache'
    $env:SILVERVINE_TEST_DATA_MIGRATION_NOOP = '1'
    $env:SILVERVINE_TEST_LIFECYCLE_NOOP = '1'
    & (Join-Path $dist 'silvervine-installer.ps1')
    $executable = Join-Path $install 'silvervine.exe'
    if (-not (Test-Path $executable)) { throw 'Installer did not install silvervine.exe' }
    if (-not (Test-Path (Join-Path $install 'silvervine-update.exe'))) { throw 'Installer did not install updater' }
    $receipt = Join-Path $env:XDG_CONFIG_HOME 'silvervine/silvervine-receipt.json'
    if (-not (Test-Path $receipt)) { throw 'Installer did not write receipt' }
    & $executable --version
    if ($LASTEXITCODE -ne 0) { throw 'Installed executable does not run' }
    $result = & $executable --json update self --dry-run | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $result.reason -ne 'dry-run' -or $result.updated) { throw 'Installed updater/receipt not detected' }
    $installReceipt = Get-Content $receipt -Raw | ConvertFrom-Json
    if ($installReceipt.install_prefix -ne $env:CARGO_HOME) { throw 'Receipt does not match installation directory' }
    Write-Host 'Windows installer smoke passed: executable, updater, matching receipt, path with spaces, no account or elevation.'
} finally {
    if ($null -ne $server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
