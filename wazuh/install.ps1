# Installs the official Wazuh single-node Docker stack for local development.
$ErrorActionPreference = "Stop"

$version = "v4.14.9"
$runtimeRoot = Join-Path $PSScriptRoot ".wazuh-docker"
$singleNode = Join-Path $runtimeRoot "single-node"
$composeFile = Join-Path $singleNode "docker-compose.yml"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is required and must be available on PATH."
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker Desktop is required and must be available on PATH."
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker is not running. Start Docker Desktop and retry."
}

if (-not (Test-Path $runtimeRoot)) {
    & git clone --depth 1 --branch $version https://github.com/wazuh/wazuh-docker.git $runtimeRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Could not clone the official Wazuh Docker repository."
    }
} elseif (-not (Test-Path (Join-Path $runtimeRoot ".git"))) {
    throw "The runtime directory exists but is not a Git checkout: $runtimeRoot"
}

if (-not (Test-Path $composeFile)) {
    throw "Wazuh compose file not found: $composeFile"
}

# Keep every published service local to this machine. The Windows host agent can
# still connect through 127.0.0.1; remote agents need an explicit network setup.
$compose = [System.IO.File]::ReadAllText($composeFile)
$mappings = @(
    [pscustomobject]@{ Source = '"1514:1514"'; Replacement = '"127.0.0.1:1514:1514"' },
    [pscustomobject]@{ Source = '"1515:1515"'; Replacement = '"127.0.0.1:1515:1515"' },
    [pscustomobject]@{ Source = '"514:514/udp"'; Replacement = '"127.0.0.1:514:514/udp"' },
    [pscustomobject]@{ Source = '"55000:55000"'; Replacement = '"127.0.0.1:55000:55000"' },
    [pscustomobject]@{ Source = '"9200:9200"'; Replacement = '"127.0.0.1:9200:9200"' },
    [pscustomobject]@{ Source = '- 443:5601'; Replacement = '- "127.0.0.1:8443:5601"' }
)
foreach ($mapping in $mappings) {
    $source = $mapping.Source
    $replacement = $mapping.Replacement
    if ($compose.Contains($source)) {
        $compose = $compose.Replace($source, $replacement)
    } elseif (-not $compose.Contains($replacement)) {
        throw "Unexpected Wazuh compose file; refusing to start with unreviewed port bindings ($source)."
    }
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($composeFile, $compose, $utf8NoBom)

Push-Location $singleNode
try {
    & docker compose -f generate-indexer-certs.yml run --rm generator
    if ($LASTEXITCODE -ne 0) {
        throw "Wazuh certificate generation failed."
    }

    & docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        throw "Wazuh startup failed."
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Wazuh dashboard: https://localhost:8443"
Write-Host "Local development credentials: admin / SecretPassword"
Write-Host "Change the default credentials before exposing the stack or enrolling remote agents."
Write-Host "Runtime checkout and certificates are stored in: $runtimeRoot"
