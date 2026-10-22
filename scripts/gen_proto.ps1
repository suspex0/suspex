param(
    [string]$Python = ""
)

# Generates Python gRPC stubs from proto/suspex.proto into
# orchestrator/src/suspex/generated and rewrites the pb2 import for in-package use.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $Python) {
    $Python = Join-Path $root "orchestrator\.venv\Scripts\python.exe"
    if (-not (Test-Path $Python)) {
        $Python = "python"
    }
}

$genDir = Join-Path $root "orchestrator\src\suspex\generated"
New-Item -ItemType Directory -Force -Path $genDir | Out-Null

& $Python -m grpc_tools.protoc `
    -I (Join-Path $root "proto") `
    --python_out=$genDir `
    --grpc_python_out=$genDir `
    (Join-Path $root "proto\suspex.proto")
if ($LASTEXITCODE -ne 0) { throw "grpc_tools.protoc failed" }

$grpcFile = Join-Path $genDir "suspex_pb2_grpc.py"
(Get-Content $grpcFile -Raw) `
    -replace [regex]::Escape("import suspex_pb2 as suspex__pb2"), "from . import suspex_pb2 as suspex__pb2" |
    Set-Content $grpcFile -NoNewline

Set-Content (Join-Path $genDir "__init__.py") "" -NoNewline
Write-Host "Python stubs generated in $genDir"
