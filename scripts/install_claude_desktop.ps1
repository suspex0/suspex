# Merge the suspex0 MCP server registration into Claude Desktop's config
# (%APPDATA%\Claude\claude_desktop_config.json), preserving any other
# mcpServers entries the user already has. Idempotent: re-runs replace only
# the "suspex0" entry.
#
# Kilo users have .kilo\kilo.json committed at repo root, Claude Code users
# have .mcp.json committed at repo root -- Claude Desktop lives out-of-tree
# in %APPDATA%, so it needs an installer.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install_claude_desktop.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\install_claude_desktop.ps1 -Url http://127.0.0.1:8765/mcp
#   powershell -ExecutionPolicy Bypass -File scripts\install_claude_desktop.ps1 -StdioFallback
#   powershell -ExecutionPolicy Bypass -File scripts\install_claude_desktop.ps1 -Remove
#
# -StdioFallback wraps the endpoint through `npx mcp-remote` for Claude
# Desktop builds that predate streamable-HTTP support.

param(
    [string]$Url = "http://127.0.0.1:8765/mcp",
    [string]$Name = "suspex0",
    [switch]$StdioFallback,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$configDir = Join-Path $env:APPDATA "Claude"
$configPath = Join-Path $configDir "claude_desktop_config.json"

if (-not (Test-Path $configDir)) {
    Write-Host "creating $configDir"
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

if (Test-Path $configPath) {
    try {
        $raw = Get-Content -Raw -Path $configPath -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $config = [ordered]@{}
        } else {
            $config = $raw | ConvertFrom-Json -ErrorAction Stop
        }
    } catch {
        Write-Error "existing $configPath is not valid JSON: $($_.Exception.Message). Refusing to overwrite; fix or move it aside first."
        exit 1
    }
    # back up before we touch it
    $backup = "$configPath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -Path $configPath -Destination $backup -Force
    Write-Host "backed up existing config to $backup"
} else {
    $config = [ordered]@{}
}

# Normalize to a PSCustomObject with an mcpServers member (may be $null when
# the file existed but only had other keys)
if ($config -isnot [PSCustomObject]) {
    $config = [PSCustomObject]@{}
}
if (-not ($config.PSObject.Properties.Name -contains 'mcpServers') -or $null -eq $config.mcpServers) {
    Add-Member -InputObject $config -MemberType NoteProperty -Name mcpServers -Value ([PSCustomObject]@{}) -Force
}

if ($Remove) {
    if ($config.mcpServers.PSObject.Properties.Name -contains $Name) {
        $config.mcpServers.PSObject.Properties.Remove($Name)
        Write-Host "removed '$Name' from mcpServers"
    } else {
        Write-Host "'$Name' not present in mcpServers - nothing to remove"
    }
} else {
    if ($StdioFallback) {
        $entry = [PSCustomObject]@{
            command = "npx"
            args    = @("-y", "mcp-remote", $Url)
        }
    } else {
        $entry = [PSCustomObject]@{
            type = "http"
            url  = $Url
        }
    }
    if ($config.mcpServers.PSObject.Properties.Name -contains $Name) {
        $config.mcpServers.$Name = $entry
        Write-Host "replaced existing '$Name' entry"
    } else {
        Add-Member -InputObject $config.mcpServers -MemberType NoteProperty -Name $Name -Value $entry -Force
        Write-Host "added '$Name' entry"
    }
}

$json = $config | ConvertTo-Json -Depth 10
# ConvertTo-Json in Windows PowerShell 5.1 emits UTF-16 by default via
# Out-File; force UTF-8 (no BOM would need .NET, BOM is fine here).
[System.IO.File]::WriteAllText($configPath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "wrote $configPath"
Write-Host "restart Claude Desktop for the change to take effect."
if (-not $Remove) {
    Write-Host "the suspex0 orchestrator must be running on $Url - start it with scripts\start_orchestrator.ps1."
}
