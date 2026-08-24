<#
.SYNOPSIS
  DEV ONLY: mints stand-in subject/actor tokens and exchanges them at POST /oauth2/token.

.EXAMPLE
  .\tools\get-token.ps1
  .\tools\get-token.ps1 -Subject emp-2 -Audience DocumentService      # cross-firm -> 403
  .\tools\get-token.ps1 -Scope "doc.read doc.write"                   # downscoped to doc.read
  .\tools\get-token.ps1 -AuthVersion 0                                # stale epoch -> 400
#>
param(
  [string]$Subject     = "emp-1",
  [string]$Actor       = "client-sys-a",
  [string]$Audience    = "DocumentService",
  [string]$Scope       = "doc.read",
  [int]   $AuthVersion = 1,
  [int]   $Ttl         = 3600,
  [string]$BaseUrl     = "http://localhost:5199"
)

$ErrorActionPreference = "Stop"
$repo  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$mint  = Join-Path $repo "tools\mint-token.cs"
$pem   = Join-Path $repo "dev-signing-key.pem"

function New-Jwt([string]$sub, [int]$version) {
  $jwt = & dotnet run $mint -- $sub $version $Ttl $pem
  if ($LASTEXITCODE -ne 0) { throw "mint-token failed for '$sub'" }
  ($jwt | Select-Object -Last 1).Trim()
}

$body = @{
  grant_type         = "urn:ietf:params:oauth:grant-type:token-exchange"
  subject_token      = New-Jwt $Subject $AuthVersion
  subject_token_type = "urn:ietf:params:oauth:token-type:jwt"
  actor_token        = New-Jwt $Actor 1
  actor_token_type   = "urn:ietf:params:oauth:token-type:jwt"
  audience           = $Audience
  scope              = $Scope
}

try {
  Invoke-RestMethod -Method Post -Uri "$BaseUrl/oauth2/token" `
    -Body $body -ContentType "application/x-www-form-urlencoded" | ConvertTo-Json
}
catch {
  # The guards return 4xx with a JSON body; surface it instead of a bare PowerShell error.
  $response = $_.Exception.Response
  if ($null -eq $response) { throw }
  Write-Host "HTTP $([int]$response.StatusCode)" -ForegroundColor Yellow
  (New-Object System.IO.StreamReader($response.GetResponseStream())).ReadToEnd()
}
