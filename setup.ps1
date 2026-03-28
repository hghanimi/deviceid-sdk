# Athar Setup Script — Run this once to clear DB and create user accounts
# Usage: .\setup.ps1

$API = "https://api.arch-hayder.workers.dev"
$Headers = @{ "X-API-Key" = "pk_live_athar_001"; "Content-Type" = "application/json" }

Write-Host "`n=== Step 1: Check Existing Admin Login ===" -ForegroundColor Cyan
try {
    $body = '{"username":"admin","password":"admin"}'
    $login = Invoke-RestMethod -Method POST -Uri "$API/v1/auth/login" -Headers $Headers -Body $body
    Write-Host "Admin already active. Login successful for: $($login.user.displayName)" -ForegroundColor Green
} catch {
    Write-Host "Admin login not ready yet; will attempt registration..." -ForegroundColor Yellow
}

Write-Host "`n=== Step 2: Register Athar Admin User (If Needed) ===" -ForegroundColor Cyan
try {
    $body = '{"username":"admin","password":"admin","displayName":"System Admin"}'
    $user1 = Invoke-RestMethod -Method POST -Uri "$API/v1/auth/register" -Headers $Headers -Body $body
    Write-Host "Created: $($user1.user.username) (Athar admin)" -ForegroundColor Green
} catch {
    Write-Host "Admin registration skipped: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n=== Step 3: Test Login ===" -ForegroundColor Cyan
try {
    $body = '{"username":"admin","password":"admin"}'
    $login = Invoke-RestMethod -Method POST -Uri "$API/v1/auth/login" -Headers $Headers -Body $body
    Write-Host "Login successful! User: $($login.user.displayName), API Key: $($login.apiKey)" -ForegroundColor Green
} catch {
    Write-Host "Login test: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Setup Complete! ===" -ForegroundColor Green
Write-Host "Portal: https://deviceid-cdn.pages.dev/portal" -ForegroundColor Cyan
Write-Host ""
Write-Host "  admin / admin     (Athar Admin)" -ForegroundColor White
