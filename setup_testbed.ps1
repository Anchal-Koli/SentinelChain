# SentinelChain Host Environment Verifier & Setup Script
# Run this script in PowerShell to verify host dependencies and initiate container build

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   SentinelChain Host Setup & Diagnostic Check    " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Check if Docker is installed
Write-Host ""
Write-Host "[1/3] Checking Docker Installation..." -ForegroundColor Yellow
$dockerCheck = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCheck) {
    $dockerVer = docker --version
    Write-Host "OK: Docker is installed: $dockerVer" -ForegroundColor Green
} else {
    Write-Host "ERROR: Docker is NOT detected in host PATH." -ForegroundColor Red
    Write-Host "Action Required: Please install Docker Desktop (https://www.docker.com/products/docker-desktop/) and ensure it is running." -ForegroundColor White
    exit
}

# 2. Check WSL2 status
Write-Host ""
Write-Host "[2/3] Checking WSL2 Integration..." -ForegroundColor Yellow
$wslCheck = wsl --status 2>$null
if ($wslCheck) {
    Write-Host "OK: WSL2 is active and default distribution kernel is ready." -ForegroundColor Green
} else {
    Write-Host "WARNING: WSL status command failed or WSL2 is not enabled." -ForegroundColor Yellow
    Write-Host "Action Required: Ensure Virtualization is enabled in BIOS and WSL2 features are installed on your Windows Host." -ForegroundColor White
}

# 3. Verify files and launch container build
Write-Host ""
Write-Host "[3/3] Checking Project Setup Files..." -ForegroundColor Yellow

$dockerfileCheck = Test-Path "Dockerfile"
if ($dockerfileCheck) {
    Write-Host "OK: Dockerfile detected." -ForegroundColor Green
} else {
    Write-Host "ERROR: Dockerfile missing." -ForegroundColor Red
    exit
}

$composeCheck = Test-Path "docker-compose.yml"
if ($composeCheck) {
    Write-Host "OK: docker-compose.yml detected." -ForegroundColor Green
} else {
    Write-Host "ERROR: docker-compose.yml missing." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Executing container build pipeline: 'docker-compose build'..." -ForegroundColor Cyan
docker-compose build

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "                 SETUP COMPLETE                   " -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host "To start the container, run: 'docker-compose up -d'" -ForegroundColor White
Write-Host "To access the container shell, run: 'docker exec -it sentinelchain-forensics bash'" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor Green
