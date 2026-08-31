# run_tests.ps1 - Locate a Python interpreter and run the test suite with pytest.
# Exits with pytest's exit code so CI can consume it directly.
# Run with: pwsh ./scripts/run_tests.ps1

$ErrorActionPreference = "Stop"

function Get-PythonCommand {
    # Preference order: py -3 launcher, then python, then python3 on PATH.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @{ Cmd = "py"; Args = @("-3") }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @{ Cmd = "python"; Args = @() }
    }
    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        return @{ Cmd = "python3"; Args = @() }
    }
    return $null
}

$python = Get-PythonCommand
if ($null -eq $python) {
    Write-Error "No Python interpreter found. Install Python 3 or add it to PATH."
    exit 127
}

Write-Host "Using interpreter: $($python.Cmd) $($python.Args)" -ForegroundColor Cyan
Write-Host "Running: $($python.Cmd) $($python.Args) -m pytest tests/ -v" -ForegroundColor Cyan

# Run from the repository root (parent of scripts/) so imports resolve.
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    & $python.Cmd @($python.Args + @("-m", "pytest", "tests/", "-v"))
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($exitCode -eq 0) {
    Write-Host "`nTEST SUITE PASSED" -ForegroundColor Green
} else {
    Write-Host "`nTEST SUITE FAILED (exit code: $exitCode)" -ForegroundColor Red
}
exit $exitCode
