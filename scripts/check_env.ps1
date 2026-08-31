# check_env.ps1 - Environment pre-flight check for LUMENOS Sandbox.
# Prints host OS/CPU/RAM info, checks Hyper-V feature state and verifies that
# hardware virtualization (VT-x / AMD-V) is enabled in firmware.
# Run with: pwsh ./scripts/check_env.ps1
# Note: reading feature state does not require elevation; if the Hyper-V query
# fails (e.g. non-Windows or restricted host), a warning is printed instead.

Write-Host "=== LUMENOS SANDBOX - ENVIRONMENT CHECK ===" -ForegroundColor Cyan

# --- Operating system -------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "`n[OS]"
Write-Host "  Caption : $($os.Caption)"
Write-Host "  Version : $($os.Version)"
Write-Host "  Arch    : $env:PROCESSOR_ARCHITECTURE"

# --- CPU and RAM ------------------------------------------------------------
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$totalRamGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
Write-Host "`n[CPU / RAM]"
Write-Host "  CPU     : $($cpu.Name.Trim())"
Write-Host "  Cores   : $($cpu.NumberOfCores) physical / $($cpu.NumberOfLogicalProcessors) logical"
Write-Host "  RAM     : $totalRamGb GB visible"

# --- Virtualization firmware ------------------------------------------------
Write-Host "`n[Virtualization Firmware (VT-x / AMD-V)]"
if ($null -ne $cpu.VirtualizationFirmwareEnabled) {
    if ($cpu.VirtualizationFirmwareEnabled) {
        Write-Host "  OK: virtualization is enabled in firmware." -ForegroundColor Green
    } else {
        Write-Warning "  VirtualizationFirmwareEnabled is False - enable VT-x/AMD-V in BIOS/UEFI."
    }
} else {
    Write-Warning "  Could not read VirtualizationFirmwareEnabled from Win32_Processor."
}

# --- Hyper-V feature state --------------------------------------------------
Write-Host "`n[Hyper-V Feature]"
try {
    # Get-WindowsOptionalFeature works on Windows; may fail on other hosts.
    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
    switch ($hv.State) {
        'Enabled'    { Write-Host "  OK: Microsoft-Hyper-V-All is ENABLED." -ForegroundColor Green }
        'Disabled'   { Write-Warning "  Hyper-V is DISABLED. Enable with (admin): Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All" }
        default      { Write-Warning "  Hyper-V state: $($hv.State)" }
    }
}
catch {
    Write-Warning "  Could not query Hyper-V state: $($_.Exception.Message)"
    Write-Warning "  This check requires Windows; skipping."
}

Write-Host "`n=== CHECK COMPLETE ===" -ForegroundColor Cyan
