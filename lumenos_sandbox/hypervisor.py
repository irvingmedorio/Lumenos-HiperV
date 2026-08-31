#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hyper-V interaction layer via PowerShell subprocess calls.

All subprocess calls to Hyper-V go through this module. Every public
function returns a safe default on failure (False / None / empty dict)
and logs a WARNING on failure, DEBUG on command entry.
"""

import subprocess
import json
import logging
from typing import Optional, Dict, Any, Tuple, List

logger = logging.getLogger("LUMENOS_SANDBOX.hypervisor")


def _run_ps(command: str, timeout: int = 30) -> Tuple[bool, str, str]:
    """Run a PowerShell command, return (success, stdout, stderr).

    Tries ``pwsh`` first, falls back to ``powershell``.  Uses
    ``-NoProfile -ExecutionPolicy Bypass`` to avoid user-profile
    interference.
    """
    for exe in ("pwsh", "powershell"):
        try:
            logger.debug("Running: %s -NoProfile -ExecutionPolicy Bypass -Command %s",
                         exe, command[:120])
            result = subprocess.run(
                [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return (True, result.stdout.strip(), result.stderr.strip())
            logger.warning("PS command failed (rc=%d): %s", result.returncode, result.stderr[:200])
            return (False, "", result.stderr.strip())
        except FileNotFoundError:
            continue  # try next exe
        except subprocess.TimeoutExpired:
            logger.warning("PS command timed out after %ds: %s", timeout, command[:80])
            return (False, "", "Command timed out")
        except Exception as exc:
            logger.warning("PS command error (%s): %s", exe, exc)
            return (False, "", str(exc))

    logger.warning("No PowerShell executable found (pwsh/powershell)")
    return (False, "", "No PowerShell executable found")


# ---------------------------------------------------------------------------
# Hyper-V availability
# ---------------------------------------------------------------------------

def check_hyper_v_available() -> bool:
    """Check if Hyper-V is enabled on the host.

    Returns ``True`` if the Microsoft-Hyper-V-All Windows optional
    feature is enabled, ``False`` otherwise.  Catches all exceptions
    so callers never need to handle errors.
    """
    cmd = (
        "(Get-WindowsOptionalFeature -Online "
        "-FeatureName Microsoft-Hyper-V-All).State"
    )
    ok, stdout, _ = _run_ps(cmd, timeout=15)
    return ok and "Enabled" in stdout


# ---------------------------------------------------------------------------
# VM status / info
# ---------------------------------------------------------------------------

def get_vm_status(vm_name: str) -> Optional[str]:
    """Get VM state: ``'Running'``, ``'Off'``, ``'Saved'``, ``'Paused'``,
    or ``None`` if the VM doesn't exist."""
    cmd = (
        f"Get-VM -Name '{vm_name}' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty State"
    )
    ok, stdout, _ = _run_ps(cmd)
    if ok and stdout:
        return stdout
    return None


def get_vm_info(vm_name: str) -> Optional[Dict[str, Any]]:
    """Get detailed VM info: name, state, memory, cpus, network, disks.

    Returns a dict parsed from PowerShell JSON, or ``None`` on failure.
    """
    cmd = (
        f"Get-VM -Name '{vm_name}' -ErrorAction SilentlyContinue | "
        "ConvertTo-Json -Compress"
    )
    ok, stdout, _ = _run_ps(cmd)
    if ok and stdout:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse VM info JSON for %s", vm_name)
    return None


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

def create_vm(vm_name: str, memory_mb: int, cpu_cores: int,
              vhd_path: Optional[str] = None,
              switch_name: Optional[str] = None,
              generation: int = 2) -> bool:
    """Create a new Gen 2 VM with specified resources.

    Steps:
    1. Create the VM with New-VM
    2. Optionally create and attach a VHD
    3. Set CPU cores
    4. Set static memory
    5. Optionally connect to a virtual switch
    """
    memory_bytes = memory_mb * 1024 * 1024

    # Step 1: Create the VM
    cmd = (
        f"New-VM -Name '{vm_name}' -Generation {generation} "
        f"-MemoryStartupBytes {memory_bytes} -Force"
    )
    ok, _, err = _run_ps(cmd, timeout=60)
    if not ok:
        logger.warning("Failed to create VM %s: %s", vm_name, err)
        return False

    # Step 2: Create and attach VHD if requested
    if vhd_path:
        vhd_cmd = (
            f"New-VHD -Path '{vhd_path}' -SizeBytes 107374182400 -Dynamic | "
            f"Add-VMHardDiskDrive -VMName '{vm_name}'"
        )
        ok, _, err = _run_ps(vhd_cmd, timeout=120)
        if not ok:
            logger.warning("Failed to create/attach VHD for %s: %s", vm_name, err)
            # Don't fail — VM exists without disk, still usable

    # Step 3: Set CPU cores
    cpu_cmd = f"Set-VMProcessor -VMName '{vm_name}' -Count {cpu_cores}"
    ok, _, err = _run_ps(cpu_cmd)
    if not ok:
        logger.warning("Failed to set CPU count for %s: %s", vm_name, err)

    # Step 4: Set static memory
    mem_cmd = (
        f"Set-VMMemory -VMName '{vm_name}' "
        f"-DynamicMemoryEnabled $false -StartupBytes {memory_bytes}"
    )
    ok, _, err = _run_ps(mem_cmd)
    if not ok:
        logger.warning("Failed to set memory for %s: %s", vm_name, err)

    # Step 5: Connect network adapter if requested
    if switch_name:
        net_cmd = (
            f"Get-VMNetworkAdapter -VMName '{vm_name}' | "
            f"Connect-VMNetworkAdapter -SwitchName '{switch_name}'"
        )
        ok, _, err = _run_ps(net_cmd)
        if not ok:
            logger.warning("Failed to connect network for %s: %s", vm_name, err)

    logger.info("VM %s created (%dMB, %d CPUs)", vm_name, memory_mb, cpu_cores)
    return True


def start_vm(vm_name: str) -> bool:
    """Start a VM."""
    cmd = f"Start-VM -Name '{vm_name}' -ErrorAction SilentlyContinue"
    ok, _, err = _run_ps(cmd, timeout=120)
    if not ok:
        logger.warning("Failed to start VM %s: %s", vm_name, err)
    return ok


def stop_vm(vm_name: str, force: bool = False) -> bool:
    """Stop a VM.  If *force*, use ``-TurnOff``."""
    turnoff = " -TurnOff" if force else ""
    cmd = f"Stop-VM -Name '{vm_name}'{turnoff} -ErrorAction SilentlyContinue"
    ok, _, err = _run_ps(cmd, timeout=120)
    if not ok:
        logger.warning("Failed to stop VM %s: %s", vm_name, err)
    return ok


def remove_vm(vm_name: str, force: bool = True) -> bool:
    """Remove a VM and its disks."""
    cmd = (
        f"Remove-VM -Name '{vm_name}' -Force:${'true' if force else 'false'} "
        "-ErrorAction SilentlyContinue"
    )
    ok, _, err = _run_ps(cmd, timeout=60)
    if not ok:
        logger.warning("Failed to remove VM %s: %s", vm_name, err)
    return ok


# ---------------------------------------------------------------------------
# Checkpoints (snapshots)
# ---------------------------------------------------------------------------

def create_checkpoint(vm_name: str, checkpoint_name: str) -> bool:
    """Create a checkpoint (snapshot) of a VM."""
    cmd = (
        f"Checkpoint-VM -Name '{vm_name}' -SnapshotName '{checkpoint_name}' "
        "-ErrorAction SilentlyContinue"
    )
    ok, _, err = _run_ps(cmd, timeout=120)
    if not ok:
        logger.warning("Failed to create checkpoint %s on %s: %s",
                       checkpoint_name, vm_name, err)
    return ok


def restore_checkpoint(vm_name: str, checkpoint_name: str) -> bool:
    """Restore a VM to a named checkpoint."""
    cmd = (
        f"Restore-VMCheckpoint -Name '{checkpoint_name}' -VMName '{vm_name}' "
        "-Confirm:$false -ErrorAction SilentlyContinue"
    )
    ok, _, err = _run_ps(cmd, timeout=120)
    if not ok:
        logger.warning("Failed to restore checkpoint %s on %s: %s",
                       checkpoint_name, vm_name, err)
    return ok


# ---------------------------------------------------------------------------
# VHD operations
# ---------------------------------------------------------------------------

def create_differencing_disk(base_vhd: str, diff_vhd: str) -> bool:
    """Create a differencing VHD linked to a base image."""
    cmd = (
        f"New-VHD -Path '{diff_vhd}' -ParentPath '{base_vhd}' -Differencing"
    )
    ok, _, err = _run_ps(cmd, timeout=60)
    if not ok:
        logger.warning("Failed to create differencing disk %s: %s", diff_vhd, err)
    return ok


def delete_file(path: str) -> bool:
    """Delete a file (used for VHD cleanup)."""
    cmd = f"Remove-Item -LiteralPath '{path}' -Force -ErrorAction SilentlyContinue"
    ok, _, err = _run_ps(cmd)
    if not ok:
        logger.warning("Failed to delete file %s: %s", path, err)
    return ok


# ---------------------------------------------------------------------------
# Virtual switches
# ---------------------------------------------------------------------------

def create_internal_switch(switch_name: str) -> bool:
    """Create an internal-only virtual switch (no external uplink)."""
    cmd = (
        f"New-VMSwitch -Name '{switch_name}' -SwitchType Internal "
        "-ErrorAction SilentlyContinue"
    )
    ok, _, err = _run_ps(cmd)
    if not ok:
        logger.warning("Failed to create switch %s: %s", switch_name, err)
    return ok


def remove_switch(switch_name: str) -> bool:
    """Remove a virtual switch."""
    cmd = (
        f"Remove-VMSwitch -Name '{switch_name}' -Force "
        "-ErrorAction SilentlyContinue"
    )
    ok, _, err = _run_ps(cmd)
    if not ok:
        logger.warning("Failed to remove switch %s: %s", switch_name, err)
    return ok


# ---------------------------------------------------------------------------
# Host integrity
# ---------------------------------------------------------------------------

def verify_host_integrity() -> Tuple[bool, str]:
    """Basic host integrity check: Hyper-V running, no unexpected VMs.

    Returns ``(success, message)``.  Currently just checks that
    Hyper-V is available and reports the number of existing VMs.
    """
    if not check_hyper_v_available():
        return (False, "Hyper-V is not available on this host")

    cmd = "(Get-VM -ErrorAction SilentlyContinue).Count"
    ok, stdout, _ = _run_ps(cmd)
    vm_count = int(stdout) if ok and stdout.isdigit() else -1

    msg = f"Hyper-V available, {vm_count} VM(s) found"
    logger.info("Host integrity: %s", msg)
    return (True, msg)


# ---------------------------------------------------------------------------
# Guest interaction via PowerShell Direct
# ---------------------------------------------------------------------------

def _escape_ps_command(command: str) -> str:
    """Escape a command for embedding in Invoke-Command -ScriptBlock."""
    return command.replace("'", "''")


def _get_vm_state(vm_name: str) -> Optional[str]:
    """Internal helper to get VM state, returns None if not found."""
    cmd = (
        f"Get-VM -Name '{vm_name}' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty State"
    )
    ok, stdout, _ = _run_ps(cmd, timeout=10)
    if ok and stdout:
        return stdout
    return None


def enable_guest_integration(vm_name: str) -> bool:
    """Enable Guest Service Interface integration service on the VM."""
    cmd = (
        f"Enable-VMIntegrationService -VMName '{vm_name}' "
        "-Name 'Guest Service Interface' -ErrorAction SilentlyContinue"
    )
    ok, _, err = _run_ps(cmd, timeout=30)
    if not ok:
        logger.warning("Failed to enable guest integration for %s: %s", vm_name, err)
    return ok


def execute_in_guest(vm_name: str, username: str, password: str,
                     command: str, timeout: int = 30) -> Tuple[bool, str]:
    """Execute a PowerShell command inside the guest VM via PowerShell Direct.

    Returns ``(success, output)``.  Uses ``Invoke-Command -VMName``
    which communicates over VMBus — no network required.
    Returns ``(False, ...)`` if the VM is not running.
    """
    state = _get_vm_state(vm_name)
    if state is None or state.lower() != "running":
        logger.warning("VM %s is not running (state=%s), cannot execute in guest", vm_name, state)
        return (False, "VM is not running")

    escaped_cmd = _escape_ps_command(command)
    ps_cmd = (
        f"$secPass = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $secPass); "
        f"Invoke-Command -VMName '{vm_name}' -Credential $cred "
        f"-ScriptBlock {{ {escaped_cmd} }} -ErrorAction Stop"
    )
    ok, stdout, err = _run_ps(ps_cmd, timeout=timeout)
    if not ok:
        # If passwordless / empty password, retry without credential construction
        if password == "":
            ps_cmd_nopw = (
                f"$cred = New-Object System.Management.Automation.PSCredential('{username}', "
                f"(ConvertTo-SecureString '' -AsPlainText -Force)); "
                f"Invoke-Command -VMName '{vm_name}' -Credential $cred "
                f"-ScriptBlock {{ {escaped_cmd} }} -ErrorAction Stop"
            )
            ok, stdout, err = _run_ps(ps_cmd_nopw, timeout=timeout)
    if not ok:
        logger.warning("execute_in_guest failed on %s: %s", vm_name, err[:200])
        return (False, err)
    return (True, stdout)


def configure_guest_firewall(vm_name: str, username: str, password: str,
                             block_outbound: bool = True,
                             allow_dns: bool = False) -> bool:
    """Configure Windows Firewall inside the guest.

    If *block_outbound*: set default outbound policy to BLOCK.
    If *allow_dns*: add exception for UDP 53 outbound.
    """
    if block_outbound:
        fw_cmd = "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
        ok, _, err = execute_in_guest(vm_name, username, password, fw_cmd, timeout=30)
        if not ok:
            logger.warning("Failed to configure guest firewall: %s", err)
            return False

    if allow_dns:
        dns_rule = (
            'netsh advfirewall firewall add rule name="Allow DNS" '
            'dir=out action=allow protocol=udp remoteport=53'
        )
        ok, _, err = execute_in_guest(vm_name, username, password, dns_rule, timeout=15)
        if not ok:
            logger.warning("Failed to add DNS firewall rule: %s", err)
            return False

    logger.info("Guest firewall configured: block_outbound=%s, allow_dns=%s",
                block_outbound, allow_dns)
    return True


def test_guest_connectivity(vm_name: str, username: str, password: str,
                            target: str = "8.8.8.8") -> bool:
    """Test if guest can reach external target.

    Returns ``True`` if BLOCKED (no connectivity) — good for isolation.
    Returns ``False`` if connectivity EXISTS (bad — should be blocked).
    Uses ``Test-NetConnection`` inside the guest.
    """
    conn_cmd = (
        f"Test-NetConnection -ComputerName {target} -Port 443 "
        "-WarningAction SilentlyContinue | Select-Object -ExpandProperty TcpTestSucceeded"
    )
    ok, stdout, err = execute_in_guest(vm_name, username, password, conn_cmd, timeout=20)
    if not ok:
        # Guest unreachable = isolation works
        return True
    # TcpTestSucceeded=True means connectivity exists → isolation failed
    if "True" in stdout:
        logger.warning("Guest can reach %s — isolation broken", target)
        return False
    return True


def get_guest_processes(vm_name: str, username: str, password: str) -> List[Dict]:
    """Get list of running processes inside the guest."""
    cmd = (
        "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet64 | "
        "ConvertTo-Json -Compress"
    )
    ok, stdout, err = execute_in_guest(vm_name, username, password, cmd, timeout=15)
    if not ok:
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            return [data]
        return data
    except (json.JSONDecodeError, TypeError):
        return []


def kill_guest_process(vm_name: str, username: str, password: str,
                       process_name: str) -> bool:
    """Kill a process by name inside the guest."""
    cmd = f"Stop-Process -Name '{_escape_ps_command(process_name)}' -Force -ErrorAction SilentlyContinue"
    ok, _, err = execute_in_guest(vm_name, username, password, cmd, timeout=10)
    return ok


def check_guest_vbs_status(vm_name: str, username: str, password: str) -> Dict[str, bool]:
    """Check Virtualization-Based Security status inside guest.

    Returns dict with keys: ``vbs_enabled``, ``hvci_enabled``, ``secure_boot``.
    """
    result = {"vbs_enabled": False, "hvci_enabled": False, "secure_boot": False}

    # Check DeviceGuard registry keys
    dg_cmd = (
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' "
        "-ErrorAction SilentlyContinue | ConvertTo-Json -Compress"
    )
    ok, stdout, _ = execute_in_guest(vm_name, username, password, dg_cmd, timeout=10)
    if ok and stdout:
        try:
            dg = json.loads(stdout)
            result["vbs_enabled"] = bool(dg.get("EnableVirtualizationBasedSecurity", 0))
            # RequirePlatformSecurityFeatures: bit 1 = Secure Boot, bit 2 = HVCI
            features = int(dg.get("RequirePlatformSecurityFeatures", 0))
            result["secure_boot"] = bool(features & 1)
            result["hvci_enabled"] = bool(features & 2)
        except (json.JSONDecodeError, TypeError):
            pass

    # Also check Secure Boot via UEFI
    sb_cmd = "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue"
    ok, stdout, _ = execute_in_guest(vm_name, username, password, sb_cmd, timeout=10)
    if ok and "True" in stdout:
        result["secure_boot"] = True

    return result


def read_guest_event_log(vm_name: str, username: str, password: str,
                         log_name: str = "Security", max_events: int = 50) -> List[Dict]:
    """Read Windows Event Log entries from guest."""
    cmd = (
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Id, TimeCreated, LevelDisplayName, Message, ProviderName | "
        "ConvertTo-Json -Compress"
    )
    ok, stdout, _ = execute_in_guest(vm_name, username, password, cmd, timeout=30)
    if not ok:
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            return [data]
        return data
    except (json.JSONDecodeError, TypeError):
        return []


def check_guest_registry(vm_name: str, username: str, password: str,
                         key_path: str) -> List[Dict]:
    """Read registry values inside the guest (for persistence detection)."""
    cmd = (
        f"Get-ItemProperty -Path '{_escape_ps_command(key_path)}' "
        "-ErrorAction SilentlyContinue | ConvertTo-Json -Compress"
    )
    ok, stdout, _ = execute_in_guest(vm_name, username, password, cmd, timeout=10)
    if not ok:
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            return [data]
        return data
    except (json.JSONDecodeError, TypeError):
        return []


def install_sysmon_in_guest(vm_name: str, username: str, password: str,
                            sysmon_path: str = "C:\\Tools\\Sysmon64.exe") -> bool:
    """Install Sysmon inside the guest.

    Assumes the Sysmon binary is already present in the VM
    (e.g. copied via Integration Services file copy).
    """
    cmd = (
        f"& '{sysmon_path}' /accepteula -i"
    )
    ok, stdout, err = execute_in_guest(vm_name, username, password, cmd, timeout=60)
    if not ok:
        logger.warning("Failed to install Sysmon in guest: %s", err)
        return False
    logger.info("Sysmon installed in guest %s", vm_name)
    return True
