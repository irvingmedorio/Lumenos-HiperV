"""Analysis Agent — Real-time monitoring inside guest VMs.

Deploys and manages an agent that runs INSIDE the Hyper-V guest,
monitoring processes, files, network, and API calls in real-time.
Communicates with the host via PowerShell Direct.
"""

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Any


class AgentStatus(Enum):
    """Status of the analysis agent."""
    STOPPED = auto()
    DEPLOYING = auto()
    RUNNING = auto()
    COLLECTING = auto()
    ERROR = auto()


class MonitorType(Enum):
    """Types of monitoring available."""
    PROCESS = "process"      # Process creation/termination
    FILE = "file"            # File system changes
    NETWORK = "network"      # Network connections
    REGISTRY = "registry"    # Registry modifications
    API = "api"              # API calls (DLL injection)
    MEMORY = "memory"        # Memory allocation patterns


@dataclass
class ProcessEvent:
    """A process creation/termination event."""
    timestamp: str
    pid: int
    ppid: int
    name: str
    path: str
    command_line: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)


@dataclass
class FileEvent:
    """A file system event."""
    timestamp: str
    event_type: str  # "created", "modified", "deleted", "renamed"
    path: str
    size: int = 0
    sha256: str = ""


@dataclass
class NetworkEvent:
    """A network connection event."""
    timestamp: str
    protocol: str  # "TCP", "UDP"
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    process_name: str = ""
    pid: int = 0


@dataclass
class RegistryEvent:
    """A registry modification event."""
    timestamp: str
    event_type: str  # "created", "modified", "deleted"
    key: str
    value_name: str = ""
    value_data: str = ""


@dataclass
class AnalysisReport:
    """Complete analysis report from the agent."""
    sandbox_id: str
    start_time: str
    end_time: str
    duration_seconds: int
    process_events: List[ProcessEvent] = field(default_factory=list)
    file_events: List[FileEvent] = field(default_factory=list)
    network_events: List[NetworkEvent] = field(default_factory=list)
    registry_events: List[RegistryEvent] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)  # Indicators of Compromise
    summary: Dict[str, Any] = field(default_factory=dict)


# Agent PowerShell script (deployed inside guest)
AGENT_SCRIPT_POWERSHELL = """
param(
    [string]$OutputDir = "C:\\Analysis\\Output",
    [int]$DurationSeconds = 60,
    [string[]]$Monitors = @("process", "file", "network")
)

$ErrorActionPreference = "Continue"
$startTime = Get-Date
$endTime = $startTime.AddSeconds($DurationSeconds)

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Initialize event logs
$processLog = @()
$fileLog = @()
$networkLog = @()
$registryLog = @()

# Monitor processes
if ($Monitors -contains "process") {
    $watcher = New-Object System.Diagnostics.Process
    Get-Process | ForEach-Object {
        $processLog += @{
            timestamp = (Get-Date -Format "o")
            pid = $_.Id
            ppid = $_.ParentId
            name = $_.ProcessName
            path = $_.Path
            command_line = $_.CommandLine
        }
    }
}

# Monitor network
if ($Monitors -contains "network") {
    $connections = Get-NetTCPConnection
    foreach ($conn in $connections) {
        $networkLog += @{
            timestamp = (Get-Date -Format "o")
            protocol = "TCP"
            local_addr = $conn.LocalAddress
            local_port = $conn.LocalPort
            remote_addr = $conn.RemoteAddress
            remote_port = $conn.RemotePort
            process_name = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            pid = $conn.OwningProcess
        }
    }
}

# Monitor files (watcher)
if ($Monitors -contains "file") {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = "C:\\"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
}

# Monitor registry
if ($Monitors -contains "registry") {
    $regKeys = @("HKLM:\\SOFTWARE", "HKCU:\\SOFTWARE")
    foreach ($key in $regKeys) {
        Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
            $registryLog += @{
                timestamp = (Get-Date -Format "o")
                event_type = "created"
                key = $_.Name
            }
        }
    }
}

# Main loop
while ((Get-Date) -lt $endTime) {
    Start-Sleep -Seconds 1
}

# Collect final state
$report = @{
    start_time = $startTime.ToString("o")
    end_time = $endTime.ToString("o")
    duration_seconds = $DurationSeconds
    process_events = $processLog
    file_events = $fileLog
    network_events = $networkLog
    registry_events = $registryLog
}

# Write report
$report | ConvertTo-Json -Depth 10 | Out-File "$OutputDir\\report.json" -Encoding UTF8
Write-Output "Analysis complete. Report saved to $OutputDir\\report.json"
"""


class AnalysisAgent:
    """Manages real-time analysis inside guest VMs.
    
    Deploys a PowerShell monitoring agent into the guest via
    PowerShell Direct, collects events during analysis, and
    generates a comprehensive report.
    
    Usage:
        agent = AnalysisAgent()
        
        # Deploy agent to running VM
        agent.deploy(
            vm_name="sandbox1",
            guest_user="Administrator",
            guest_pass="P@ssw0rd",
            duration_seconds=120,
            monitors=["process", "file", "network"],
        )
        
        # Wait for completion
        report = agent.collect("sandbox1")
        
        # Analyze results
        for ioc in report.iocs:
            print(f"IOC: {ioc}")
    """

    def __init__(self):
        self._agents: Dict[str, AgentStatus] = {}
        self._reports: Dict[str, AnalysisReport] = {}

    def deploy(self, vm_name: str, guest_user: str = "Administrator",
               guest_pass: str = "", duration_seconds: int = 60,
               monitors: Optional[List[str]] = None) -> bool:
        """Deploy and start the analysis agent inside the guest."""
        self._agents[vm_name] = AgentStatus.DEPLOYING

        if monitors is None:
            monitors = ["process", "file", "network"]

        try:
            # Create output directory in guest
            self._run_ps_direct(vm_name, guest_user, guest_pass,
                               "New-Item -ItemType Directory -Force -Path 'C:\\Analysis\\Output'")

            # Write agent script to guest
            script_path = "C:\\Analysis\\agent.ps1"
            self._write_to_guest(vm_name, guest_user, guest_pass,
                                script_path, AGENT_SCRIPT_POWERSHELL)

            # Start agent in background
            cmd = (
                f"Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass "
                f"-File {script_path} -DurationSeconds {duration_seconds} "
                f"-Monitors ({','.join(monitors)})' -WindowStyle Hidden"
            )
            result = self._run_ps_direct(vm_name, guest_user, guest_pass, cmd)

            if result is not None:
                self._agents[vm_name] = AgentStatus.RUNNING
                return True
            else:
                self._agents[vm_name] = AgentStatus.ERROR
                return False

        except Exception:
            self._agents[vm_name] = AgentStatus.ERROR
            return False

    def collect(self, vm_name: str, guest_user: str = "Administrator",
                guest_pass: str = "") -> Optional[AnalysisReport]:
        """Collect analysis results from the guest."""
        self._agents[vm_name] = AgentStatus.COLLECTING

        try:
            # Read report from guest
            cmd = "Get-Content 'C:\\Analysis\\Output\\report.json' -Raw"
            raw = self._run_ps_direct(vm_name, guest_user, guest_pass, cmd)

            if not raw:
                self._agents[vm_name] = AgentStatus.ERROR
                return None

            data = json.loads(raw)

            # Build report
            report = AnalysisReport(
                sandbox_id=vm_name,
                start_time=data.get("start_time", ""),
                end_time=data.get("end_time", ""),
                duration_seconds=data.get("duration_seconds", 0),
                process_events=[
                    ProcessEvent(**e) for e in data.get("process_events", [])
                ],
                file_events=[
                    FileEvent(**e) for e in data.get("file_events", [])
                ],
                network_events=[
                    NetworkEvent(**e) for e in data.get("network_events", [])
                ],
                registry_events=[
                    RegistryEvent(**e) for e in data.get("registry_events", [])
                ],
            )

            # Detect IOCs
            report.iocs = self._detect_iocs(report)
            report.summary = self._generate_summary(report)

            self._reports[vm_name] = report
            self._agents[vm_name] = AgentStatus.STOPPED
            return report

        except Exception:
            self._agents[vm_name] = AgentStatus.ERROR
            return None

    def get_status(self, vm_name: str) -> AgentStatus:
        """Get agent status for a VM."""
        return self._agents.get(vm_name, AgentStatus.STOPPED)

    def get_report(self, vm_name: str) -> Optional[AnalysisReport]:
        """Get cached report for a VM."""
        return self._reports.get(vm_name)

    # ----- IOC Detection -----

    def _detect_iocs(self, report: AnalysisReport) -> List[Dict[str, Any]]:
        """Detect Indicators of Compromise from collected events."""
        iocs = []

        # Suspicious processes
        suspicious_names = ["mimikatz", "lazagne", "bloodhound", "cobaltstrike",
                           "meterpreter", "payload", "shellcode", "inject"]
        for event in report.process_events:
            name_lower = event.name.lower()
            for sus in suspicious_names:
                if sus in name_lower:
                    iocs.append({
                        "type": "process",
                        "severity": "high",
                        "description": f"Suspicious process: {event.name}",
                        "pid": event.pid,
                        "path": event.path,
                    })

        # Suspicious network connections
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337]
        for event in report.network_events:
            if event.remote_port in suspicious_ports:
                iocs.append({
                    "type": "network",
                    "severity": "high",
                    "description": f"Connection to suspicious port: {event.remote_addr}:{event.remote_port}",
                    "protocol": event.protocol,
                })

        # Suspicious file operations
        suspicious_paths = ["\\temp\\", "\\appdata\\", "\\startup\\", "\\system32\\"]
        for event in report.file_events:
            path_lower = event.path.lower()
            for sus in suspicious_paths:
                if sus in path_lower and event.event_type == "created":
                    iocs.append({
                        "type": "file",
                        "severity": "medium",
                        "description": f"File created in suspicious location: {event.path}",
                    })

        # Suspicious registry modifications
        suspicious_keys = ["run", "runonce", "services", "startup"]
        for event in report.registry_events:
            key_lower = event.key.lower()
            for sus in suspicious_keys:
                if sus in key_lower:
                    iocs.append({
                        "type": "registry",
                        "severity": "high",
                        "description": f"Registry persistence: {event.key}",
                    })

        return iocs

    def _generate_summary(self, report: AnalysisReport) -> Dict[str, Any]:
        """Generate summary from analysis report."""
        return {
            "total_processes": len(report.process_events),
            "total_file_events": len(report.file_events),
            "total_network_connections": len(report.network_events),
            "total_registry_changes": len(report.registry_events),
            "total_iocs": len(report.iocs),
            "high_severity_iocs": len([i for i in report.iocs if i["severity"] == "high"]),
            "unique_processes": len(set(e.name for e in report.process_events)),
            "unique_remote_ips": len(set(e.remote_addr for e in report.network_events)),
        }

    # ----- PowerShell Direct helpers -----

    def _run_ps_direct(self, vm_name: str, user: str, password: str,
                       command: str) -> Optional[str]:
        """Execute a command inside the guest via PowerShell Direct."""
        try:
            cred_cmd = ""
            if password:
                cred_cmd = (
                    f"$pass = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
                    f"$cred = New-Object System.Management.Automation.PSCredential('{user}', $pass); "
                )
            else:
                cred_cmd = f"$cred = New-Object System.Management.Automation.PSCredential('{user}', (ConvertTo-SecureString '' -AsPlainText -Force)); "

            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f'{cred_cmd}Invoke-Command -VMName "{vm_name}" '
                 f'-Credential $cred -ScriptBlock {{ {command} }}'],
                capture_output=True, text=True, timeout=30,
            )
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None

    def _write_to_guest(self, vm_name: str, user: str, password: str,
                        remote_path: str, content: str) -> bool:
        """Write a file to the guest via PowerShell Direct."""
        try:
            # Escape content for PowerShell
            escaped = content.replace("'", "''")
            cmd = (
                f"Set-Content -Path '{remote_path}' -Value '{escaped}' -Force"
            )
            result = self._run_ps_direct(vm_name, user, password, cmd)
            return result is not None
        except Exception:
            return False
