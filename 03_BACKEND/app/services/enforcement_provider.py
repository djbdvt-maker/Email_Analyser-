"""
Mock / Local Provider Implementation for Provider-Neutral Enforcement.
======================================================================
Provides a safe local/mock implementation for demonstration and testing.
The provider clearly reports:
- is_demo: True
- provider: "mock_local_provider"
- honest status: never masquerades as modifying live M365 or Google Workspace.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Set
import subprocess
import socket

from app.interfaces.enforcement import EnforcementProvider, EnforcementResult
from app.config import Settings

_settings = Settings()

class MockLocalEnforcementProvider(EnforcementProvider):
    """
    In-memory / local demonstration enforcement provider.
    Supports simulated failures for test coverage.
    """

    def __init__(self):
        self.blocked_senders: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.quarantined_targets: Set[str] = set()

    def _execute(
        self, action_type: str, target: str, context: Optional[Dict[str, Any]] = None
    ) -> EnforcementResult:
        ctx = context or {}
        if ctx.get("simulate_failure"):
            return EnforcementResult(
                status="FAILED",
                provider="mock_local_provider",
                is_demo=True,
                target=target,
                action_type=action_type,
                message=f"Simulated provider failure while executing {action_type} on target {target}",
                details={"error": "Simulated downstream gateway timeout", "simulated": True},
            )

        now_str = datetime.now(timezone.utc).isoformat()

        if action_type == "BLOCK_SENDER":
            self.blocked_senders.add(target)
        elif action_type == "BLOCK_DOMAIN":
            self.blocked_domains.add(target)
        elif action_type == "BLOCK_IP":
            self.blocked_ips.add(target)
        elif action_type == "QUARANTINE":
            self.quarantined_targets.add(target)

        return EnforcementResult(
            status="EXECUTED",
            provider="mock_local_provider",
            is_demo=True,
            target=target,
            action_type=action_type,
            message="Executed on local demo enforcement provider (external mail provider not modified)",
            details={
                "executed_at": now_str,
                "scope": "local_demonstration",
                "backend": "mock_local_provider",
            },
        )

    def block_sender(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("BLOCK_SENDER", target, context)

    def block_domain(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("BLOCK_DOMAIN", target, context)

    def block_ip(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("BLOCK_IP", target, context)

    def quarantine(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("QUARANTINE", target, context)


class WindowsDefenderEnforcementProvider(EnforcementProvider):
    """
    Physically modifies Windows Defender Firewall for IP blocks and domains (via DNS resolution).
    This is an explicitly OPT-IN real firewall provider.
    """
    def _execute(
        self, action_type: str, target: str, context: Optional[Dict[str, Any]] = None
    ) -> EnforcementResult:
        if action_type not in ("BLOCK_IP", "BLOCK_DOMAIN"):
            # Fallback behavior or fail if action is unsupported by Windows Firewall
            return EnforcementResult(
                status="FAILED",
                provider="windows_defender_firewall",
                is_demo=False,
                target=target,
                action_type=action_type,
                message=f"Action type {action_type} is not supported by Windows Defender Firewall",
                details={"error": "Unsupported action"},
            )
            
        ips_to_block = []
        if action_type == "BLOCK_IP":
            ips_to_block.append(target)
        elif action_type == "BLOCK_DOMAIN":
            try:
                resolved_ips = socket.gethostbyname_ex(target)[2]
                ips_to_block.extend(resolved_ips)
            except Exception as e:
                return EnforcementResult(
                    status="FAILED",
                    provider="windows_defender_firewall",
                    is_demo=False,
                    target=target,
                    action_type=action_type,
                    message=f"DNS resolution for firewall failed: {e}",
                    details={"error": str(e)},
                )

        successes = []
        failures = []
        for ip in ips_to_block:
            rule_name = f"HopZero Threat Block: {ip}"
            cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound -Action Block -RemoteAddress {ip} -ErrorAction Stop'
            
            try:
                proc = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
                if proc.returncode == 0:
                    successes.append(ip)
                else:
                    failures.append((ip, proc.stderr.strip() or "Access Denied (Requires Admin)"))
            except Exception as e:
                failures.append((ip, str(e)))

        if failures and not successes:
            return EnforcementResult(
                status="FAILED",
                provider="windows_defender_firewall",
                is_demo=False,
                target=target,
                action_type=action_type,
                message=f"OS Firewall failed: {failures[0][1]}",
                details={"error": failures[0][1]},
            )
            
        return EnforcementResult(
            status="EXECUTED",
            provider="windows_defender_firewall",
            is_demo=False,
            target=target,
            action_type=action_type,
            message="Physical block executed securely via Windows Defender Firewall.",
            details={"firewall_blocked_ips": successes, "failures": [f[1] for f in failures] if failures else []},
        )

    def block_sender(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("BLOCK_SENDER", target, context)

    def block_domain(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("BLOCK_DOMAIN", target, context)

    def block_ip(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("BLOCK_IP", target, context)

    def quarantine(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        return self._execute("QUARANTINE", target, context)

_mock_instance = MockLocalEnforcementProvider()
_windows_instance = WindowsDefenderEnforcementProvider()

def get_default_enforcement_provider() -> EnforcementProvider:
    if _settings.enforcement_provider == "windows_defender":
        return _windows_instance
    return _mock_instance
