"""
Provider-Neutral Enforcement Interface.
========================================
Defines the standard abstraction for email security enforcement actions:
- block_sender
- block_domain
- block_ip
- quarantine

Enables provider-agnostic integration with future external platforms
(Microsoft 365, Google Workspace, mail gateways, SIEM/SOAR, firewalls)
while guaranteeing that mock/local implementations never masquerade as
successful external blocks.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class EnforcementResult:
    status: str  # "EXECUTED" | "FAILED" | "REJECTED"
    provider: str
    is_demo: bool
    target: str
    action_type: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


class EnforcementProvider(ABC):
    """
    Abstract base class for threat response and enforcement integrations.
    """

    @abstractmethod
    def block_sender(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        """Blocks an email sender address."""
        raise NotImplementedError

    @abstractmethod
    def block_domain(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        """Blocks a domain name."""
        raise NotImplementedError

    @abstractmethod
    def block_ip(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        """Blocks an IP address on network/gateway controls."""
        raise NotImplementedError

    @abstractmethod
    def quarantine(self, target: str, context: Optional[Dict[str, Any]] = None) -> EnforcementResult:
        """Quarantines a message or related artifact."""
        raise NotImplementedError
