"""
HopZero Domain & Lookalike Checker Package.
===========================================
First standalone tool in the HopZero Tool Suite family.
"""
import sys
import os
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_forensics = os.path.join(_repo_root, "02_FORENSICS")
if os.path.isdir(_forensics) and _forensics not in sys.path:
    sys.path.insert(0, _forensics)

from .manifest import DOMAIN_TOOL_MANIFEST
from .service import (
    analyze_domain,
    analyze_domains_batch,
    DomainCheckResult,
    check_brand_lookalike,
    check_punycode,
    check_mixed_script,
    normalize_domain_string,
)
from .router import (
    router as domain_tool_router,
    DOMAIN_TOOL_VERSION_INFO,
)

__all__ = [
    "DOMAIN_TOOL_MANIFEST",
    "DOMAIN_TOOL_VERSION_INFO",
    "domain_tool_router",
    "analyze_domain",
    "analyze_domains_batch",
    "DomainCheckResult",
    "check_brand_lookalike",
    "check_punycode",
    "check_mixed_script",
    "normalize_domain_string",
]
