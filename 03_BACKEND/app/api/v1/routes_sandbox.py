import asyncio
import ipaddress
import socket
import urllib.parse
from typing import List, Optional, Tuple, Union

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None

from app.audit import record_audit_event
from app.config import get_settings
from app.database import get_db
from app.models import AuditAction, User, UserRole
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/sandbox", tags=["sandbox"])

_SANDBOX_SEMAPHORE = asyncio.Semaphore(2)

DENIED_DOMAIN_SUFFIXES = (
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    "metadata.google.internal",
)


def parse_ip_literal(host: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """
    Parses IP literals in standard or non-standard encodings:
    - Standard dotted IPv4 and standard IPv6
    - Integer / Decimal IPv4 (e.g. 2130706433 -> 127.0.0.1)
    - Octal or hex encoded dotted IPv4 (e.g. 0177.0.0.1, 0x7f.0.0.1)
    - Short dotted notation (e.g. 127.1 -> 127.0.0.1)
    - IPv4-mapped IPv6 (e.g. [::ffff:127.0.0.1])
    """
    clean_host = host.strip("[]")
    try:
        return ipaddress.ip_address(clean_host)
    except ValueError:
        pass

    # Decimal integer IP
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # Dotted notation with octal, hex, or fewer than 4 components
    parts = clean_host.split(".")
    if 1 <= len(parts) <= 4:
        try:
            int_parts = []
            for p in parts:
                if p.startswith(("0x", "0X")):
                    int_parts.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    int_parts.append(int(p, 8))
                elif p.isdigit():
                    int_parts.append(int(p, 10))
                else:
                    return None
            if len(int_parts) == 1:
                val = int_parts[0]
            elif len(int_parts) == 2:
                val = (int_parts[0] << 24) | (int_parts[1] & 0xFFFFFF)
            elif len(int_parts) == 3:
                val = (int_parts[0] << 24) | ((int_parts[1] & 0xFF) << 16) | (int_parts[2] & 0xFFFF)
            else:
                val = (int_parts[0] << 24) | (int_parts[1] << 16) | (int_parts[2] << 8) | int_parts[3]
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    return None


def is_prohibited_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Validates IP against loopback, private RFC 1918, link-local, cloud metadata,
    unique-local IPv6, multicast, reserved, and unspecified destinations.
    """
    if ip.is_loopback:
        return True, "loopback IP destination"
    if ip.is_private:
        return True, "private RFC 1918 IP destination"
    if ip.is_link_local:
        return True, "link-local IP destination"
    if ip.is_multicast:
        return True, "multicast IP destination"
    if ip.is_reserved:
        return True, "reserved IP destination"
    if ip.is_unspecified:
        return True, "unspecified IP destination"
    if str(ip) in ("169.254.169.254", "fd00:ec2::254"):
        return True, "cloud metadata IP destination"

    # IPv6 checks
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            mapped_blocked, mapped_reason = is_prohibited_ip(ip.ipv4_mapped)
            if mapped_blocked:
                return True, f"IPv4-mapped {mapped_reason}"
        if ip in ipaddress.IPv6Network("fc00::/7"):
            return True, "unique-local IPv6 destination"

    return False, ""


def _validate_safe_sandbox_url(raw_url: str) -> str:
    """
    Strict SSRF validation:
    - Only http and https protocols permitted (rejects file://, ftp://, data://).
    - Checks literal IP addresses in all representations (octal, hex, decimal, short, mapped).
    - Checks domain denylist (localhost, local, internal, cloud metadata).
    - Performs DNS resolution on hostnames and verifies EVERY resolved address.
    """
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format",
        )

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Prohibited URL scheme '{scheme}'. Only http and https schemes are permitted.",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing URL hostname",
        )

    # 1. Check if hostname is an IP literal
    ip = parse_ip_literal(hostname)
    if ip:
        blocked, reason = is_prohibited_ip(ip)
        if blocked:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Prohibited target: {reason} is forbidden.",
            )
        return raw_url

    # 2. Check local / internal hostname denylist
    lower_host = hostname.lower()
    if any(lower_host == d or lower_host.endswith(d) for d in DENIED_DOMAIN_SUFFIXES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Prohibited target: local, loopback, or cloud metadata destinations are forbidden.",
        )

    # 3. Resolve DNS and validate every resolved IP (IPv4 and IPv6)
    try:
        addr_infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: failed to resolve DNS hostname '{hostname}'.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="DNS resolution failed for requested URL.",
        )

    for _, _, _, _, sockaddr in addr_infos:
        resolved_ip_str = sockaddr[0]
        resolved_ip = parse_ip_literal(resolved_ip_str)
        if resolved_ip:
            blocked, reason = is_prohibited_ip(resolved_ip)
            if blocked:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Prohibited target: hostname resolves to prohibited {reason} ({resolved_ip_str}).",
                )

    return raw_url


@router.get("/screenshot")
async def get_sandbox_screenshot(
    url: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. URL SSRF Validation
    safe_url = _validate_safe_sandbox_url(url)

    # 2. Role Gating: ANALYST or ADMIN only
    if user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions: sandbox screenshot feature is restricted to ANALYST and ADMIN roles.",
        )

    # 3. Runtime Extra Check
    if not PLAYWRIGHT_AVAILABLE or async_playwright is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sandbox screenshot feature is unavailable because the optional 'playwright' package is not installed. Install with: pip install hopzero[sandbox]",
        )

    # 4. Settings check (feature toggle off by default)
    settings = get_settings()
    if not getattr(settings, "sandbox_screenshot_enabled", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sandbox screenshot feature is disabled. Set SANDBOX_SCREENSHOT_ENABLED=1 to enable.",
        )

    async with _SANDBOX_SEMAPHORE:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    accept_downloads=False,
                )
                page = await context.new_page()

                # Request interception to block SSRF on redirects and subresources
                async def handle_route(route, request):
                    try:
                        _validate_safe_sandbox_url(request.url)
                        await route.continue_()
                    except Exception:
                        await route.abort("blockedbyclient")

                await page.route("**/*", handle_route)

                timeout_ms = int(getattr(settings, "sandbox_timeout_seconds", 10.0) * 1000)
                await page.goto(safe_url, wait_until="networkidle", timeout=timeout_ms)
                screenshot_bytes = await page.screenshot(full_page=False)
                await browser.close()

                # Log AuditEvent
                record_audit_event(
                    db,
                    organization_id=user.organization_id,
                    action=AuditAction.SANDBOX_SCREENSHOT_CAPTURED,
                    actor_user_id=user.id,
                    metadata={"url": safe_url},
                )
                db.commit()

                return Response(content=screenshot_bytes, media_type="image/png")
        except HTTPException:
            raise
        except Exception as e:
            err_str = str(e).lower()
            if "executable doesn't exist" in err_str or "playwright install" in err_str:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Sandbox browser binary not found. Run 'playwright install chromium' to install browser binaries.",
                )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate sandbox screenshot: {e}",
            )
