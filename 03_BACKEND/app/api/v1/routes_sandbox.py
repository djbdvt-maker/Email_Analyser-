import asyncio
import ipaddress
import urllib.parse
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from playwright.async_api import async_playwright

from app.models import User
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/sandbox", tags=["sandbox"])

_SANDBOX_SEMAPHORE = asyncio.Semaphore(2)


def _validate_safe_sandbox_url(raw_url: str) -> str:
    """
    Validates that a URL is safe for sandbox execution:
    - Allows only http and https schemes (no file://, data://, ftp://).
    - Blocks loopback, RFC 1918 private subnets, link-local, and cloud metadata endpoints.
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

    # Block localhost and loopback names
    if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Prohibited target: loopback destinations are forbidden.",
        )

    # Block private, link-local, and cloud metadata IPs
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or str(ip) == "169.254.169.254":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Prohibited target: internal or private IP destinations are forbidden.",
            )
    except ValueError:
        # Hostname is a standard domain name, not an IP literal
        pass

    return raw_url


@router.get("/screenshot")
async def get_sandbox_screenshot(
    url: str,
    user: User = Depends(get_current_user),
):
    safe_url = _validate_safe_sandbox_url(url)
    async with _SANDBOX_SEMAPHORE:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                )
                page = await context.new_page()
                await page.goto(safe_url, wait_until="networkidle", timeout=10000)
                screenshot_bytes = await page.screenshot(full_page=False)
                await browser.close()
                return Response(content=screenshot_bytes, media_type="image/png")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate sandbox screenshot for requested URL.",
            )
