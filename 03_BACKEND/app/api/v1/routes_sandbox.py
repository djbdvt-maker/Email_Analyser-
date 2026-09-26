from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from app.security import get_current_user
from app.models import User
import asyncio
from playwright.async_api import async_playwright

router = APIRouter(prefix="/api/v1/sandbox", tags=["sandbox"])

@router.get("/screenshot")
async def get_sandbox_screenshot(
    url: str,
    user: User = Depends(get_current_user)
):
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = await context.new_page()
            
            # Wait for network idle to ensure the page is loaded, but timeout quickly if it hangs
            await page.goto(url, wait_until="networkidle", timeout=10000)
            
            # Take screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            await browser.close()
            
            return Response(content=screenshot_bytes, media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate sandbox screenshot: {str(e)}")
