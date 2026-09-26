import httpx
import asyncio
import os

async def test():
    async with httpx.AsyncClient() as client:
        token_resp = await client.post("http://localhost:8000/api/v1/auth/login", data={"username": "admin@hopzero.local", "password": "changeme123"})
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        eml_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "07_TEST_DATA", "phishing", "credential_harvesting_portal.eml"))
        with open(eml_path, "rb") as f:
            eml_bytes = f.read()
        
        resp = await client.post(
            "http://localhost:8000/api/v1/ingest",
            headers=headers,
            data={
                "ingestion_source": "web_upload",
                "provider_message_id": "upload-12345",
                "auto_analyze": "true",
            },
            files={"file": ("test.eml", eml_bytes, "message/rfc822")},
            timeout=60.0
        )
        print(resp.status_code)
        print(resp.text)

if __name__ == "__main__":
    asyncio.run(test())
