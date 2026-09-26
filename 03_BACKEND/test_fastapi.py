import time
import json
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import User
from app.security import create_access_token

def test_flow():
    client = TestClient(app)
    db = SessionLocal()
    admin_user = db.query(User).filter(User.email == "admin@hopzero.local").first()
    
    token = create_access_token(
        user_id=admin_user.id,
        organization_id=admin_user.organization_id,
        role=admin_user.role.value
    )
    headers = {"Authorization": f"Bearer {token}"}
    
    print("1. Uploading EML...")
    with open("test.eml", "rb") as f:
        res = client.post("/api/v1/ingest", headers=headers, files={"file": ("test.eml", f, "message/rfc822")})
    
    upload_data = res.json()
    print("Upload Result:", upload_data)
    inv_id = upload_data.get("investigation_id") or upload_data.get("investigationId")
    
    print("3. Fetching Investigation...")
    res = client.get(f"/api/v1/investigations/{inv_id}", headers=headers)
            
    print("\n--- ANALYSIS COMPLETED ---")
    data = res.json()
    run = data["currentRun"]["result"]
    
    print(f"Total Score: {run['score']}")
    print(f"Severity: {run['severity']}")
    print(f"Verdict: {run['verdict']}")
    print(f"Findings: {len(run['findings'])}")
    for f in run["findings"]:
        print(f"  - {f['category']}: {f['qualification_code']} (MITRE: {f.get('mitre_id')}) [{f['strength']}]")
        
    print("\n--- ROUTING TIMELINE ---")
    for h in run['routing']['hops']:
        print(f"  Hop {h['hopIndex']}: IP={h['observedIp']} | Server={h['receivingServer']}")
        
    print("\n--- EXTRACTED LINKS ---")
    links = run['links']
    for l in links:
        print(f"  Link: {l['actualHref']}")
        
    print("\n4. Testing Defanged Sandbox...")
    if links:
        test_url = links[0]['actualHref']
        print(f"Requesting screenshot for {test_url}")
        res = client.get(f"/api/v1/sandbox/screenshot?url={test_url}", headers=headers)
        if res.status_code == 200:
            print(f"Screenshot received! Size: {len(res.content)} bytes")
        else:
            print("Screenshot failed:", res.text)
            
    print("\n5. Testing Chain of Custody Export...")
    res = client.get(f"/api/v1/investigations/{inv_id}/export", headers=headers)
    if res.status_code == 200:
        print(f"Export zip downloaded! Size: {len(res.content)} bytes")
        with open("export_test.zip", "wb") as f:
            f.write(res.content)
    else:
        print("Export failed:", res.text)

if __name__ == "__main__":
    test_flow()
