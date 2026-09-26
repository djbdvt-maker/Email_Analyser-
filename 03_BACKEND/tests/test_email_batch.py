import os
import random
import pytest

def test_batch_emails(client, user):
    ham_dir = "test_emails/ham_zipped/main_ham"
    if not os.path.exists(ham_dir):
        pytest.skip("Test data not found")
    spam_dir = "test_emails/spam_zipped/main_spam"

    ham_files = [os.path.join(ham_dir, f) for f in os.listdir(ham_dir) if os.path.isfile(os.path.join(ham_dir, f))]
    spam_files = [os.path.join(spam_dir, f) for f in os.listdir(spam_dir) if os.path.isfile(os.path.join(spam_dir, f))]

    random.seed(42)
    selected_ham = random.sample(ham_files, min(5, len(ham_files)))
    selected_spam = random.sample(spam_files, min(5, len(spam_files)))

    # Get admin token
    from tests.conftest import auth_headers
    headers = auth_headers(user)

    results = []

    def process_file(path, label):
        with open(path, "rb") as f:
            file_bytes = f.read()
        filename = os.path.basename(path)
        
        files = {"file": (filename, file_bytes, "message/rfc822")}
        response = client.post("/api/v1/ingest", files=files, headers=headers)
        
        if response.status_code == 201:
            data = response.json()
            inv_id = data.get("investigation_id")
            
            inv_resp = client.get(f"/api/v1/investigations/{inv_id}", headers=headers)
            if inv_resp.status_code == 200:
                inv_data = inv_resp.json()
                score = inv_data.get("score")
                severity = inv_data.get("severity")
                verdict = inv_data.get("verdict")
                results.append(f"[{label}] {filename[:15]:<15} | Score: {score:>3} | Severity: {severity:<8} | Verdict: {verdict}")
            else:
                results.append(f"[{label}] {filename[:15]:<15} | Failed to fetch inv: {inv_resp.text}")
        else:
            results.append(f"[{label}] {filename[:15]:<15} | Ingest Failed: {response.status_code} {response.text}")

    print("\n\n=== HOPZERO SCORECARD ===")
    
    print("\n--- ANALYZING HAM EMAILS ---")
    for h in selected_ham:
        process_file(h, "HAM")

    print("\n--- ANALYZING SPAM EMAILS ---")
    for s in selected_spam:
        process_file(s, "SPAM")

    print("\n=== FINAL RESULTS ===")
    for r in results:
        print(r)
    print("======================\n\n")



