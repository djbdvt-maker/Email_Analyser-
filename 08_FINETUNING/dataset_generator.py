import os
import json
import email
from email import policy
import glob

def parse_eml(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    
    subject = msg.get("Subject", "")
    body_text = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_text = part.get_content()
                break
    else:
        body_text = msg.get_content()
        
    return subject.strip(), body_text.strip()

def generate_expected_candidates(manifest):
    # This simulates what the AI Reasoner should output based on the scenario manifest
    candidates = []
    floors = manifest.get("expected_floors_triggered", [])
    
    if "CF-01" in floors or manifest.get("category") == "lookalike":
        candidates.append({
            "finding_type": "BRAND_IMPERSONATION",
            "supporting_text": "Sender is using a lookalike domain",
            "strength": "High"
        })
    if "CF-02" in floors or manifest.get("category") == "BEC":
        candidates.append({
            "finding_type": "EXECUTIVE_AUTHORITY",
            "supporting_text": "Sender is claiming to be an executive requesting urgent action",
            "strength": "High"
        })
        candidates.append({
            "finding_type": "FINANCIAL_REQUEST",
            "supporting_text": "Request for financial wire transfer",
            "strength": "High"
        })
    if "CF-03" in floors or manifest.get("category") == "phishing":
        candidates.append({
            "finding_type": "CREDENTIAL_HARVESTING",
            "supporting_text": "Link to a credential harvesting portal",
            "strength": "High"
        })
    if "CF-04" in floors or manifest.get("category") == "attachments":
        candidates.append({
            "finding_type": "SUSPICIOUS_ATTACHMENT",
            "supporting_text": "Double extension macro attachment",
            "strength": "High"
        })
        
    # If no floors/findings (e.g. clean)
    if not candidates and manifest.get("category") != "clean":
        candidates.append({
            "finding_type": "SUSPICIOUS_CONTENT",
            "supporting_text": manifest.get("description", "Suspicious content detected"),
            "strength": "Moderate"
        })
        
    return {"candidates": candidates}

def main():
    test_data_dir = os.path.join(os.path.dirname(__file__), "..", "07_TEST_DATA")
    output_file = os.path.join(os.path.dirname(__file__), "train.jsonl")
    
    dataset = []
    
    for manifest_path in glob.glob(os.path.join(test_data_dir, "*", "manifest.json")):
        folder_dir = os.path.dirname(manifest_path)
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
            
        for filename in manifest.get("files", []):
            eml_path = os.path.join(folder_dir, filename)
            if not os.path.exists(eml_path):
                continue
                
            subject, body = parse_eml(eml_path)
            
            # The prompt format exactly as sent by ai_reasoner_service.py
            system_prompt = "You are a forensic email content analyzer. Extract potential findings. Output ONLY JSON with a 'candidates' array."
            user_prompt = f"Subject: {subject}\n\n{body}"
            
            expected_json = json.dumps(generate_expected_candidates(manifest))
            
            # ShareGPT format for Unsloth
            record = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                    {"role": "assistant", "content": expected_json}
                ]
            }
            dataset.append(record)
            
    with open(output_file, 'w', encoding='utf-8') as f:
        for r in dataset:
            f.write(json.dumps(r) + "\n")
            
    print(f"Generated {len(dataset)} training examples in {output_file}")

if __name__ == "__main__":
    main()
