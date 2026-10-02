import json
import random
import os

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "train.jsonl")
SYSTEM_PROMPT = "You are a forensic email content analyzer. Extract potential findings. Output ONLY JSON with a 'candidates' array."

def generate_bec():
    executives = ["CEO", "CFO", "Managing Director", "President"]
    urgencies = ["URGENT:", "Action Required:", "Time Sensitive:"]
    subjects = [
        f"{random.choice(urgencies)} Wire Transfer Request",
        f"Confidential: Project {random.choice(['Zeus', 'Apollo', 'Titan'])} payment",
        "Are you at your desk?"
    ]
    bodies = [
        "I am currently in a meeting. I need you to process an urgent wire transfer to our new vendor today. Please send me the routing details immediately.",
        "Can you discreetly arrange a payment of $45,000 to the attached invoice? I cannot take calls right now, just reply when done.",
        "Please update my direct deposit payroll account to the following routing number before EOD."
    ]
    
    expected = {
        "candidates": [
            {
                "finding_type": "EXECUTIVE_AUTHORITY",
                "supporting_text": "Sender is claiming to be an executive requesting urgent action",
                "strength": "High"
            },
            {
                "finding_type": "FINANCIAL_REQUEST",
                "supporting_text": "Request for financial wire transfer or payroll change",
                "strength": "High"
            }
        ]
    }
    return subjects, bodies, expected

def generate_phishing():
    subjects = [
        "Action Required: Your Microsoft 365 Password Expires Today",
        "Security Alert: Unusual login attempt",
        "IT Helpdesk: Mandatory Security Update"
    ]
    bodies = [
        "Your Office 365 password will expire in 2 hours. Please click here to keep your current password: http://portal-update-m365.com/login",
        "We detected a login from Russia. If this wasn't you, verify your identity immediately at https://secure-verify-account.net/auth",
        "Due to a recent server migration, you must re-authenticate your mailbox. Failure to do so will result in account suspension."
    ]
    
    expected = {
        "candidates": [
            {
                "finding_type": "CREDENTIAL_HARVESTING",
                "supporting_text": "Link to a credential harvesting portal with urgency",
                "strength": "High"
            }
        ]
    }
    return subjects, bodies, expected

def generate_clean():
    subjects = [
        "Meeting notes from Tuesday",
        "Lunch tomorrow?",
        "Q3 Marketing Report"
    ]
    bodies = [
        "Hey team, attached are the notes from our brainstorming session. Let me know if I missed anything.",
        "Are we still on for lunch at 12? I can drive.",
        "The Q3 numbers look good. We hit 110% of our pipeline goal. Great job everyone."
    ]
    
    expected = {
        "candidates": []
    }
    return subjects, bodies, expected

def main():
    dataset = []
    
    # Read existing
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    dataset.append(json.loads(line))
                    
    initial_count = len(dataset)
    
    # Generate 150 synthetic examples (50 of each)
    generators = [generate_bec, generate_phishing, generate_clean]
    
    for _ in range(50):
        for gen in generators:
            subs, bods, expected = gen()
            subject = random.choice(subs)
            body = random.choice(bods)
            
            # Add some random noise to make it robust
            if random.random() > 0.5:
                body = body + f"\n\nThanks,\n{random.choice(['John', 'Sarah', 'Mike'])}"
                
            user_prompt = f"Subject: {subject}\n\n{body}"
            
            record = {
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                    {"role": "assistant", "content": json.dumps(expected)}
                ]
            }
            dataset.append(record)
            
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for r in dataset:
            f.write(json.dumps(r) + "\n")
            
    print(f"Added {len(dataset) - initial_count} synthetic training examples.")
    print(f"Total dataset size is now {len(dataset)} examples. Ready for Colab!")

if __name__ == "__main__":
    main()
