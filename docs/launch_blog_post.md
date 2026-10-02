# Introducing HopZero: Ending the "Black Box" of Email Security

Have you ever looked at a security alert and wondered, "Why was this flagged?" 

For years, security teams have struggled with a major problem. When an email is marked as a threat—like Phishing or Business Email Compromise (BEC)—the system rarely explains *why*. Security tools often act like a "black box." They give a threat score, but they don't show the math.

As a developer, I felt this pain. SOC (Security Operations Center) analysts waste countless hours trying to reverse-engineer why an alert was triggered just to be sure it isn't a false positive. This lack of clear, explainable threat intelligence inspired me to build a solution.

Today, I am thrilled to announce the open-source launch of **HopZero**!

## What is HopZero?

HopZero is an Enterprise Email Threat Forensics Platform. It is designed to analyze, score, and neutralize email-based attacks like Phishing, BEC, and lookalike domains. 

But what makes HopZero truly special is its **transparency**. 

Instead of hiding behind a secret AI model that you cannot verify, HopZero uses a deterministic forensic engine. It clearly separates the entire investigation process into a simple, auditable pipeline: **Evidence → Finding → Score → Verdict**.

## How It Works

We designed HopZero to be powerful but simple to understand:
1. **The 41-Rule Qualification Registry**: When an email enters the system, HopZero checks it against 41 specific, real-world rules (like checking if an IP address is suspicious or if a sender domain is trying to trick you).
2. **The 9-Bucket Capped Scoring Model**: Instead of a confusing percentage, HopZero assigns a strict score based on the hard evidence it found. 
3. **Clear Explanations**: The final verdict is fully auditable. A security analyst can look at a result and see exactly which piece of evidence triggered which rule, and how it led to the final score.

## Core Benefits for Developers and Security Teams

- **No More Guesswork**: You get rigorous, explainable intelligence. You always know exactly *why* an email was flagged.
- **Easy to Audit**: The deterministic approach means the same email will always get the exact same score for the same reasons.
- **Seamless Integration**: Built with a modern tech stack (Python, FastAPI, React, n8n, and Docker) so you can easily integrate it with your existing tools and workflows.
- **Open Source**: You can run it locally, inspect the code, and customize the forensic rules to fit your organization's specific needs.

## Join the Mission

Security should not be a secret. By making threat intelligence transparent, we can help teams respond faster and with much more confidence.

I would love for you to try HopZero. If you are a developer, security engineer, or just passionate about open-source security, please check it out!

👉 **[Explore HopZero on GitHub](https://github.com/djbdvt-maker/Email_Analyser-)**

If you find the project useful, **please leave a ⭐️ (star)** on GitHub! It helps more developers discover the tool. 

We also welcome contributions! Whether it is adding a new forensic rule, fixing a bug, or improving the documentation, your help is greatly appreciated. Let's build a safer, more transparent digital world together!
