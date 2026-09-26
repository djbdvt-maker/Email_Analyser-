# HopZero Analyst Extension

An interactive MVP browser extension for SOC analysts. The extension is a client of HopZero; it is not the forensic engine.

## Overview
This extension detects the currently open email in Gmail, extracts raw message details (subject, sender, body), and submits them to the HopZero backend API for analysis. It polls the locked analysis run and displays the backend-authoritative Risk Severity, Score, and Findings.

## Features
- **Analyze:** Connects seamlessly to HopZero `/ingest` API.
- **Feedback & Re-Analysis:** Report an email as phishing/spam, which triggers a NEW analysis run. The extension safely polls the new run and requests `/compare-runs`.
- **Enforcement:** Fetches grounded enforcement options (e.g. `probable-origin IP`) and strictly requires explicit authorization before triggering `/execute`.

## Security Limitations
- **Gmail DOM vs Raw `.eml`:** Because this extension operates without additional Google Workspace OAuth scopes, it relies on DOM extraction (`gmail_adapter.js`). The resulting structure is functionally useful but not a cryptographically perfect raw RFC 5322 `.eml` byte stream. This is a known limitation.
- **Authentication:** Uses JWT token-based authentication via the HopZero backend (`/api/v1/auth/login`). No API keys or LLM secrets are stored in the extension source code. 

## How to Load in Chrome
1. Open Chrome and go to `chrome://extensions/`.
2. Enable "Developer mode" in the top right.
3. Click "Load unpacked" and select the `07_EXTENSION` directory.
4. Pin the extension to your toolbar.
5. Enter your HopZero backend URL and credentials in the popup to authenticate.

## Architecture
- **Popup UI:** Displays backend-generated states (IDLE, ANALYZING, COMPLETED, etc.).
- **Content Script (`gmail_adapter.js`):** Interacts with the Gmail DOM to parse the visible email.
- **Client (`hopzero_client.js`):** Interacts purely with HopZero APIs. It does not calculate scores, determine maliciousness, or attempt independent CF logic.
