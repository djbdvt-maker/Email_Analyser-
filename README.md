# HopZero - Email Threat Forensics Platform

[![CI](https://github.com/djbdvt-maker/Email_Analyser-/actions/workflows/ci.yml/badge.svg)](https://github.com/djbdvt-maker/Email_Analyser-/actions/workflows/ci.yml)

> **HopZero** is a deterministic forensic engine and enterprise threat-detection platform for analyzing, scoring, and neutralizing email-based attacks (Phishing, BEC, Lookalikes).

## 🎥 Demo & Product Tour

*(**Jury / Reviewers:** Watch our 2-3 minute product demo below to see the forensic engine and dashboard in action)*

[**▶️ Watch the HopZero Demo Video**](#) <!-- Replace # with actual video link -->

### Platform Screenshots
*(Replace these placeholders with actual screenshots of the UI before final submission)*
1. **[Dashboard Overview](./docs/screenshots/dashboard.png)**
2. **[Forensic Threat Analysis View](./docs/screenshots/analysis.png)**
3. **[Rule Registry & Scoring](./docs/screenshots/scoring.png)**
4. **[Browser Extension in Action](./docs/screenshots/extension.png)**

---

## 🚀 Problem Statement
Current email security solutions often rely on black-box ML models or simplistic rulesets, making it difficult for security operations center (SOC) analysts to understand *why* an email was flagged. 

**HopZero** solves this by implementing a transparent, deterministic forensic engine with a 41-rule qualification registry and a 9-bucket capped scoring model. It clearly separates **Evidence → Finding → Score → Verdict**, providing SOC teams with rigorous, explainable threat intelligence.

## 🏗️ Architecture & Modules

The platform is designed as a coherent, full-stack microservices architecture:

- **`01_REGISTRY`**: The core 41-rule qualification registry for deterministic threat modeling.
- **`02_FORENSICS`**: The evidence and scoring engine (CF-01 to CF-06 buckets).
- **`03_BACKEND`**: FastAPI server with Alembic migrations, RBAC, and SQLite/PostgreSQL support.
- **`04_FRONTEND`**: React/TypeScript dashboard for SOC analysts.
- **`06_N8N`**: Automation workflows for threat response.
- **`07_EXTENSION`**: Browser extension for immediate end-user context.
- **`08_FINETUNING`**: LLM component pipeline for adaptive threat analysis.

*(See our [Architecture Visuals](./docs/architecture-visual/hopzero-architecture.html) for a complete system topology)*

## 🛠️ Setup & Installation

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Node.js 18+

### Quick Start (Docker)
```bash
docker-compose up --build
```

### Local Development Setup

1. **Backend**
```bash
cd 03_BACKEND
pip install -r requirements.txt
uvicorn app.main:app --reload
```

2. **Frontend**
```bash
cd 04_FRONTEND
npm install
npm run dev
```

## 🧪 Testing

We maintain strict test discipline with a **276-test suite** running across the registry, forensics engine, backend, and QA corpus. This guarantees the integrity of our deterministic scoring engine.

```bash
# Run the complete test suite
pytest
```

*(We have a dedicated `07_TEST_DATA` corpus containing phishing, BEC, lookalike, and clean samples for robust regression validation.)*

## 👥 Team
- **Member 1** - [GitHub](https://github.com/) / [LinkedIn](https://linkedin.com/) - Role
- **Member 2** - [GitHub](https://github.com/) / [LinkedIn](https://linkedin.com/) - Role
- **Member 3** - [GitHub](https://github.com/) / [LinkedIn](https://linkedin.com/) - Role
- **Member 4** - [GitHub](https://github.com/) / [LinkedIn](https://linkedin.com/) - Role
