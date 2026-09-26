# HopZero Analyst Agent (n8n)

This directory contains the orchestration logic for the HopZero Analyst Agent, implemented as an n8n workflow (`hopzero_analyst_agent.json`). 

**CRITICAL ARCHITECTURAL RULE**: The HopZero backend is authoritative. The n8n Agent is exclusively an orchestration, interaction, and explanation layer. It does **not** calculate scores, determine severities, invent forensic findings, calculate floors, or independently authorize firewall blocks.

---

## 1. PHASE 1: Locked Investigation & Polling

The initial phase of the workflow is responsible for safely extracting and explaining the current state of an analysis:

1. **Manual Trigger & Input**: Receives a target `investigation_id`.
2. **Login**: Authenticates with the backend `/auth/login`.
3. **Get Investigation**: Retrieves the current state of the investigation.
4. **Store Run ID**: Freezes the `investigation_id` and `analysis_run_id` securely into node state. The workflow will **never** rediscover the run ID dynamically.
5. **Locked Polling**: The workflow loops against the backend, polling the locked run ID. It explicitly handles all 7 run statuses (`QUEUED`, `PARSING`, `ANALYZING`, `SCORING`, `COMPLETED`, `FAILED`, `CANCELLED`).
6. **Results Extraction**: On `COMPLETED`, retrieves run-scoped Findings, Score, and Evidence. Validates consistency against the locked run ID, and generates an AI explanation.

---

## 2. PHASE 2: Re-Analysis & Grounded Enforcement

Phase 2 safely implements analyst interaction, re-analysis, and execution authorization.

1. **Analyst Feedback**: Analyst feedback (e.g., "This is phishing") is submitted to the backend via `/feedback`. *Feedback is not a verdict; it is a request for re-analysis.*
2. **NEW Analysis Run**: The backend preserves the old run immutably and spins up a NEW `analysis_run_id`.
3. **New Run Polling & Comparison**: The workflow safely locks the new run ID, polls it until completion, and natively submits both the old and new run IDs to the `/compare-runs` API to extract exact deltas.
4. **Grounded Enforcement Options**: The Agent requests `/enforcement/options`. It uses **only** targets grounded by the backend (e.g. `probable-origin IP`), never inferring attacker IPs from loose email headers.
5. **Explicit Action Selection**: The analyst explicitly selects an action from the grounded options. 
6. **Enforcement Request**: A formal request is queued in the backend (`REQUESTED` state). The `action_id` is frozen in node state via `Store Enforcement Action`.
7. **Explicit Authorization**: The workflow halts until the analyst explicitly authorizes the block.
8. **Execution**: The workflow calls `/execute`. The backend natively delegates the rule to the firewall provider (e.g., Mock Provider) and the AI reports the final audit trail.

---

## 3. DEMO MODE vs. REAL ANALYST MODE

To satisfy the Smart India Hackathon (SIH) demonstration requirements while preserving production safety, the workflow explicitly bifurcates into two modes.

### REAL ANALYST MODE
**Configuration**: `demo_mode = false`

This is the production architecture. The workflow explicitly **STOPS** at three critical interaction boundaries using `Wait` nodes (configured as Webhook listeners):
1. `Wait for Analyst Feedback` (waits for actual analyst feedback)
2. `Wait for Analyst Enforcement Choice` (waits for actual enforcement selection)
3. `Wait for Explicit Authorization` (waits for explicit authorization)

The workflow **NEVER** automatically assumes `options[0]` as a selection, and **NEVER** automatically authorizes a firewall block. Human interaction is strictly required to resume execution at these boundaries.

### DEMO MODE (Deterministic Simulation)
**Configuration**: `demo_mode = true`

For SIH judge demonstrations, the workflow includes deterministic simulation branches marked explicitly as `[DEMO MODE]`.
- **Behavior**: When enabled, the workflow bypasses the `Wait` nodes and routes into deterministic mock nodes (`[DEMO MODE] Simulate Analyst Feedback`, `[DEMO MODE] Simulate Analyst Enforcement Choice`, and `[DEMO MODE] Simulate Explicit Authorization`).
- **WARNING**: DEMO MODE SIMULATES ANALYST ACTIONS FOR DEMONSTRATION PURPOSES. IT IS NOT REAL HUMAN AUTHORIZATION. In production, `demo_mode` must be disabled.

### How to Switch Modes
To switch between DEMO and REAL ANALYST modes, modify the `Set Input ID` node at the start of the n8n workflow:
1. Open the **Set Input ID** node.
2. Locate the `demo_mode` string value.
3. Set to `true` to enable deterministic simulations (DEMO MODE).
4. Set to `false` to enforce explicit webhook halts (REAL ANALYST MODE).

### Recommended SIH Demo Sequence
1. Start investigation.
2. Agent reports initial result.
3. Demo analyst reports phishing (simulated).
4. Backend creates new AnalysisRun.
5. Agent polls new run.
6. Agent compares old/new natively.
7. Agent shows grounded enforcement options.
8. Demo selects one (simulated).
9. Demo explicitly simulates authorization (simulated).
10. Backend authorizes and executes mock provider.
11. Agent reports final provider result, securely audited by the backend.