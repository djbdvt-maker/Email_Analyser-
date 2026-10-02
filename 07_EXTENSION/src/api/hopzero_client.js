class HopZeroClient {
  constructor() {
    this.baseUrl = "http://localhost:8000";
    this.token = null;
  }

  async login(username, password, baseUrl) {
    this.baseUrl = baseUrl || this.baseUrl;
    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);

    const res = await fetch(`${this.baseUrl}/api/v1/auth/login`, {
      method: "POST",
      body: formData
    });
    if (!res.ok) throw new Error(`Login failed: ${res.status}`);
    const data = await res.json();
    this.token = data.access_token;
    return this.token;
  }

  getHeaders() {
    return { "Authorization": `Bearer ${this.token}` };
  }

  async ingestEmail(emailData) {
    const formData = new FormData();
    formData.append("ingestion_source", "gmail_extension_api");
    if (emailData.provider_message_id) {
        formData.append("provider_message_id", emailData.provider_message_id);
    }
    formData.append("title", `Ext Ingestion: ${emailData.provider_message_id || 'Unknown'}`);
    formData.append("auto_analyze", "true");

    if (emailData.raw_eml) {
        formData.append("file", new Blob([emailData.raw_eml], { type: "message/rfc822" }), `${emailData.provider_message_id || 'email'}.eml`);
    } else {
        throw new Error("Raw .eml data not available.");
    }

    const res = await fetch(`${this.baseUrl}/api/v1/ingest`, {
      method: "POST",
      headers: this.getHeaders(),
      body: formData
    });
    if (!res.ok) throw new Error(`Ingestion failed: ${res.status}`);
    return await res.json();
  }

  async getAnalysisRun(investigationId, runId) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/analysis-runs/${runId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Analysis run fetch failed: ${res.status}`);
    return await res.json();
  }

  async getFindings(investigationId, runId) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/findings?analysis_run_id=${runId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Findings fetch failed: ${res.status}`);
    return await res.json();
  }

  async getScore(investigationId, runId) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/analysis-runs/${runId}/score`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Score fetch failed: ${res.status}`);
    return await res.json();
  }

  async submitFeedback(investigationId, runId, feedbackType, note) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/feedback`, {
      method: "POST",
      headers: { ...this.getHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        feedback_type: feedbackType,
        note: note,
        source_analysis_run_id: runId
      })
    });
    if (!res.ok) throw new Error(`Feedback failed: ${res.status}`);
    return await res.json();
  }

  async compareRuns(investigationId, run1, run2) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/compare-runs?run1=${run1}&run2=${run2}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Compare runs failed: ${res.status}`);
    return await res.json();
  }

  async getEnforcementOptions(investigationId) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/enforcement/options`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Enforcement options failed: ${res.status}`);
    return await res.json();
  }

  async requestEnforcement(investigationId, actionType, target) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/enforcement/request`, {
      method: "POST",
      headers: { ...this.getHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ action_type: actionType, target: target })
    });
    if (!res.ok) throw new Error(`Enforcement request failed: ${res.status}`);
    return await res.json();
  }

  async authorizeEnforcement(investigationId, actionId) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/enforcement/${actionId}/authorize`, {
      method: "POST",
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Authorize enforcement failed: ${res.status}`);
    return await res.json();
  }

  async executeEnforcement(investigationId, actionId) {
    const res = await fetch(`${this.baseUrl}/api/v1/investigations/${investigationId}/enforcement/${actionId}/execute`, {
      method: "POST",
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Execute enforcement failed: ${res.status}`);
    return await res.json();
  }
}
window.HopZeroClient = HopZeroClient;
