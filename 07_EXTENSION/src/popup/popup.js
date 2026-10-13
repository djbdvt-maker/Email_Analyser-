document.addEventListener("DOMContentLoaded", async () => {
  const client = new window.HopZeroClient();
  let currentInvId = null;
  let currentRunId = null;
  let isEmployeeMode = true;

  // Tab switching in login view
  const tabCodeBtn = document.getElementById("tab-code-btn");
  const tabAnalystBtn = document.getElementById("tab-analyst-btn");
  const tabCodePanel = document.getElementById("tab-code-panel");
  const tabAnalystPanel = document.getElementById("tab-analyst-panel");

  if (tabCodeBtn && tabAnalystBtn) {
    tabCodeBtn.addEventListener("click", () => {
      tabCodeBtn.classList.add("active");
      tabAnalystBtn.classList.remove("active");
      tabCodePanel.classList.remove("hidden");
      tabAnalystPanel.classList.add("hidden");
    });
    tabAnalystBtn.addEventListener("click", () => {
      tabAnalystBtn.classList.add("active");
      tabCodeBtn.classList.remove("active");
      tabAnalystPanel.classList.remove("hidden");
      tabCodePanel.classList.add("hidden");
    });
  }

  // Restore stored session
  const storage = await chrome.storage.local.get([
    "hz_token", "hz_url", "hz_role", "hz_employee_name", "hz_secret_code", "hz_offline_queue"
  ]);

  const updateConnectionStatus = async (url) => {
    const banner = document.getElementById("connection-banner");
    const indicator = document.getElementById("conn-indicator");
    const text = document.getElementById("conn-text");
    if (!banner) return;
    banner.classList.remove("hidden");
    try {
      const resp = await fetch(`${url || "http://localhost:8000"}/health`, { signal: AbortSignal.timeout(1500) });
      if (resp.ok) {
        indicator.className = "dot dot-green";
        text.innerText = "Connected to SOC Hub (Online)";
        // Flush any offline queued reports
        flushOfflineQueue();
      } else {
        throw new Error("unhealthy");
      }
    } catch {
      indicator.className = "dot dot-orange";
      text.innerText = "⚡ Autonomous Offline Mode (Local Scanner Active)";
    }
  };

  if (storage.hz_token) {
    client.token = storage.hz_token;
    client.baseUrl = storage.hz_url || "http://localhost:8000";
    isEmployeeMode = storage.hz_role === "EMPLOYEE";

    document.getElementById("login-view").classList.add("hidden");
    document.getElementById("main-view").classList.remove("hidden");
    document.getElementById("auth-status").innerText = isEmployeeMode ? "Enrolled" : "Analyst";
    
    const userDisplay = document.getElementById("user-name-display");
    if (userDisplay) {
      userDisplay.innerText = storage.hz_employee_name || (isEmployeeMode ? "Employee Portal" : "SOC Analyst");
    }

    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) logoutBtn.classList.remove("hidden");

    updateConnectionStatus(client.baseUrl);
    updateQueueBadge();
  }

  // 1. Employee Secret Code Connect
  const connectCodeBtn = document.getElementById("connect-code-btn");
  if (connectCodeBtn) {
    connectCodeBtn.addEventListener("click", async () => {
      const errorDiv = document.getElementById("code-error");
      errorDiv.innerText = "";
      try {
        const code = document.getElementById("secret-code-input").value.trim();
        const url = document.getElementById("api-url-code").value.trim() || "http://localhost:8000";
        if (!code) {
          errorDiv.innerText = "Please enter your 8-character secret code.";
          return;
        }

        connectCodeBtn.disabled = true;
        connectCodeBtn.innerText = "Verifying...";

        const data = await client.loginWithSecretCode(code, url);
        isEmployeeMode = true;

        await chrome.storage.local.set({
          hz_token: data.access_token,
          hz_url: url,
          hz_role: "EMPLOYEE",
          hz_employee_name: data.employee_name || data.employee_email,
          hz_secret_code: code.toUpperCase(),
        });

        document.getElementById("login-view").classList.add("hidden");
        document.getElementById("main-view").classList.remove("hidden");
        document.getElementById("auth-status").innerText = "Enrolled";
        
        const userDisplay = document.getElementById("user-name-display");
        if (userDisplay) {
          userDisplay.innerText = data.employee_name || data.employee_email;
        }

        const logoutBtn = document.getElementById("logout-btn");
        if (logoutBtn) logoutBtn.classList.remove("hidden");

        updateConnectionStatus(url);
      } catch (err) {
        errorDiv.innerText = err.message || "Failed to verify secret code.";
      } finally {
        connectCodeBtn.disabled = false;
        connectCodeBtn.innerText = "Connect with Secret Code";
      }
    });
  }

  // 2. Analyst Login
  const loginBtn = document.getElementById("login-btn");
  if (loginBtn) {
    loginBtn.addEventListener("click", async () => {
      const errorDiv = document.getElementById("login-error");
      errorDiv.innerText = "";
      try {
        const user = document.getElementById("username").value.trim();
        const pass = document.getElementById("password").value.trim();
        const url = document.getElementById("api-url-analyst").value.trim() || "http://localhost:8000";
        await client.login(user, pass, url);
        isEmployeeMode = false;

        await chrome.storage.local.set({
          hz_token: client.token,
          hz_url: url,
          hz_role: "ANALYST",
          hz_employee_name: user,
        });

        document.getElementById("login-view").classList.add("hidden");
        document.getElementById("main-view").classList.remove("hidden");
        document.getElementById("auth-status").innerText = "Analyst";
        
        const userDisplay = document.getElementById("user-name-display");
        if (userDisplay) userDisplay.innerText = user;

        const logoutBtn = document.getElementById("logout-btn");
        if (logoutBtn) logoutBtn.classList.remove("hidden");

        // Show admin-only findings box
        const adminBox = document.getElementById("admin-findings-box");
        if (adminBox) adminBox.classList.remove("hidden");

        updateConnectionStatus(url);
      } catch (err) {
        errorDiv.innerText = err.message || "Login failed.";
      }
    });
  }

  // Logout handler
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      await chrome.storage.local.remove(["hz_token", "hz_role", "hz_employee_name", "hz_secret_code"]);
      client.token = null;
      document.getElementById("login-view").classList.remove("hidden");
      document.getElementById("main-view").classList.add("hidden");
      document.getElementById("auth-status").innerText = "Logged Out";
      logoutBtn.classList.add("hidden");
      document.getElementById("run-status").innerText = "IDLE";
      const banner = document.getElementById("connection-banner");
      if (banner) banner.classList.add("hidden");
    });
  }

  // Autonomous Client-Side Scanner for offline protection
  function runAutonomousLocalScan(emailData) {
    const text = ((emailData.subject || "") + " " + (emailData.body || "")).toLowerCase();
    const sender = (emailData.sender || "").toLowerCase();
    let score = 0;
    const flags = [];

    // Check urgency & credential solicitation
    const urgencyKeywords = [
      "wire transfer", "payment overdue", "password reset", "account suspended",
      "verify immediately", "gift card", "bank update", "unauthorized access",
      "action required", "payroll update", "invoice attached"
    ];
    for (const kw of urgencyKeywords) {
      if (text.includes(kw)) {
        score += 15;
        flags.push(`Urgency keyword detected: '${kw}'`);
      }
    }

    // Check lookalike sender anomalies
    if (sender.includes("@") && (sender.includes(".ru") || sender.includes(".xyz") || sender.includes(".top"))) {
      score += 20;
      flags.push("Suspicious high-risk top-level domain in sender address");
    }

    if (text.includes("http://") || text.includes("bit.ly/") || text.includes("tinyurl.com/")) {
      score += 15;
      flags.push("Unencrypted or shortened redirect link detected in message body");
    }

    let verdict = "SAFE";
    let recommendation = "✅ No obvious phishing signals found. Always verify unexpected attachments.";
    if (score >= 35) {
      verdict = "DANGEROUS";
      recommendation = "🚨 High Risk Threat: Do NOT click links or reply. Report to SOC immediately.";
    } else if (score >= 15) {
      verdict = "SUSPICIOUS";
      recommendation = "⚠️ Suspicious Signals: Confirm sender identity via a secondary channel.";
    }

    return {
      verdict,
      score: Math.min(score, 100),
      severity: score >= 35 ? "HIGH" : (score >= 15 ? "MEDIUM" : "LOW"),
      one_line_explanation: flags.length > 0 ? flags[0] : "Local heuristic scan found no elevated threats.",
      action_recommendation: recommendation,
      is_offline: true,
      flags,
    };
  }

  // Display scan results
  function renderScanResults(res) {
    document.getElementById("progress-container").classList.add("hidden");
    document.getElementById("results-container").classList.remove("hidden");

    const card = document.getElementById("verdict-banner");
    const title = document.getElementById("res-verdict-title");
    const scorePill = document.getElementById("res-score-pill");
    const expl = document.getElementById("res-explanation");
    const rec = document.getElementById("res-recommendation");

    const v = (res.verdict || "SAFE").toUpperCase();
    title.innerText = v;
    scorePill.innerText = `${res.score || 0} / 100`;
    expl.innerText = res.one_line_explanation || "Scan completed.";
    rec.innerText = res.action_recommendation || "Remain vigilant.";

    card.className = "verdict-card " + (
      v === "DANGEROUS" ? "verdict-dangerous" : (v === "SUSPICIOUS" ? "verdict-suspicious" : "verdict-safe")
    );

    const reportMsg = document.getElementById("report-success-msg");
    if (reportMsg) reportMsg.classList.add("hidden");
  }

  // Scan Button Handler
  document.getElementById("analyze-btn").addEventListener("click", async () => {
    document.getElementById("status-container").classList.remove("hidden");
    document.getElementById("run-status").innerText = "CAPTURING";
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) {
      document.getElementById("run-status").innerText = "ERROR: Please open a Gmail message first.";
      return;
    }

    try {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["src/content/gmail_adapter.js"]
        });
      } catch (err) {
        console.warn("Script injection note:", err);
      }

      const response = await chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_EMAIL" });
      if (!response || !response.success) {
        document.getElementById("run-status").innerText = "FAILED TO EXTRACT EMAIL";
        return;
      }

      const emailData = response.data;
      document.getElementById("progress-container").classList.remove("hidden");
      document.getElementById("run-status").innerText = "ANALYZING";

      // Attempt online scan first; fallback to autonomous offline engine if server is unreachable
      try {
        let scanResult;
        if (isEmployeeMode) {
          scanResult = await client.scanAsEmployee(emailData);
          currentInvId = scanResult.investigation_id;
        } else {
          const ingestRes = await client.ingestEmail(emailData);
          currentInvId = ingestRes.investigation_id;
          currentRunId = ingestRes.analysis_run_id;
  function safeSetText(id, val) {
    const el = document.getElementById(id);
    if (el) el.innerText = val !== undefined && val !== null ? String(val) : "";
  }

  async function displayResults(runId) {
    try {
      const scoreData = await client.getScore(currentInvId, runId);
      const findingsData = await client.getFindings(currentInvId, runId);
      
      document.getElementById("results-container").classList.remove("hidden");
      safeSetText("res-verdict-title", scoreData.verdict);
      safeSetText("res-score-pill", `${scoreData.total_score} / 100`);
      safeSetText("res-explanation", scoreData.one_line_explanation || scoreData.conclusion_text);
      safeSetText("res-recommendation", scoreData.why_explanation || "Review findings in SOC console.");
      
      const ul = document.getElementById("res-findings");
      if (ul) {
        ul.innerHTML = "";
        findingsData.forEach(f => {
          const li = document.createElement("li");
          li.innerText = `[${f.qualification_code}] ${f.supporting_text}`;
          ul.appendChild(li);
        });
      }
    } catch(e) {
      console.error(e);
    }
  }

  function pollRun(runId, isNewRun = false) {
    let attempts = 0;
    const pollingInterval = setInterval(async () => {
      attempts++;
      if (attempts > 30) {
        clearInterval(pollingInterval);
        return;
      }
      try {
        const run = await client.getAnalysisRun(currentInvId, runId);
        const status = run.status;
        document.getElementById("run-status").innerText = status;
        if (status === "COMPLETED") {
          clearInterval(pollingInterval);
          if (isNewRun) {
            displayComparison(currentRunId, runId);
          } else {
            displayResults(runId);
          }
        } else if (status === "FAILED" || status === "CANCELLED") {
          clearInterval(pollingInterval);
        }
      } catch(e) {
        // continue polling
      }
    }, 1500);
  }

  const feedbackBtn = document.getElementById("feedback-btn");
  if (feedbackBtn) {
    feedbackBtn.addEventListener("click", async () => {
      document.getElementById("run-status").innerText = "AWAITING_FEEDBACK";
      try {
        const fb = await client.submitFeedback(currentInvId, currentRunId, "PHISHING_REPORTED", "Actually, I think this is phishing.");
        const newRunId = fb.new_analysis_run_id;
        document.getElementById("run-status").innerText = "REANALYZING";
        pollRun(newRunId, true);
      } catch(e) {
        console.error(e);
      }
    });
  }

  async function displayComparison(oldRun, newRun) {
    try {
      safeSetText("comp-old-run", oldRun.substring(0, 8) + "...");
      safeSetText("comp-new-run", newRun.substring(0, 8) + "...");
      const comp = await client.compareRuns(currentInvId, oldRun, newRun);
      const compareBox = document.getElementById("compare-container");
      if (compareBox) compareBox.classList.remove("hidden");
      safeSetText("comp-score-delta", comp.score_delta);
      safeSetText("comp-severity-change", comp.severity_changed ? "Changed" : "Unchanged");
      safeSetText("comp-verdict-change", comp.verdict_changed ? "Changed" : "Unchanged");
      loadEnforcement();
    } catch(e) {
      console.error(e);
    }
  }

  let selectedAction = null;
  let selectedTarget = null;
  async function loadEnforcement() {
    try {
      const opts = await client.getEnforcementOptions(currentInvId);
      const enfContainer = document.getElementById("enforcement-container");
      if (enfContainer) enfContainer.classList.remove("hidden");
      const ul = document.getElementById("enforcement-options");
      if (ul) {
        ul.innerHTML = "";
        opts.forEach(opt => {
          const btn = document.createElement("button");
          btn.innerText = `[ ${opt.action_type} ] ${opt.target}`;
          btn.className = "warning";
          btn.onclick = () => {
            selectedAction = opt.action_type;
            selectedTarget = opt.target;
            const authContainer = document.getElementById("auth-container");
            if (authContainer) authContainer.classList.remove("hidden");
            safeSetText("auth-target", opt.target);
            safeSetText("auth-action", opt.action_type);
          };
          const li = document.createElement("li");
          li.appendChild(btn);
          ul.appendChild(li);
        });
      }
    } catch(e) {
      console.error(e);
    }
  }

  const authBtn = document.getElementById("authorize-btn");
  if (authBtn) {
    authBtn.addEventListener("click", async () => {
      if (!selectedAction || !selectedTarget) return;
      try {
        const req = await client.requestEnforcement(currentInvId, selectedAction, selectedTarget);
        const actionId = req.id;
        await client.authorizeEnforcement(currentInvId, actionId);
        const exec = await client.executeEnforcement(currentInvId, actionId);
        safeSetText("enforcement-status", `Result: ${exec.status}`);
        const authContainer = document.getElementById("auth-container");
        if (authContainer) authContainer.classList.add("hidden");
      } catch(e) {
        safeSetText("enforcement-status", `Failed: ${e.message}`);
      }
    });
  }

  // Instant Visual Scanner Button
  document.getElementById("visual-scan-btn").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["src/content/gmail_adapter.js"]
      });
      const response = await chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_EMAIL" });
      if (response && response.success) {
        const offlineResult = runAutonomousLocalScan(response.data);
        renderScanResults(offlineResult);
        document.getElementById("status-container").classList.remove("hidden");
        document.getElementById("run-status").innerText = "INSTANT SCAN";
      }
    } catch (err) {
      alert("Please open an active webmail tab: " + err.message);
    }
  });

  // Report to SOC Button
  const reportBtn = document.getElementById("report-soc-btn");
  if (reportBtn) {
    reportBtn.addEventListener("click", async () => {
      reportBtn.disabled = true;
      const successMsg = document.getElementById("report-success-msg");

      if (currentInvId) {
        try {
          await client.reportToSoc(currentInvId, "Flagged by user via extension");
          if (successMsg) {
            successMsg.innerText = "✓ Incident reported directly to your SOC security queue!";
            successMsg.classList.remove("hidden");
          }
        } catch {
          // If reporting online failed, queue locally
          await queueOfflineReport(currentInvId, window._lastExtractedEmail);
        }
      } else {
        // Entirely offline scan: save to offline queue
        await queueOfflineReport(null, window._lastExtractedEmail);
      }
      reportBtn.disabled = false;
    });
  }

  // Offline queue helpers
  async function queueOfflineReport(invId, emailData) {
    const data = await chrome.storage.local.get(["hz_offline_queue"]);
    const queue = data.hz_offline_queue || [];
    queue.push({
      invId,
      emailData,
      timestamp: new Date().toISOString()
    });
    await chrome.storage.local.set({ hz_offline_queue: queue });
    const successMsg = document.getElementById("report-success-msg");
    if (successMsg) {
      successMsg.innerText = "⚡ Saved to Offline Queue! Will auto-sync to SOC when connected.";
      successMsg.classList.remove("hidden");
    }
    updateQueueBadge();
  }

  async function updateQueueBadge() {
    const data = await chrome.storage.local.get(["hz_offline_queue"]);
    const count = (data.hz_offline_queue || []).length;
    const badge = document.getElementById("offline-queue-badge");
    if (!badge) return;
    if (count > 0) {
      badge.innerText = `${count} Queued`;
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }
  }

  async function flushOfflineQueue() {
    const data = await chrome.storage.local.get(["hz_offline_queue"]);
    const queue = data.hz_offline_queue || [];
    if (queue.length === 0) return;

    const remaining = [];
    for (const item of queue) {
      try {
        if (item.invId) {
          await client.reportToSoc(item.invId, "Synced from offline queue");
        } else if (item.emailData) {
          const scanRes = await client.scanAsEmployee(item.emailData);
          await client.reportToSoc(scanRes.investigation_id, "Synced from offline queue");
        }
      } catch {
        remaining.push(item);
      }
    }
    await chrome.storage.local.set({ hz_offline_queue: remaining });
    updateQueueBadge();
  }
});
