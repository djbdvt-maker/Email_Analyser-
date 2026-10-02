document.addEventListener("DOMContentLoaded", async () => {
  const client = new window.HopZeroClient();
  let currentInvId = null;
  let currentRunId = null;
  let newRunId = null;
  let pollingInterval = null;

  const storage = await chrome.storage.local.get(["hz_token", "hz_url"]);
  if (storage.hz_token) {
    client.token = storage.hz_token;
    client.baseUrl = storage.hz_url || "http://localhost:8000";
    document.getElementById("login-view").classList.add("hidden");
    document.getElementById("main-view").classList.remove("hidden");
    document.getElementById("auth-status").innerText = "Logged In";
  }

  document.getElementById("login-btn").addEventListener("click", async () => {
    try {
      const user = document.getElementById("username").value.trim();
      const pass = document.getElementById("password").value.trim();
      const url = document.getElementById("api-url").value.trim();
      await client.login(user, pass, url);
      await chrome.storage.local.set({ hz_token: client.token, hz_url: url });
      
      document.getElementById("login-view").classList.add("hidden");
      document.getElementById("main-view").classList.remove("hidden");
      document.getElementById("auth-status").innerText = "Logged In";
    } catch (e) {
      document.getElementById("login-error").innerText = e.message;
    }
  });

  document.getElementById("analyze-btn").addEventListener("click", async () => {
    document.getElementById("status-container").classList.remove("hidden");
    document.getElementById("run-status").innerText = "CAPTURING";
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    // Safety check: Content scripts can't run on chrome:// or restricted pages
    if (!tab || !tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) {
      document.getElementById("run-status").innerText = "ERROR: Please open a Gmail email first.";
      return;
    }

    try {
      // Force injection so user doesn't have to manually refresh the page
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["src/content/gmail_adapter.js"]
        });
      } catch (injectionError) {
        console.warn("Could not inject script (maybe already injected or restricted):", injectionError);
      }

      const response = await chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_EMAIL" });
      
      if (!response || !response.success) {
        document.getElementById("run-status").innerText = "FAILED TO CAPTURE EMAIL";
        return;
      }
      if (!response.data.raw_available) {
        document.getElementById("reconstructed-warning").classList.remove("hidden");
      }
      
      document.getElementById("run-status").innerText = "SUBMITTING";
      try {
        const ingestRes = await client.ingestEmail(response.data);
        currentInvId = ingestRes.investigation_id;
        currentRunId = ingestRes.analysis_run_id;
        pollRun(currentRunId);
      } catch(e) {
        console.error("Ingestion failed:", e);
        if (e.message && (e.message.includes("401") || e.message.includes("403"))) {
          await chrome.storage.local.remove(["hz_token"]);
          document.getElementById("login-view").classList.remove("hidden");
          document.getElementById("main-view").classList.add("hidden");
          document.getElementById("login-error").innerText = "Session expired. Please log in again.";
        } else {
          document.getElementById("run-status").innerText = `FAILED TO INGEST (${e.message})`;
        }
      }
    } catch (e) {
      console.error("Extraction error:", e);
      document.getElementById("run-status").innerText = `ERROR: ${e.message || "Could not run on this page."}`;
    }
  });

  document.getElementById("visual-scan-btn").addEventListener("click", async () => {
    document.getElementById("status-container").classList.remove("hidden");
    document.getElementById("run-status").innerText = "RUNNING VISUAL SCANNER...";
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) {
      document.getElementById("run-status").innerText = "ERROR: Please open a Gmail email first.";
      return;
    }

    try {
      await chrome.scripting.insertCSS({
        target: { tabId: tab.id },
        files: ["src/styles/visual_scanner.css"]
      });
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["src/content/visual_scanner.js"]
      });
    } catch (e) {
      console.warn("Could not inject visual scanner scripts:", e);
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { type: "EXR_SCAN" });
      if (response && response.ok) {
        document.getElementById("run-status").innerText = `VISUAL SCAN DONE: ${response.results.length} findings.`;
      } else {
        document.getElementById("run-status").innerText = "VISUAL SCAN FAILED.";
      }
    } catch(e) {
      document.getElementById("run-status").innerText = "ERROR: Could not communicate with page.";
    }
  });

  function safeSetText(id, text) {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
  }

  async function pollRun(runId, isNewRun = false) {
    if (pollingInterval) clearInterval(pollingInterval);
    let attempts = 0;
    const MAX_ATTEMPTS = 120;
    
    // UI Progress Bar Steps
    const progContainer = document.getElementById("progress-container");
    const progFill = document.getElementById("progress-fill");
    const progText = document.getElementById("progress-text");
    progContainer.classList.remove("hidden");
    
    const steps = [
      "Extracting metadata...",
      "Mapping IP routing tables...",
      "Running deterministic YARA...",
      "Executing AI models...",
      "Computing Final Forensic Score..."
    ];

    pollingInterval = setInterval(async () => {
      attempts++;
      
      // Fake progress logic
      const progPercent = Math.min(95, attempts * (100 / MAX_ATTEMPTS));
      progFill.style.width = progPercent + "%";
      const stepIdx = Math.min(steps.length - 1, Math.floor((progPercent / 100) * steps.length));
      progText.innerText = steps[stepIdx];

      if (attempts > MAX_ATTEMPTS) {
        clearInterval(pollingInterval);
        document.getElementById("run-status").innerText = "Analysis timed out.";
        progContainer.classList.add("hidden");
        return;
      }

      try {
        const run = await client.getAnalysisRun(currentInvId, runId);
        const status = run.status;
        if (!status) throw new Error("Missing status");
        
        document.getElementById("run-status").innerText = isNewRun ? `NEW RUN: ${status}` : status;
        
        if (status === "COMPLETED") {
          clearInterval(pollingInterval);
          progFill.style.width = "100%";
          progText.innerText = "Done!";
          setTimeout(() => progContainer.classList.add("hidden"), 500);

          if (isNewRun) {
            displayComparison(currentRunId, runId);
          } else {
            displayResults(runId);
          }
        } else if (status === "FAILED" || status === "CANCELLED") {
          clearInterval(pollingInterval);
          progContainer.classList.add("hidden");
        }
      } catch(e) {
        // network error or 404, continue polling until timeout
      }
    }, 1500);
  }

  async function displayResults(runId) {
    try {
      const scoreData = await client.getScore(currentInvId, runId);
      const findingsData = await client.getFindings(currentInvId, runId);
      
      document.getElementById("results-container").classList.remove("hidden");
      
      safeSetText("res-severity", scoreData.severity);
      safeSetText("res-score", scoreData.total_score);
      safeSetText("res-verdict", scoreData.verdict);
      safeSetText("res-conclusion", scoreData.conclusion_text);

      let whyText = scoreData.why_explanation;
      if (whyText.includes("without establishing confirmed maliciousness")) {
          whyText = "We found a few suspicious flags (like missing security headers), but no hard proof of a cyberattack. Proceed with caution.";
      } else if (scoreData.severity === "CRITICAL" || scoreData.severity === "HIGH") {
          whyText = "🚨 Warning: This email contains severe, confirmed threats (like known malware) and is extremely dangerous.";
      }
      safeSetText("res-why", whyText);
      
      const floorsStr = (scoreData.triggered_floor_codes || []).join(", ");
      safeSetText("res-floors", floorsStr || "None");
      
      const ul = document.getElementById("res-findings");
      ul.innerHTML = "";
      findingsData.forEach(f => {
        const li = document.createElement("li");
        
        let friendlyText = `[${f.qualification_code}] ${f.supporting_text}`;
        if (f.qualification_code === "DKIM_NONE") friendlyText = `⚠️ Missing DKIM (Email could be spoofed)`;
        else if (f.qualification_code === "DMARC_NONE") friendlyText = `⚠️ Missing DMARC (Sender identity unverified)`;
        else if (f.qualification_code === "SPF_NONE") friendlyText = `⚠️ Missing SPF (Sender server is not authorized)`;
        else if (f.qualification_code === "KNOWN_MALWARE_SIGNATURE") friendlyText = `🚨 Known Threat: ${f.supporting_text.split(':').pop()}`;
        else if (f.qualification_code === "FINANCIAL_REQUEST") friendlyText = `💸 Urgent Request: "${f.supporting_text}"`;
        
        li.innerText = friendlyText;
        li.style.marginBottom = "5px";
        ul.appendChild(li);
      });
    } catch(e) {
      console.error(e);
    }
  }

  document.getElementById("feedback-btn").addEventListener("click", async () => {
    document.getElementById("run-status").innerText = "AWAITING_FEEDBACK";
    try {
      const fb = await client.submitFeedback(currentInvId, currentRunId, "PHISHING_REPORTED", "Actually, I think this is phishing.");
      newRunId = fb.new_analysis_run_id;
      document.getElementById("run-status").innerText = "REANALYZING";
      pollRun(newRunId, true);
    } catch(e) {
      console.error(e);
    }
  });

  async function displayComparison(oldRun, newRun) {
    try {
      safeSetText("comp-old-run", oldRun.substring(0, 8) + "...");
      safeSetText("comp-new-run", newRun.substring(0, 8) + "...");

      const comp = await client.compareRuns(currentInvId, oldRun, newRun);
      document.getElementById("compare-container").classList.remove("hidden");
      
      safeSetText("comp-score-delta", comp.score_delta);
      safeSetText("comp-severity-change", comp.severity_change ? "Changed" : "Unchanged");
      safeSetText("comp-verdict-change", comp.verdict_change ? "Changed" : "Unchanged");
      
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
      document.getElementById("enforcement-container").classList.remove("hidden");
      const ul = document.getElementById("enforcement-options");
      ul.innerHTML = "";
      opts.forEach(opt => {
        const btn = document.createElement("button");
        btn.innerText = `[ ${opt.action_type} ] ${opt.target}`;
        btn.className = "warning";
        btn.onclick = () => {
          selectedAction = opt.action_type;
          selectedTarget = opt.target;
          document.getElementById("auth-container").classList.remove("hidden");
          safeSetText("auth-target", opt.target);
          safeSetText("auth-action", opt.action_type);
        };
        const li = document.createElement("li");
        li.appendChild(btn);
        ul.appendChild(li);
      });
    } catch(e) {
      console.error(e);
    }
  }

  document.getElementById("authorize-btn").addEventListener("click", async () => {
    if (!selectedAction || !selectedTarget) return;
    try {
      const req = await client.requestEnforcement(currentInvId, selectedAction, selectedTarget);
      const actionId = req.id;
      await client.authorizeEnforcement(currentInvId, actionId);
      const exec = await client.executeEnforcement(currentInvId, actionId);
      
      safeSetText("enforcement-status", `Result: ${exec.status}`);
      document.getElementById("auth-container").classList.add("hidden");
    } catch(e) {
      safeSetText("enforcement-status", `Failed: ${e.message}`);
    }
  });
});
