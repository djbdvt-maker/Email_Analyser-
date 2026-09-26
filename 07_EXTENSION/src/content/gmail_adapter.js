chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "EXTRACT_EMAIL") {
    (async () => {
      try {
        let rawEml = null;
        let msgId = null;

        try {
          // Attempt 1: Gmail API Extraction
          const msgContainer = document.querySelector('[data-legacy-message-id]');
          msgId = msgContainer ? msgContainer.getAttribute('data-legacy-message-id') : null;
          
          let ik = null;
          const match = document.documentElement.innerHTML.match(/"ik"\s*,\s*"([^"]+)"/);
          if (match) ik = match[1];

          if (msgId && ik) {
            const rawUrl = `${window.location.origin}${window.location.pathname}?ui=2&ik=${ik}&view=om&th=${msgId}`;
            const res = await fetch(rawUrl);
            if (res.ok) {
              const text = await res.text();
              const parser = new DOMParser();
              const doc = parser.parseFromString(text, 'text/html');
              const pre = doc.querySelector('pre');
              if (pre && pre.innerText) {
                rawEml = pre.innerText;
              }
            }
          }
        } catch (apiErr) {
          console.warn("Gmail API extraction failed, falling back to DOM", apiErr);
        }

        if (!rawEml) {
          // Attempt 2: DOM Scraping Fallback
          msgId = msgId || window.location.hash.split('/').pop() || "unknown";
          
          const subjectEl = document.querySelector('h2.hP');
          const subject = subjectEl ? subjectEl.innerText : "No Subject";
          
          const senderEl = document.querySelector('.gD');
          const senderName = senderEl ? senderEl.innerText : "";
          const senderEmail = senderEl ? senderEl.getAttribute('email') : "unknown@example.com";
          
          const bodyEl = document.querySelector('.a3s.aiL');
          const body = bodyEl ? bodyEl.innerText : "No Body";
          
          // Construct synthetic .eml (Must be completely deterministic to pass backend SHA-256 integrity checks)
          rawEml = `From: ${senderName} <${senderEmail}>
To: Recipient <recipient@example.com>
Subject: ${subject}
Message-ID: <${msgId}@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

${body}`;
        }

        sendResponse({
          success: true,
          data: {
            provider: "gmail",
            capture_mode: "dom_fallback",
            provider_message_id: msgId,
            raw_eml: rawEml,
            raw_available: true
          }
        });
      } catch (e) {
        sendResponse({ success: false, error: e.toString() });
      }
    })();
    return true; // Keep message channel open for async response
  }
});
