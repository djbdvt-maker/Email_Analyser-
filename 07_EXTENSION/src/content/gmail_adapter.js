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

        let isRaw = true;
        if (!rawEml) {
          isRaw = false;
          // Attempt 2: DOM Scraping Fallback
          msgId = msgId || window.location.hash.split('/').pop() || "unknown";
          
          const subjectEl = document.querySelector('h2.hP');
          const subject = subjectEl ? subjectEl.innerText : "No Subject";
          
          const senderEl = document.querySelector('.gD');
          const senderName = senderEl ? senderEl.innerText : "";
          const senderEmail = senderEl ? senderEl.getAttribute('email') : "unknown@example.com";
          
          const bodyEl = document.querySelector('.a3s.aiL');
          const body = bodyEl ? bodyEl.innerText : "No Body";
          
          const bodyHtml = bodyEl ? bodyEl.innerHTML : "";
          
          // Generate a proper multi-part MIME .eml
          const boundary = "----=_Part_" + (new Date().getTime()).toString(16) + "_" + Math.random().toString(16).substring(2);

          // Helper for Base64 encoding unicode text safely in the browser
          const base64EncodeUnicode = (str) => {
              return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)));
          };

          const plainTextB64 = base64EncodeUnicode(body);
          const htmlB64 = base64EncodeUnicode(bodyHtml);

          rawEml = `From: ${senderName} <${senderEmail}>
To: Recipient <recipient@example.com>
Subject: ${subject}
Message-ID: <${msgId}@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="${boundary}"

--${boundary}
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

${plainTextB64.match(/.{1,76}/g)?.join('\r\n') || ''}

--${boundary}
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

${htmlB64.match(/.{1,76}/g)?.join('\r\n') || ''}
--${boundary}--
`;
        }

        let responseData = {
          provider: "gmail",
          capture_mode: isRaw ? "api" : "dom_fallback",
          provider_message_id: msgId,
          raw_eml: rawEml,
          raw_available: isRaw ? true : false // raw_available: false
        };

        sendResponse({
          success: true,
          data: responseData
        });
      } catch (e) {
        sendResponse({ success: false, error: e.toString() });
      }
    })();
    return true; // Keep message channel open for async response
  }
});
