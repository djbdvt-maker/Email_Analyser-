import imaplib
import email
import time
import os
import logging
from threading import Thread
import requests

logger = logging.getLogger(__name__)

IMAP_SERVER = os.getenv("IMAP_SERVER", "")
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD", "")
INGEST_URL = "http://localhost:8000/api/v1/ingest?auto_analyze=true"

def watch_inbox():
    if not IMAP_SERVER or not IMAP_USER or not IMAP_PASSWORD:
        logger.info("IMAP credentials not configured. Email watcher disabled.")
        return

    logger.info(f"Starting IMAP watcher for {IMAP_USER} on {IMAP_SERVER}")
    
    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(IMAP_USER, IMAP_PASSWORD)
            mail.select('inbox')

            status, data = mail.search(None, '(UNSEEN)')
            if status == 'OK':
                for num in data[0].split():
                    status, msg_data = mail.fetch(num, '(RFC822)')
                    if status == 'OK':
                        raw_email = msg_data[0][1]
                        
                        # Post to our ingest endpoint
                        logger.info("New email detected. Ingesting to HopZero pipeline...")
                        files = {'file': ('inbox_email.eml', raw_email, 'message/rfc822')}
                        from app.config import get_settings
                        settings = get_settings()
                        headers = {}
                        if settings.hopzero_n8n_ingest_key:
                            headers["X-N8N-Ingest-Key"] = settings.hopzero_n8n_ingest_key
                        resp = requests.post(INGEST_URL, files=files, headers=headers)
                        
                        if resp.status_code == 200:
                            logger.info(f"Successfully ingested email from IMAP: {resp.json()}")
            
            mail.close()
            mail.logout()
        except Exception as e:
            logger.error(f"IMAP Watcher error: {e}")
            
        time.sleep(30)

def start_imap_watcher():
    t = Thread(target=watch_inbox, daemon=True)
    t.start()
