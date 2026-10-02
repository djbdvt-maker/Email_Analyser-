import requests

url = "http://localhost:8000/api/v1/ingest"
headers = {
    "Authorization": "Bearer sih-extension-demo-key"
}
files = {
    "file": ("test.eml", b"From: test@test.com\nTo: admin@hopzero.test\nSubject: Hello\n\nThis is a test email.", "message/rfc822")
}
data = {
    "auto_analyze": "true"
}

response = requests.post(url, headers=headers, files=files, data=data)
print(response.status_code)
print(response.json())
