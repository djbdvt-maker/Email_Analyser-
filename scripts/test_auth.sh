#!/bin/sh
wget -qO /tmp/token.json \
  --header="Content-Type: application/x-www-form-urlencoded" \
  --post-data="username=$HOPZERO_USERNAME&password=$HOPZERO_PASSWORD" \
  http://backend:8000/api/v1/auth/login

if [ -f "/tmp/token.json" ]; then
    cat /tmp/token.json
    
    # Extract token
    TOKEN=$(grep -o '"access_token":"[^"]*"' /tmp/token.json | cut -d'"' -f4)
    
    # Test authenticated endpoint
    wget -qO /tmp/investigations.json \
      --header="Authorization: Bearer $TOKEN" \
      http://backend:8000/api/v1/investigations
      
    echo ""
    echo "--- Investigations ---"
    cat /tmp/investigations.json
else
    echo "Auth failed."
fi
