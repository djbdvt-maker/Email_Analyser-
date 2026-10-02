wget -qO /tmp/openapi.json http://backend:8000/openapi.json
grep -o '"/api/v1/[^"]*"' /tmp/openapi.json | sort -u
