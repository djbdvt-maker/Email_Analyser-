#!/bin/bash
set -e

echo "Running Alembic migrations..."
alembic upgrade head || {
  echo "Alembic migration failed — stamping current state and retrying..."
  alembic stamp head
  echo "Database stamped. Skipping migrations."
}

echo "Initializing default admin user..."
python scripts/create_user.py --org-name "SIH Demo" --email "admin@hopzero.test" --password "admin123" --role ADMIN || true

echo "Starting Uvicorn server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
