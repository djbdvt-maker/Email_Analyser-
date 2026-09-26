import os
import sys

# Append the current directory to sys.path
sys.path.append(os.path.abspath("."))

from tests.conftest import client, db_session, user
import app
from app.db.database import get_db

print("Checking clean email findings via FastAPI testclient...")
