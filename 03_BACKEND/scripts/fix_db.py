from sqlalchemy import text
from app.database import engine

def add_enum(val):
    try:
        with engine.connect() as conn:
            conn.execute(text(f"ALTER TYPE auditaction ADD VALUE '{val}';"))
            conn.commit()
            print(f"Added {val}")
    except Exception as e:
        print(f"Skipped {val}: {e}")

add_enum("ENFORCEMENT_REQUESTED")
add_enum("ENFORCEMENT_AUTHORIZED")
add_enum("ENFORCEMENT_EXECUTED")
add_enum("ENFORCEMENT_FAILED")
add_enum("ENFORCEMENT_REJECTED")
