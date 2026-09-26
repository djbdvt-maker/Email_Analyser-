"""
HopZero Local Demo Environment Bootstrap Utility
=================================================
Initializes a local demonstration environment with an evaluation organization
and test analyst user.

SECURITY WARNING:
This script is intended exclusively for isolated local evaluation / demo use.
DO NOT EXECUTE IN PRODUCTION ENVIRONMENTS.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base, engine, SessionLocal
from app.models import Organization, User, UserRole
from app.security import hash_password


def bootstrap_demo():
    print("Initializing HopZero local demo database...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # Create or fetch demo organization
        org = db.query(Organization).filter(Organization.name == "HopZero Primary").one_or_none()
        if org is None:
            org = Organization(name="HopZero Primary")
            db.add(org)
            db.flush()
            print(f"Created demo organization: '{org.name}' ({org.id})")
        else:
            print(f"Found existing demo organization: '{org.name}' ({org.id})")

        # Create or update demo administrator
        demo_email = "admin@hopzero.local"
        demo_pass = "changeme123"
        existing = db.query(User).filter(User.email == demo_email).one_or_none()
        if existing is None:
            user = User(
                organization_id=org.id,
                email=demo_email,
                hashed_password=hash_password(demo_pass),
                role=UserRole.ADMIN,
            )
            db.add(user)
            db.commit()
            print(f"Bootstrapped demo user: {demo_email} (Role: ADMIN)")
        else:
            print(f"Demo user already exists: {demo_email} (Role: {existing.role.value})")

        print("\n" + "=" * 60)
        print("DEMO BOOTSTRAP COMPLETE")
        print("Credentials for local evaluation:")
        print(f"  Email:    {demo_email}")
        print(f"  Password: {demo_pass}")
        print("WARNING: Change credentials or use create_user.py before any real use.")
        print("=" * 60 + "\n")
    finally:
        db.close()


if __name__ == "__main__":
    bootstrap_demo()
