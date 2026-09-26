"""
One-off bootstrap script: create an Organization + User for local/dev
use. There is intentionally no public self-signup API endpoint in
this MVP -- user provisioning is an operator action.

Usage:
    python scripts/create_user.py --org-name "Acme Security" \
        --email analyst@acme.test --password "changeme123" --role ADMIN
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import SessionLocal
from app.models import Organization, User, UserRole
from app.security import hash_password


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org-name", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="ADMIN", choices=[r.value for r in UserRole])
    args = parser.parse_args()

    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.name == args.org_name).one_or_none()
        if org is None:
            org = Organization(name=args.org_name)
            db.add(org)
            db.flush()

        existing = db.query(User).filter(User.email == args.email).one_or_none()
        if existing is not None:
            print(f"User {args.email} already exists.")
            return

        user = User(
            organization_id=org.id,
            email=args.email,
            hashed_password=hash_password(args.password),
            role=UserRole(args.role),
        )
        db.add(user)
        db.commit()
        print(f"Created user {args.email} in org '{org.name}' ({org.id}) with role {args.role}.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
