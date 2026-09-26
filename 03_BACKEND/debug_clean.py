import sys
import os
sys.path.append(os.path.abspath("."))
from app.database import get_db
from app.models import Investigation, Finding, AnalysisRun

db = next(get_db())

invs = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(10).all()
for inv in invs:
    print(f"Investigation {inv.id}")
    run = db.query(AnalysisRun).filter(AnalysisRun.investigation_id == inv.id).first()
    if run:
        print(f"Run {run.id}, status {run.status}")
        findings = db.query(Finding).filter(Finding.analysis_run_id == run.id).all()
        for f in findings:
            print(f"- {f.qualification_code} ({f.strength}) by {f.produced_by}")
        print("---")
