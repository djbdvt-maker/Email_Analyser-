import sys
import logging

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        logging.error("Missing arguments")
        sys.exit(1)

    user_id = sys.argv[1]
    inv_id = sys.argv[2]
    artifact_id = sys.argv[3]
    run_id = sys.argv[4]

    from app.database import SessionLocal
    from app.models import User
    from app.services.pipeline_service import execute_analysis_pipeline

    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        if user:
            execute_analysis_pipeline(
                db,
                user=user,
                investigation_id=inv_id,
                artifact_id=artifact_id,
                run_id=run_id,
            )
    except Exception as e:
        logging.error(f"Pipeline script failed: {e}")
    finally:
        db.close()
