"""
Scan endpoints: trigger a new scan, check status, retrieve results, list history.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid

from api.models.database import get_db, ScanRecord
from api.models.schemas import ScanRequest, ScanSummary, ScanDetail
from scanner.orchestrator import run_full_scan
from api.utils.authorization import is_target_authorized

router = APIRouter(prefix="/scan", tags=["scans"])


def _execute_scan(scan_id: str, target_url: str, checks: list, db_session_factory):
    """Runs in the background: performs the scan and updates the DB record."""
    from api.models.database import SessionLocal
    db = SessionLocal()
    try:
        record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        record.status = "running"
        db.commit()

        report = run_full_scan(target_url, checks_to_run=checks)

        record.status = "completed"
        record.risk_score = report["risk_summary"]["risk_score"]
        record.grade = report["risk_summary"]["grade"]
        record.total_findings = report["risk_summary"]["total_findings"]
        record.report = report
        record.completed_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as e:
        record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if record:
            record.status = "error"
            record.report = {"error": str(e)}
            db.commit()
    finally:
        db.close()


@router.post("", response_model=ScanSummary)
def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan_id = str(uuid.uuid4())
    target_url = str(scan_request.target_url)

    record = ScanRecord(id=scan_id, target=target_url, status="pending")
    db.add(record)
    db.commit()
    db.refresh(record)

    # Runs after the response is returned — non-blocking
    background_tasks.add_task(_execute_scan, scan_id, target_url, scan_request.checks, None)

    return record


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db)):
    return db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).all()


@router.post("", response_model=ScanSummary)
def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target_url = str(scan_request.target_url)

    if not is_target_authorized(target_url, db):
        raise HTTPException(
            status_code=403,
            detail=f"Target not authorized. Add it via /targets before scanning."
        )

    scan_id = str(uuid.uuid4())
    record = ScanRecord(id=scan_id, target=target_url, status="pending")
    db.add(record)
    db.commit()
    db.refresh(record)

    background_tasks.add_task(_execute_scan, scan_id, target_url, scan_request.checks, None)
    return record