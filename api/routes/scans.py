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

from api.utils.auth import get_current_user
from api.models.database import User

from fastapi.responses import FileResponse
from reports.generate_pdf import generate_pdf_report

from api.models.database import get_db, ScanRecord, User, AuthorizedTarget

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
def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    target_url = str(scan_request.target_url)

    if not is_target_authorized(target_url, db):
        raise HTTPException(status_code=403, detail="Target not authorized. Add it via /targets before scanning.")

    from urllib.parse import urlparse
    hostname = urlparse(target_url).hostname
    authorized_record = db.query(AuthorizedTarget).filter(AuthorizedTarget.domain == hostname).first()
    client_id = authorized_record.client_id if authorized_record else None

    scan_id = str(uuid.uuid4())
    record = ScanRecord(id=scan_id, target=target_url, client_id=client_id, status="pending")
    db.add(record)
    db.commit()
    db.refresh(record)

    background_tasks.add_task(_execute_scan, scan_id, target_url, scan_request.checks, None)
    return record

@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).all()


@router.post("", response_model=ScanSummary)
def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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



@router.get("/{scan_id}/pdf")
def download_scan_pdf(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.status != "completed":
        raise HTTPException(status_code=400, detail="Scan is not completed yet")

    client_name = None
    if record.client_id:
        client = db.query(Client).filter(Client.id == record.client_id).first()
        client_name = client.name if client else None

    scan_dict = {
        "id": record.id,
        "target": record.target,
        "client_name": client_name,
        "completed_at": str(record.completed_at),
        "grade": record.grade,
        "risk_score": record.risk_score,
        "total_findings": record.total_findings,
        "report": record.report,
    }

    pdf_path = generate_pdf_report(scan_dict)
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"security_report_{scan_id}.pdf")