"""
Authorized target management: add/list/remove domains that scans
are permitted to run against.
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from api.models.database import get_db, AuthorizedTarget

router = APIRouter(prefix="/targets", tags=["authorized targets"])


class TargetRequest(BaseModel):
    domain: str
    notes: str = None


@router.post("")
def add_target(target: TargetRequest, db: Session = Depends(get_db)):
    existing = db.query(AuthorizedTarget).filter(AuthorizedTarget.domain == target.domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already authorized")

    record = AuthorizedTarget(id=str(uuid.uuid4()), domain=target.domain, notes=target.notes)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("")
def list_targets(db: Session = Depends(get_db)):
    return db.query(AuthorizedTarget).all()


@router.delete("/{target_id}")
def remove_target(target_id: str, db: Session = Depends(get_db)):
    record = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(record)
    db.commit()
    return {"status": "deleted"}