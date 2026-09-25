"""
Authorized target management: add/list/remove domains that scans
are permitted to run against.
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from api.models.database import get_db, AuthorizedTarget
from api.utils.auth import get_current_user
from api.models.database import User
from typing import Optional

router = APIRouter(prefix="/targets", tags=["authorized targets"])


class TargetRequest(BaseModel):
    domain: str
    client_id: Optional[str] = None 
    notes: str = None


@router.post("")
def add_target(target: TargetRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    existing = db.query(AuthorizedTarget).filter(AuthorizedTarget.domain == target.domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already authorized")

    record = AuthorizedTarget(
        id=str(uuid.uuid4()),
        domain=target.domain,
        client_id=target.client_id,
        notes=target.notes,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

@router.get("")
def list_targets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(AuthorizedTarget).all()


@router.delete("/{target_id}")
def remove_target(target_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    record = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(record)
    db.commit()
    return {"status": "deleted"}