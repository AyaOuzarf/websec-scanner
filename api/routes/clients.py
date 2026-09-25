"""
Client management: agencies organize scans and authorized targets
under named clients rather than raw domains.
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from api.models.database import get_db, Client, AuthorizedTarget, ScanRecord, User
from api.utils.auth import get_current_user

router = APIRouter(prefix="/clients", tags=["clients"])


class ClientRequest(BaseModel):
    name: str
    contact_email: Optional[str] = None
    notes: Optional[str] = None


@router.post("")
def create_client(client: ClientRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    existing = db.query(Client).filter(Client.name == client.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Client already exists")

    record = Client(id=str(uuid.uuid4()), **client.model_dump())
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("")
def list_clients(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Client).all()


@router.get("/{client_id}/targets")
def get_client_targets(client_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(AuthorizedTarget).filter(AuthorizedTarget.client_id == client_id).all()


@router.get("/{client_id}/scans")
def get_client_scans(client_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(ScanRecord).filter(ScanRecord.client_id == client_id).order_by(ScanRecord.created_at.desc()).all()


@router.delete("/{client_id}")
def delete_client(client_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    record = db.query(Client).filter(Client.id == client_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Client not found")
    db.delete(record)
    db.commit()
    return {"status": "deleted"}