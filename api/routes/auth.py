"""
Authentication endpoints: register a user, log in and receive a JWT.
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from api.models.database import get_db, User
from api.utils.auth import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        id=str(uuid.uuid4()),
        username=request.username,
        hashed_password=hash_password(request.password),
    )
    db.add(user)
    db.commit()
    return {"status": "registered", "username": user.username}


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer"}