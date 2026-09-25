"""
Database setup and models for scan storage (SQLite for simplicity,
swappable to PostgreSQL later by changing DATABASE_URL).
"""

from sqlalchemy import create_engine, Column, String, DateTime, Integer, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

DATABASE_URL = "sqlite:///./data/scans.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    client_id = Column(String, nullable=True)   # NEW
    status = Column(String, default="pending")
    risk_score = Column(Integer, nullable=True)
    grade = Column(String, nullable=True)
    total_findings = Column(Integer, nullable=True)
    report = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

def init_db():
    import os
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
        
class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"

    id = Column(String, primary_key=True)
    domain = Column(String, nullable=False, unique=True)
    client_id = Column(String, nullable=True)   # NEW — links to Client.id
    added_by = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    
class Client(Base):
    __tablename__ = "clients"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    contact_email = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))