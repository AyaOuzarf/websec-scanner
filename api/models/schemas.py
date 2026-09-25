"""Pydantic schemas for API request/response validation."""

from pydantic import BaseModel, HttpUrl
from typing import Optional
from datetime import datetime


class ScanRequest(BaseModel):
    target_url: HttpUrl
    checks: Optional[list[str]] = None  # e.g. ["http_security_headers", "ssl_tls"]


class ScanSummary(BaseModel):
    id: str
    target: str
    status: str
    risk_score: Optional[int] = None
    grade: Optional[str] = None
    total_findings: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanDetail(ScanSummary):
    report: Optional[dict] = None