"""
Authorization check: only allow scans against domains explicitly
added to the authorized_targets table.
"""

from urllib.parse import urlparse
from sqlalchemy.orm import Session
from api.models.database import AuthorizedTarget


def is_target_authorized(target_url: str, db: Session) -> bool:
    hostname = urlparse(target_url).hostname
    if not hostname:
        return False

    # Allow localhost/local lab targets automatically (dev/testing convenience)
    if hostname in ("localhost", "127.0.0.1"):
        return True

    record = db.query(AuthorizedTarget).filter(AuthorizedTarget.domain == hostname).first()
    return record is not None