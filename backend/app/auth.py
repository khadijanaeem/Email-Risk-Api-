# import hashlib
# from fastapi import Header, HTTPException, Depends
# from sqlalchemy.orm import Session
# from .database import get_db
# from .models import ApiKey


# def hash_key(key: str):
#     return hashlib.sha256(key.encode()).hexdigest()

# def get_api_key(
#     authorization: str | None = Header(default=None),
#     db: Session = Depends(get_db)
# ):
#     if not authorization or not authorization.startswith("Bearer "):
#         raise HTTPException(status_code=401, detail="Missing Bearer API key")

#     key = authorization[7:].strip()
#     record = db.query(ApiKey).filter(
#         ApiKey.key_hash == hash_key(key),
#         ApiKey.active == True
#     ).first()

#     if not record:
#         raise HTTPException(status_code=401, detail="Invalid API key")

#     return record
import hashlib

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .database import get_db
from .models import ApiKey
import secrets

from fastapi import Header, HTTPException, status

from .config import settings


def require_rapidapi(
    x_rapidapi_proxy_secret: str | None = Header(
        default=None,
        alias="X-RapidAPI-Proxy-Secret",
    ),
):
    expected = getattr(settings, "rapidapi_proxy_secret", None)

    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RapidAPI authentication is not configured.",
        )

    if not x_rapidapi_proxy_secret or not secrets.compare_digest(
        x_rapidapi_proxy_secret,
        expected,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request must come through RapidAPI.",
        )

    return True

security = HTTPBearer()


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def get_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    key = credentials.credentials

    record = (
        db.query(ApiKey)
        .filter(
            ApiKey.key_hash == hash_key(key),
            ApiKey.active == True,
        )
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return record