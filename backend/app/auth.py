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