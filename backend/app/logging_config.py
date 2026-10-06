# from fastapi import Depends, HTTPException, Request
# from sqlalchemy.orm import Session
# from .schemas import BulkCheckRequest
# from .models import ApiKey
# from .database import get_db
# from .auth import get_api_key
# from .config import Settings 
# from .services import run_check
# from .usage import increment_usage

# def bulk_check(
#     request: Request, 
#     payload: BulkCheckRequest, 
#     db: Session = Depends(get_db), 
#     api_key: ApiKey = Depends(get_api_key)
# ):
#     if not payload.emails:
#         raise HTTPException(
#             status_code=400,
#             detail={"code": "EMPTY_BULK_REQUEST", "message": "At least one email is required."}
#         )
        
#     # Deduplicate first so you count and process only unique emails
#     emails = list(dict.fromkeys(email.lower().strip() for email in payload.emails))
    
#     if len(emails) > Settings.max_bulk_size:
#         raise HTTPException(
#             status_code=400, 
#             detail=f"Maximum {Settings.max_bulk_size} unique emails per request"
#         )
        
#     # Charge based on the deduplicated/actual count
#     increment_usage(db, api_key, len(emails))
    
#     try:
#         results = [run_check(email, db) for email in emails]
#         db.commit()
#         return results
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(status_code=500, detail="Internal server error during bulk check.")

import logging
import sys

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ],
    )