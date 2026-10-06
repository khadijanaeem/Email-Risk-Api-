import hashlib
# from .services import run_check
from .usage import increment_usage

def email_hash(email: str) -> str:
    return hashlib.sha256(
        email.lower().strip().encode()
    ).hexdigest()[:12]

# def check_email(request: Request,  response: Response, payload: CheckRequest, db: Session = Depends(get_db), api_key: ApiKey = Depends(get_api_key)):
    usage = increment_usage(db, api_key)
    response.headers["X-RateLimit-Limit"] = str(
    api_key.monthly_limit
    )

    response.headers["X-RateLimit-Remaining"] = str(
        max(
            0,
            api_key.monthly_limit - usage.request_count
        )
    )
    result = run_check(payload.email, db)
    db.commit()
    return result