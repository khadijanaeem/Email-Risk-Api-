from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from fastapi import Request, Response , APIRouter
from .auth import get_api_key
from .config import settings 
from .database import Base, engine, get_db
from .models import ApiKey, DomainCache, Usage, User
from .schemas import BulkCheckRequest, CheckRequest, CheckResponse, CreateKeyRequest, CreateKeyResponse
from .services import (
    calculate_risk, check_dmarc, check_mx, check_spf, domain_age_days,
    generate_api_key, is_disposable, parse_email, suspicious_lookalike, FREE_PROVIDERS,
)
from datetime import datetime
import logging, time, uuid
from .services import run_check
from .usage import increment_usage
from .logging_config import setup_logging


logger=logging.getLogger("email-risk-api")
limiter = Limiter(key_func=get_remote_address)

setup_logging()
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.app_name,
    version="1.1.0",
    description="Email signup-abuse risk API using disposable-domain intelligence, DNS checks and cached RDAP domain-age signals.",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Email", "description": "Email risk checks."},
        {"name": "Authentication", "description": "Development API-key management."},
        {"name": "Account", "description": "Usage information."},
    ],
)
app.state.limiter = limiter

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):
    request_id = request.headers.get(
        "X-Request-ID"
    )

    logger.exception(
        "Unhandled exception request_id=%s",
        request_id
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred.",
                "request_id": request_id
            }
        }
    )

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again later."})

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"],
# )

origins = [
    origin.strip()
    for origin in settings.cors_origins.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Request-ID",
    ],
)

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get(
        "X-Request-ID",
        f"req_{uuid.uuid4().hex}"
    )

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id

    return response

@app.middleware("http")
async def monitoring_middleware(
    request: Request,
    call_next
):
    start = time.perf_counter()

    try:
        response = await call_next(request)

        return response

    finally:
        duration = time.perf_counter() - start

        logger.info(
            "request method=%s path=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            duration * 1000
        )
@app.get("/", tags=["Email"])
def root():
    return {"name": settings.app_name, "version": "1.1.0", "docs": "/docs"}

@app.get("/health", tags=["Email"])
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat()
    }
# def health():
#     return {"status": "ok"}

@app.get("/ready", tags=["Email"])

# @app.get("/ready")

async def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))

        return {
            "status": "ready",
            "database": "ok"
        }

    except Exception:
        logger.exception(
            "Database readiness check failed"
        )

        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "database": "error"
            }
        )

@app.get("/privacy", tags=["Legal"])
async def privacy():
    return {
        "name": settings.app_name,
        "policy": {
            "email_checks": "Email addresses are processed to perform risk analysis.",
            "storage": "Individual email checks should not be permanently stored unless required for service operation.",
            "api_keys": "API keys are stored as cryptographic hashes.",
            "logs": "Sensitive values should not be written to application logs."
        }
    }

@app.get("/terms", tags=["Legal"])
async def terms():
    return {
        "name": settings.app_name,
        "terms": {
            "acceptable_use": "Do not use the API for unlawful activity.",
            "availability": "The service is provided on an as-is basis.",
            "rate_limits": "Requests are subject to applicable API plan limits."
        }
    }

@app.post("/v1/keys", response_model=CreateKeyResponse, tags=["Authentication"])
def create_key(payload: CreateKeyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user:
        user = User(email=payload.email.lower())
        db.add(user); db.flush()
    raw_key, digest = generate_api_key(settings.api_key_prefix)
    key = ApiKey(user_id=user.id, key_hash=digest, name=payload.name, monthly_limit=1000)
    db.add(key); db.commit()
    return {"api_key": raw_key, "warning": "Store this key now. The full secret is not shown again."}

# def increment_usage(db: Session, api_key: ApiKey, amount: int = 1):
#     from datetime import datetime, timezone
#     period = datetime.now(timezone.utc).strftime("%Y-%m")
#     usage = db.query(Usage).filter(Usage.api_key_id == api_key.id, Usage.period == period).first()
#     if not usage:
#         usage = Usage(api_key_id=api_key.id, period=period, request_count=0)
#         db.add(usage)
#     if usage.request_count + amount > api_key.monthly_limit:
#         raise HTTPException(status_code=429, detail="Monthly API limit reached")
#     usage.request_count += amount
#     api_key.last_used_at = datetime.now(timezone.utc)

# def increment_usage(db, api_key):
#     period = datetime.utcnow().strftime("%Y-%m")

#     usage = (
#         db.query(Usage)
#         .filter(
#             Usage.api_key_id == api_key.id,
#             Usage.period == period
#         )
#         .first()
#     )

#     if usage is None:
#         usage = Usage(
#             api_key_id=api_key.id,
#             period=period,
#             request_count=0
#         )

#         db.add(usage)

#     usage.request_count += 1
#     api_key.last_used_at = datetime.utcnow()
#     db.flush()
#     return usage

# def run_check(email: str, db: Session):
#     try:
#         normalized_email, domain = parse_email(email)
#         logger.info(
#         "Risk check email_hash=%s domain=%s",
#         email_hash(email),
#         domain
#     )
#     except ValueError as exc:
#         raise HTTPException(status_code=422, detail=str(exc)) from exc

#     cached = db.query(DomainCache).filter(DomainCache.domain == domain).first()
#     from datetime import datetime, timezone, timedelta
#     fresh = cached and cached.checked_at and cached.checked_at >= datetime.now(timezone.utc) - timedelta(seconds=Settings.cache_ttl_seconds)
#     if fresh:
#         age = cached.domain_age_days
#         mx_valid, spf, dmarc, disposable = cached.mx_valid, cached.spf, cached.dmarc, cached.disposable
#     else:
#         mx_valid = check_mx(domain)
#         spf = check_spf(domain)
#         dmarc = check_dmarc(domain)
#         disposable = is_disposable(domain)
#         age = domain_age_days(domain)
#         if not cached:
#             cached = DomainCache(domain=domain)
#             db.add(cached)
#         cached.domain_age_days = age
#         cached.mx_valid = mx_valid
#         cached.spf = spf
#         cached.dmarc = dmarc
#         cached.disposable = disposable
#         cached.checked_at = datetime.now(timezone.utc)
#         db.flush()

#     free_provider = domain in FREE_PROVIDERS
#     lookalike = suspicious_lookalike(domain)
#     score, level, verdict, signals = calculate_risk(
#         disposable=disposable, free_provider=free_provider, mx_valid=mx_valid,
#         spf=spf, dmarc=dmarc, domain_age_days_value=age, lookalike=lookalike,
#     )
#     # return CheckResponse(
#     #     email=normalized_email, domain=domain, valid_format=True, disposable=disposable,
#     #     free_provider=free_provider, mx_valid=mx_valid, spf=spf, dmarc=dmarc,
#     #     domain_age_days=age, lookalike=lookalike, risk_score=score,
#     #     risk_level=level, verdict=verdict, signals=signals,
#     # )
#     risk = calculate_risk(
#     disposable=disposable,
#     free_provider=free_provider,
#     mx_valid=mx_valid,
#     spf=spf,
#     dmarc=dmarc,
#     domain_age_days=domain_age_days,
#     lookalike=lookalike,
#     )

#     return CheckResponse(
#         email=str(email),
#         domain=domain,
#         valid_format=True,
#         disposable=disposable,
#         free_provider=free_provider,
#         mx_valid=mx_valid,
#         spf=spf,
#         dmarc=dmarc,
#         domain_age_days=domain_age_days,
#         lookalike=lookalike,
#         risk_score=risk["risk_score"],
#         risk_level=risk["risk_level"],
#         verdict=risk["verdict"],
#         signals=risk["signals"],
#         score_breakdown=risk["score_breakdown"],

#         data_quality={
#             "dns": "available" if any(
#                 value is not None
#                 for value in [mx_valid, spf, dmarc]
#             ) else "unavailable",

#             "rdap": (
#                 "available"
#                 if domain_age_days is not None
#                 else "unavailable"
#             )
#         }

#     )

@app.post("/v1/check", response_model=CheckResponse, tags=["Email"], summary="Check email risk",
    description=(
        "Analyzes an email address for disposable domains, "
        "free providers, DNS signals, domain age, and "
        "lookalike domains."
    ))
@limiter.limit("60/minute")

def check_email(request: Request,  response: Response, payload: CheckRequest, db: Session = Depends(get_db), api_key: ApiKey = Depends(get_api_key)):
    usage= increment_usage(db, api_key)

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

@app.post("/v1/bulk-check", response_model=list[CheckResponse], tags=["Email"])
@limiter.limit("10/minute")

def bulk_check(
    request: Request, 
    payload: BulkCheckRequest, 
    db: Session = Depends(get_db), 
    api_key: ApiKey = Depends(get_api_key)
):
    if not payload.emails:
        raise HTTPException(
            status_code=400,
            detail={"code": "EMPTY_BULK_REQUEST", "message": "At least one email is required."}
        )
        
    # Deduplicate first so you count and process only unique emails
    emails = list(dict.fromkeys(email.lower().strip() for email in payload.emails))
    
    if len(emails) > settings.max_bulk_size:
        raise HTTPException(
            status_code=400, 
            detail=f"Maximum {settings.max_bulk_size} unique emails per request"
        )
        
    # Charge based on the deduplicated/actual count
    increment_usage(db, api_key, len(emails))
    
    try:
        results = [run_check(email, db) for email in emails]
        db.commit()
        return results
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error during bulk check.")


@app.get("/v1/usage", tags=["Account"])
def usage(db: Session = Depends(get_db), api_key: ApiKey = Depends(get_api_key)):
    from datetime import datetime, timezone
    period = datetime.now(timezone.utc).strftime("%Y-%m")
    row = db.query(Usage).filter(Usage.api_key_id == api_key.id, Usage.period == period).first()
    used = row.request_count if row else 0
    return {"period": period, "used": used, "limit": api_key.monthly_limit, "remaining": max(0, api_key.monthly_limit - used)}
