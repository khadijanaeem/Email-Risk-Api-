from __future__ import annotations
import hashlib
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from sqlalchemy.orm import Session
import dns.resolver, httpx
from email_validator import EmailNotValidError, validate_email
import logging, requests
from .utils import email_hash
from fastapi import HTTPException
from sqlalchemy import text
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from .config import settings 
from .models import DomainCache
from .schemas import CheckResponse
from datetime import datetime
from .utils import email_hash



logger = logging.getLogger("email-risk-api")
DISPOSABLE_FILE = Path(__file__).resolve().parent / "data" / "disposable_domains.txt"
DISPOSABLE_URL = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/disposable_email_blocklist.conf"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "pm.me", "aol.com", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "yandex.ru", "mail.ru",
}

STARTER_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "guerrillamailblock.com",
    "temp-mail.org", "tempmail.com", "tempmailo.com", "yopmail.com", "sharklasers.com",
    "getnada.com", "maildrop.cc", "discard.email", "fakeinbox.com", "emailondeck.com",
    "mailnesia.com", "mintemail.com", "throwawaymail.com", "mailcatch.com", "mailnull.com",
    "spamgourmet.com", "trashmail.com", "trashmail.me", "trashmail.net", "mytrashmail.com",
    "tempail.com", "tempr.email", "burnermail.io", "mohmal.com", "emailfake.com",
    "fakemail.net", "tempmailaddress.com", "disposablemail.com", "disposable-emails.com",
}

PROTECTED_BRANDS = {
    "google.com", "microsoft.com", "apple.com", "paypal.com", "stripe.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "openai.com",
}


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain

def calculate_risk(
    disposable: bool,
    free_provider: bool,
    mx_valid: bool | None,
    spf: bool| None,
    dmarc: bool| None,
    domain_age_days: int | None,
    lookalike: bool,
):
    score = 0
    signals = []
    breakdown = {}

    # Disposable email
    if disposable:
        score += 60
        signals.append("disposable_email_domain")
        breakdown["disposable_email_domain"] = 60

    # Domain age
    if domain_age_days is not None:
        if domain_age_days < 7:
            score += 25
            signals.append("very_new_domain")
            breakdown["very_new_domain"] = 25
        elif domain_age_days < 30:
            score += 10
            signals.append("new_domain")
            breakdown["new_domain"] = 10

    # MX
    if mx_valid is False:
        score += 30
        signals.append("missing_mx_record")
        breakdown["missing_mx_record"] = 30


    # Free provider
    if free_provider:
        score += 5
        signals.append("free_email_provider")
        breakdown["free_email_provider"] = 5

    # Lookalike
    if lookalike:
        score += 35
        signals.append("lookalike_domain")
        breakdown["lookalike_domain"] = 35

    # SPF
    if spf is False:
        score += 3
        signals.append("missing_spf")
        breakdown["missing_spf"] = 3

    # DMARC
    if dmarc is False:
        score += 2
        signals.append("missing_dmarc")
        breakdown["missing_dmarc"] = 2

    score = min(score, 100)

    if score >= 80:
        risk_level = "very_high"
        verdict = "block"
    elif score >= 60:
        risk_level = "high"
        verdict = "block"
    elif score >= 30:
        risk_level = "medium"
        verdict = "review"
    else:
        risk_level = "low"
        verdict = "allow"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "signals": signals,
        "score_breakdown": breakdown,
    }

def run_check(email: str, db: Session):
    try:
        normalized_email, domain = parse_email(email)

        logger.info(
            "Risk check email_hash=%s domain=%s",
            email_hash(email),
            domain
        )

    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    cached = (
        db.query(DomainCache)
        .filter(DomainCache.domain == domain)
        .first()
    )

    from datetime import timedelta

    fresh = (
        cached
        and cached.checked_at
        and cached.checked_at >= (
            datetime.now(timezone.utc)
            - timedelta(seconds=settings.rdap_cache_ttl_seconds)
        )
    )

    if fresh:
        # Use cached values
        age = cached.domain_age_days
        mx_valid = cached.mx_valid
        spf = cached.spf
        dmarc = cached.dmarc
        disposable = cached.disposable

    else:
        # Perform fresh checks
        mx_valid = check_mx(domain)
        spf = check_spf(domain)
        dmarc = check_dmarc(domain)
        disposable = is_disposable(domain)
        age = domain_age_days(domain)

        if not cached:
            cached = DomainCache(domain=domain)
            db.add(cached)

        cached.domain_age_days = age
        cached.mx_valid = mx_valid
        cached.spf = spf
        cached.dmarc = dmarc
        cached.disposable = disposable
        cached.checked_at = datetime.now(timezone.utc)

        db.flush()

    # Additional risk indicators
    free_provider = domain in FREE_PROVIDERS
    lookalike = suspicious_lookalike(domain)

    # Calculate risk BEFORE returning it
    risk = calculate_risk(
        disposable=disposable,
        free_provider=free_provider,
        mx_valid=mx_valid,
        spf=spf,
        dmarc=dmarc,
        domain_age_days=age,
        lookalike=lookalike,
    )

    return CheckResponse(
        email=normalized_email,
        domain=domain,
        valid_format=True,
        disposable=disposable,
        free_provider=free_provider,
        mx_valid=mx_valid,
        spf=spf,
        dmarc=dmarc,
        domain_age_days=age,
        lookalike=lookalike,

        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        verdict=risk["verdict"],
        signals=risk["signals"],
        score_breakdown=risk["score_breakdown"],

        data_quality={
            "dns": (
                "available"
                if any(
                    value is not None
                    for value in [mx_valid, spf, dmarc]
                )
                else "unavailable"
            ),
            "rdap": (
                "available"
                if age is not None
                else "unavailable"
            )
        }
    )
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
#     fresh = cached and cached.checked_at and cached.checked_at >= datetime.now(timezone.utc) - timedelta(seconds=settings.rdap_cache_ttl_seconds)
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

#     return CheckResponse(
#         email=str(email),
#         domain=domain,
#         valid_format=True,
#         disposable=disposable,
#         free_provider=free_provider,
#         mx_valid=mx_valid,
#         spf=spf,
#         dmarc=dmarc,
#         domain_age_days=age,
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
#                 if age is not None
#                 else "unavailable"
#             )
#         }
#     )

#     # score, level, verdict, signals = calculate_risk(
#     #     disposable=disposable, free_provider=free_provider, mx_valid=mx_valid,
#     #     spf=spf, dmarc=dmarc, domain_age_days_value=age, lookalike=lookalike,
#     # )
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

#     # return CheckResponse(
#     #     email=str(email),
#     #     domain=domain,
#     #     valid_format=True,
#     #     disposable=disposable,
#     #     free_provider=free_provider,
#     #     mx_valid=mx_valid,
#     #     spf=spf,
#     #     dmarc=dmarc,
#     #     domain_age_days=age,
#     #     lookalike=lookalike,
#     #     risk_score=risk["risk_score"],
#     #     risk_level=risk["risk_level"],
#     #     verdict=risk["verdict"],
#     #     signals=risk["signals"],
#     #     score_breakdown=risk["score_breakdown"],

#     #     data_quality={
#     #         "dns": "available" if any(
#     #             value is not None
#     #             for value in [mx_valid, spf, dmarc]
#     #         ) else "unavailable",

#     #         "rdap": (
#     #             "available"
#     #             if domain_age_days is not None
#     #             else "unavailable"
#     #         )
#     #     }

#     # )


def parse_email(email: str) -> tuple[str, str]:
    try:
        result = validate_email(email, check_deliverability=False)
        return result.normalized, normalize_domain(result.domain)
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc

# def create_dns_resolver():
#     resolver = dns.resolver.Resolver()

#     resolver.nameservers = [
#         server.strip()
#         for server in settings.dns_servers.split(",")
#         if server.strip()
#     ]

#     resolver.timeout = settings.dns_timeout_seconds
#     resolver.lifetime = settings.dns_timeout_seconds

#     return resolver
def create_dns_resolver():
    # Use Docker/system resolver.
    # Docker provides 127.0.0.11, which successfully resolves DNS
    # inside this container.
    resolver = dns.resolver.Resolver(configure=True)

    resolver.timeout = settings.dns_timeout_seconds
    resolver.lifetime = settings.dns_timeout_seconds

    return resolver

def load_disposable_domains() -> set[str]:
    domains = set(STARTER_DISPOSABLE_DOMAINS)
    if DISPOSABLE_FILE.exists():
        for line in DISPOSABLE_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            line = line.lstrip("@*.")
            domains.add(normalize_domain(line))
    return domains


def is_disposable(domain: str) -> bool:
    domain = normalize_domain(domain)
    domains = load_disposable_domains()
    if domain in domains:
        return True
    parts = domain.split(".")
    return any(".".join(parts[i:]) in domains for i in range(1, len(parts) - 1))


# def check_mx(domain: str) -> bool:
#     try:
#         answers = dns.resolver.resolve(domain, "MX", lifetime=3)
#         return len(answers) > 0
#     except Exception:
#         try:
#             dns.resolver.resolve(domain, "A", lifetime=3)
#             return True
#         except Exception:
#             return False

def check_mx(domain: str) -> bool | None:
    try:
        resolver = create_dns_resolver()
        answers = resolver.resolve(domain, "MX")

        return len(answers) > 0

    except dns.resolver.NXDOMAIN:
        logger.info("DNS NXDOMAIN domain=%s", domain)
        
        return False

    except dns.resolver.NoAnswer:
        logger.info("DNS has no MX answer domain=%s", domain)
        return False

    except dns.resolver.Timeout:
        logger.error(
            "DNS TIMEOUT domain=%s nameservers=%s",
            domain,
            settings.dns_servers,
        )
        return None

    except dns.resolver.NoNameservers:
        logger.error(
            "DNS NO NAMESERVERS domain=%s nameservers=%s",
            domain,
            settings.dns_servers,
        )
        return None

    except Exception:
        logger.exception(
            "Unexpected DNS error domain=%s",
            domain
        )
        return None

# def check_txt(domain: str, record_name: str | None = None) -> bool:
#     target = record_name or domain
#     try:
#         answers = dns.resolver.resolve(target, "TXT", lifetime=3)
#         values = [r.to_text().strip('"') for r in answers]
#         if record_name:
#             return len(values) > 0
#         return any(v.lower().startswith("v=spf1") for v in values)
#     except Exception:
#         return False


# def check_spf(domain: str) -> bool:
#     return check_txt(domain)

def check_spf(domain: str) -> bool | None:
    try:
        resolver = create_dns_resolver()

        answers = resolver.resolve(
            domain,
            "TXT"
        )

        for record in answers:
            value = record.to_text().strip('"')

            if value.lower().startswith("v=spf1"):
                return True

        return False

    except dns.resolver.NXDOMAIN:
        return False

    except dns.resolver.NoAnswer:
        return False

    except (
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ):
        return None

    except Exception:
        return None


# def check_dmarc(domain: str) -> bool:
#     return check_txt(domain, f"_dmarc.{domain}")

def check_dmarc(domain: str) -> bool | None:
    try:
        resolver = create_dns_resolver()

        answers = resolver.resolve(
            f"_dmarc.{domain}",
            "TXT"
        )

        for record in answers:
            value = record.to_text().strip('"')

            if value.lower().startswith("v=dmarc1"):
                return True

        return False

    except dns.resolver.NXDOMAIN:
        return False

    except dns.resolver.NoAnswer:
        return False

    except (
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ):
        return None

    except Exception:
        return None

def rdap_base_for_domain(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()

    try:
        response = requests.get(
            RDAP_BOOTSTRAP_URL,
            timeout=3
        )

        response.raise_for_status()

        data = response.json()

        for service in data.get("services", []):
            tlds, urls = service

            if tld in [str(x).lower() for x in tlds]:
                return str(urls[0]).rstrip("/")

        return None

    except requests.Timeout:
        logger.warning(
            "RDAP bootstrap timeout domain=%s",
            domain
        )
        return None

    except requests.RequestException:
        logger.exception(
            "RDAP bootstrap request failed domain=%s",
            domain
        )
        return None

    except Exception:
        logger.exception(
            "Unexpected RDAP bootstrap error domain=%s",
            domain
        )
        return None

def get_domain_registration_date(domain: str) -> tuple[datetime | None, str | None]:
    """Return (registration_datetime, rdap_base_url) using IANA bootstrap discovery."""
    base = rdap_base_for_domain(domain)
    if not base:
        return None, None
    try:
        url = f"{base}/domain/{domain}"
        response = httpx.get(url, timeout=7, headers={"Accept": "application/rdap+json, application/json"})
        if response.status_code != 200:
            return None, base
        data: dict[str, Any] = response.json()
        for event in data.get("events", []):
            if str(event.get("eventAction", "")).lower() == "registration":
                value = event.get("eventDate")
                if value:
                    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    return parsed.astimezone(timezone.utc), base
        return None, base
    except Exception:
        return None, base


def domain_age_days(domain: str) -> int | None:
    registered_at, _ = get_domain_registration_date(domain)
    if not registered_at:
        return None
    return max(0, (datetime.now(timezone.utc) - registered_at).days)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def suspicious_lookalike(domain: str) -> bool:
    domain = normalize_domain(domain)
    if domain in PROTECTED_BRANDS:
        return False
    if domain.startswith("xn--"):
        return True
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    root = ".".join(labels[-2:])
    substitutions = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
    normalized = root.translate(substitutions)
    for brand in PROTECTED_BRANDS:
        brand_root = brand
        distance = levenshtein(normalized, brand_root)
        threshold = 1 if len(brand_root) <= 8 else 2
        if distance <= threshold and normalized != brand_root:
            return True
    return False

# def calculate_risk(*, disposable: bool, free_provider: bool, mx_valid: bool, spf: bool,
#                    dmarc: bool, domain_age_days_value: int | None, lookalike: bool) -> tuple[int, str, str, list[str]]:
#     score = 0
#     signals: list[str] = []
#     if disposable:
#         score += 60; signals.append("disposable_domain")
#     if domain_age_days_value is not None and domain_age_days_value < 7:
#         score += 25; signals.append("domain_under_7_days_old")
#     elif domain_age_days_value is not None and domain_age_days_value < 30:
#         score += 10; signals.append("domain_under_30_days_old")
#     if not mx_valid:
#         score += 30; signals.append("no_mx_or_a_record")
#     if free_provider:
#         score += 5; signals.append("free_email_provider")
#     if lookalike:
#         score += 35; signals.append("possible_lookalike_domain")
#     if not spf:
#         score += 3; signals.append("no_spf")
#     if not dmarc:
#         score += 2; signals.append("no_dmarc")
#     score = min(score, 100)
#     if score >= 80:
#         return score, "very_high", "block", signals
#     if score >= 60:
#         return score, "high", "block", signals
#     if score >= 30:
#         return score, "medium", "review", signals
#     return score, "low", "allow", signals


def generate_api_key(prefix: str) -> tuple[str, str]:
    raw = prefix + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()
