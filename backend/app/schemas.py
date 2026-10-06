from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional,Any

class CheckRequest(BaseModel):
    email: EmailStr


class CheckResponse(BaseModel):
    email: str = Field(
        description="The normalized email address that was checked."
    )

    domain: str = Field(
        description="The domain extracted from the email address."
    )

    valid_format: bool = Field(
        description="Whether the email has a valid email format."
    )

    disposable: bool = Field(
        description="Whether the domain is known to provide disposable/temporary email addresses."
    )

    free_provider: bool = Field(
        description="Whether the email uses a common free email provider such as Gmail or Outlook."
    )

    mx_valid: bool | None = Field(
        default=None,
        description="Whether the domain has a valid MX record. Null means the DNS check could not be completed."
    )

    spf: bool | None = Field(
        default=None,
        description="Whether an SPF record exists."
    )

    dmarc: bool | None = Field(
        default=None,
        description="Whether a DMARC record exists."
    )

    domain_age_days: Optional[int] = Field(
        default=None,
        description="Approximate number of days since the domain was registered. Null when registration data is unavailable."
    )

    lookalike: bool = Field(
        description="Whether the domain resembles a protected brand/domain."
    )

    risk_score: int = Field(
        ge=0,
        le=100,
        description="Risk score from 0 to 100. Higher means greater signup-abuse risk."
    )

    risk_level: str = Field(
        description="Risk category: low, medium, high, or very_high."
    )

    verdict: str = Field(
        description="Recommended automated action: allow, review, or block."
    )

    signals: List[str] = Field(
        default_factory=list,
        description="Risk signals detected during analysis."
    )

    score_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Risk points contributed by each detected signal."
    )

    data_quality: dict[str, str] = Field(
        default_factory=dict,
        description="Availability of external DNS and RDAP checks."
    )

class CreateKeyRequest(BaseModel):
    email: EmailStr
    name: str = Field(default="Default", max_length=100)

class CreateKeyResponse(BaseModel):
    api_key: str
    warning: str

class BulkCheckRequest(BaseModel):
    emails: list[EmailStr]

class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None = None

class ErrorResponse(BaseModel):
    error: ErrorDetail