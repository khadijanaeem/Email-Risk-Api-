from datetime import datetime, timezone
from sqlalchemy import Index, String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

def now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), default="Default")
    monthly_limit: Mapped[int] = mapped_column(Integer, default=1000)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Usage(Base):
    __tablename__ = "usage"
    id: Mapped[int] = mapped_column(primary_key=True)
    api_key_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"), index=True, nullable=False)
    period: Mapped[str] = mapped_column(String(7), index=True)
    request_count: Mapped[int] = mapped_column(Integer, default=0)

class DomainCache(Base):
    __tablename__ = "domain_cache"
    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    domain_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mx_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    spf: Mapped[bool] = mapped_column(Boolean, default=True)
    dmarc: Mapped[bool] = mapped_column(Boolean, default=True)
    disposable: Mapped[bool] = mapped_column(Boolean, default=False,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
