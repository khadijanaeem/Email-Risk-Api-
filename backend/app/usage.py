from datetime import datetime,timezone
from .models import  Usage


def increment_usage(db, api_key,amount=1):
    period = datetime.now(timezone.utc).strftime("%Y-%m")

    usage = (
        db.query(Usage)
        .filter(
            Usage.api_key_id == api_key.id,
            Usage.period == period
        )
        .first()
    )

    if usage is None:
        usage = Usage(
            api_key_id=api_key.id,
            period=period,
            request_count=0
        )

        db.add(usage)

    usage.request_count += amount

    api_key.last_used_at = datetime.now(timezone.utc)

    db.flush()

    return usage
