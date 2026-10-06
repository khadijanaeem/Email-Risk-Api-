from app.services import calculate_risk

def test_clean_email():
    result = calculate_risk(
        disposable=False,
        free_provider=False,
        mx_valid=True,
        spf=True,
        dmarc=True,
        domain_age_days=1000,
        lookalike=False,
    )

    assert result["risk_score"] == 0
    assert result["verdict"] == "allow"


def test_disposable_email():
    result = calculate_risk(
        disposable=True,
        free_provider=False,
        mx_valid=True,
        spf=True,
        dmarc=True,
        domain_age_days=1000,
        lookalike=False,
    )

    assert result["risk_score"] == 60
    assert result["verdict"] == "block"


def test_missing_mx():
    result = calculate_risk(
        disposable=False,
        free_provider=False,
        mx_valid=False,
        spf=True,
        dmarc=True,
        domain_age_days=1000,
        lookalike=False,
    )

    assert result["risk_score"] == 30
    assert result["verdict"] == "review"


def test_dns_failure_does_not_add_risk():
    result = calculate_risk(
        disposable=False,
        free_provider=False,
        mx_valid=None,
        spf=None,
        dmarc=None,
        domain_age_days=1000,
        lookalike=False,
    )

    assert result["risk_score"] == 0
    assert result["verdict"] == "allow"