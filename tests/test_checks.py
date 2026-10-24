from datetime import datetime, timezone

import pytest

from netsentry.checks import CertificateResult, check_certificate


@pytest.mark.parametrize("host,port,timeout", [("", 443, 5), ("example.com", 0, 5), ("a", 443, 0)])
def test_rejects_invalid_parameters(host, port, timeout):
    with pytest.raises(ValueError):
        check_certificate(host, port, timeout)


def test_certificate_result_shape():
    result = CertificateResult("example.com", 443, "CN=example.com", "CN=Issuer",
                               datetime.now(timezone.utc), 30)
    assert result.host == "example.com"
    assert result.days_remaining == 30
