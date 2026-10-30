import pytest

from ai.url_detection.features import InvalidURLError, extract_features, normalize_url
from ai.risk_engine.scoring import severity_from_score, verdict_from_severity


def test_known_malware_test_site_is_blocked(predictor):
    """Regression: malware.wicar.org was scored 10/100 'Safe' in the first version."""
    r = predictor.predict("http://malware.wicar.org/")
    assert r["score"] == 100
    assert r["severity"] == "CRITICAL"
    assert r["verdict"] == "Malicious"
    assert r["source"] == "blocklist"


def test_blocklist_matches_subdomains_of_listed_host(predictor):
    assert predictor.predict("http://a.b.malware.wicar.org/x")["verdict"] == "Malicious"


@pytest.mark.parametrize("url", ["https://google.com", "https://www.saucedemo.com/", "https://hackthebox.com",
                                 "https://accounts.google.com/signin", "https://login.microsoftonline.com/"])
def test_trusted_sites_are_safe(predictor, url):
    r = predictor.predict(url)
    assert r["verdict"] == "Safe" and r["score"] <= 12


@pytest.mark.parametrize("url", [
    "http://login-verify-account.com",
    "http://secure-login-example.xyz/verify/account",
    "http://paypa1-secure.xyz/login",
    "http://192.168.4.7:8080/login.php",
    "https://paypal.com.evil-site.top/webscr",
    "https://paypal.com@collect-data.top/verify",
])
def test_phishing_patterns_are_flagged(predictor, url):
    r = predictor.predict(url)
    assert r["severity"] in ("HIGH", "CRITICAL"), r
    assert r["verdict"] == "Malicious"
    assert r["reasons"], "every flagged URL must explain why"


def test_typosquat_is_explained(predictor):
    r = predictor.predict("https://www.paypa1.com/signin")
    assert r["verdict"] != "Safe"
    assert any("paypal" in reason for reason in r["reasons"])


def test_scores_are_not_just_two_fixed_values(predictor):
    urls = ["https://google.com", "http://login-verify-account.com", "https://mycompany-docs.com/about",
            "http://bit.ly/abc123", "http://example-shop.top/login", "https://netmirror.center/"]
    assert len({predictor.predict(u)["score"] for u in urls}) >= 4


def test_score_and_confidence_in_range(predictor):
    for u in ["https://google.com", "http://login-verify-account.com", "http://malware.wicar.org"]:
        r = predictor.predict(u)
        assert 0 <= r["score"] <= 100
        assert 50 <= r["confidence"] <= 100


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "javascript:alert(1)", "http://", "http://exa mple.com",
                                 "http://localhost:99999", "a" * 3000])
def test_invalid_input_is_rejected(bad):
    with pytest.raises(InvalidURLError):
        normalize_url(bad)


def test_scheme_is_added_when_missing():
    assert normalize_url("Example.COM/Path") == "http://example.com/Path"


def test_feature_vector_is_complete_and_numeric():
    feats = extract_features(normalize_url("https://sub.example.com/a/b?x=1"))
    assert all(isinstance(v, float) for v in feats.values())


def test_severity_bands_and_verdicts():
    assert severity_from_score(0) == "LOW" and severity_from_score(30) == "LOW"
    assert severity_from_score(31) == "MEDIUM" and severity_from_score(60) == "MEDIUM"
    assert severity_from_score(61) == "HIGH" and severity_from_score(85) == "HIGH"
    assert severity_from_score(86) == "CRITICAL" and severity_from_score(100) == "CRITICAL"
    assert [verdict_from_severity(s) for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")] == ["Safe", "Suspicious", "Malicious", "Malicious"]
