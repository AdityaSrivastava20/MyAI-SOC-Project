def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["detector_mode"] == "hybrid"


def test_scan_returns_full_result(client):
    r = client.post("/api/v1/scan", json={"url": "http://malware.wicar.org/"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "Malicious" and body["severity"] == "CRITICAL" and body["score"] == 100
    assert body["reasons"] and body["source"] == "blocklist"


def test_repeat_scan_does_not_create_duplicate_rows(client):
    for _ in range(3):
        client.post("/api/v1/scan", json={"url": "https://google.com"})
    client.post("/api/v1/scan", json={"url": "HTTPS://Google.com"})  # same URL after normalisation
    history = client.get("/api/v1/history").json()
    assert history["total"] == 1
    assert history["items"][0]["scan_count"] == 4


def test_stats_categories_add_up(client):
    for u in ["https://google.com", "https://google.com", "http://login-verify-account.com",
              "http://malware.wicar.org/", "https://hackthebox.com", "http://bit.ly/abc123"]:
        client.post("/api/v1/scan", json={"url": u})
    s = client.get("/api/v1/stats").json()
    assert s["total_scans"] == 6
    assert s["unique_urls"] == 5
    assert sum(s["verdicts"].values()) == s["unique_urls"]  # no double counting
    assert sum(s["severities"].values()) == s["unique_urls"]


def test_ids_are_sequential_without_gaps(client):
    for u in ["https://google.com", "https://hackthebox.com", "http://login-verify-account.com"]:
        client.post("/api/v1/scan", json={"url": u})
    ids = sorted(i["id"] for i in client.get("/api/v1/history").json()["items"])
    assert ids == [1, 2, 3]


def test_invalid_url_returns_422_and_is_not_stored(client):
    r = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
    assert r.status_code == 422
    assert client.get("/api/v1/history").json()["total"] == 0


def test_history_filter(client):
    client.post("/api/v1/scan", json={"url": "https://google.com"})
    client.post("/api/v1/scan", json={"url": "http://malware.wicar.org/"})
    items = client.get("/api/v1/history", params={"verdict": "Malicious"}).json()["items"]
    assert len(items) == 1 and items[0]["verdict"] == "Malicious"
    assert client.get("/api/v1/history", params={"verdict": "Nope"}).status_code == 422


def test_dashboard_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "AI-SOC" in r.text
