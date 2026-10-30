# AI-SOC: AI-Powered URL Threat Detection (Minor Project)

Detect suspicious URLs **before** the user opens them, explain *why*, and keep a scan history.
This is Phase 1 of the AI-SOC roadmap; the full platform vision is in [`docs/VISION.md`](docs/VISION.md).

## Status

| Area | State |
|---|---|
| URL detection (blocklist + whitelist + ML + rules, with reasons) | Implemented |
| REST API (`/api/v1/scan`, `/history`, `/stats`, `/health`) | Implemented |
| SQLite storage, de-duplicated history, correct counters | Implemented |
| Dashboard (scan, result with reasons, stats, history) | Implemented (plain HTML/JS) |
| Tests (`pytest`) | Implemented |
| Phishing email NLP, malware/file scan, log anomaly detection | Planned (Phase 2-3) |
| Auth / RBAC / multi-tenancy, correlation, MITRE, RAG | Planned (Phase 3-4) |

## How a URL is judged

```
URL -> normalize/validate
    -> 1. Blocklist hit?   -> CRITICAL 100 (known-bad is decided by threat intel, not by the model)
    -> 2. ML + rules       -> score = 0.65 * model probability + 0.35 * rule score
    -> 3. Trusted domain?  -> score capped at 12 (never fully ignored)
    -> score, severity, verdict, confidence, reasons[]
```

| Score | Severity | Verdict |
|---|---|---|
| 0-30 | LOW | Safe |
| 31-60 | MEDIUM | Suspicious |
| 61-85 | HIGH | Malicious |
| 86-100 | CRITICAL | Malicious |

*Confidence* = how far the score is from the 50/50 point (a score of 5 or 95 is 95% confident, 50 is 50%).

## Run it

```bash
python -m venv venv && venv\Scripts\activate      # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python scripts/train_models.py                    # creates ai/models/url_model.pkl
uvicorn backend.main:app --reload                 # open http://localhost:8000
pytest                                            # 35 tests
```

API docs are auto-generated at `http://localhost:8000/docs`.

## What was fixed from the first version

| Problem seen in the first dashboard | Fix |
|---|---|
| `malware.wicar.org` scored 10/100 LOW | Threat-intel blocklist checked before the model (`data/threat_intelligence/blocklist.csv`) |
| Every URL scored exactly 10 or 90 | Real probability from `predict_proba` blended with a rule score |
| "Risk Score" card shown twice | Replaced by *Detected by* (blocklist / ML / whitelist) |
| Confidence 81% next to LOW, unclear meaning | Defined and computed from the score (see above) |
| No explanation for the result | `reasons[]` for every scan |
| Same URL stored 3-4 times | One row per unique URL, `scan_count` increments |
| Missing ID `#4` | IDs are assigned only on successful insert; invalid URLs return 422 and are not stored |
| Stats: 18 + 3 + 3 != 21 | Safe/Suspicious/Malicious are exclusive and come from one `GROUP BY` query |
| Keyword-only flags (`login`, `verify`) | Whitelist + "hard negative" legit login pages in training data |

## Training on real data (do this before your viva)

The model shipped here is trained on **synthetic URLs** so the project runs offline. Its metrics
(F1 ~ 0.998) are **optimistic** and must not be presented as real-world accuracy. Download a phishing
feed (PhishTank / OpenPhish / URLhaus) and a legitimate list (Tranco top sites) as CSVs with a `url`
(or `domain`) column and run:

```bash
python scripts/train_models.py --phishing-csv phishtank.csv --legit-csv tranco.csv --limit 50000
```

This overwrites `ai/models/url_model.pkl` and writes real Precision / Recall / F1 / ROC-AUC / False-Positive-Rate
to `ai/models/model_config.json` for your report. Add real feed entries to `data/threat_intelligence/blocklist.csv`
(`indicator,type,source,category`; `type` is `host` or `url`) and trusted sites to `whitelist.csv`.

## Known limitations

* The detector only sees the URL text. A clean-looking URL on a malicious domain (e.g. a new domain with a normal name) can score LOW. Domain age (WHOIS), DNS, SSL and page content are the next features to add.
* A whitelisted domain is not proof every page on it is safe (open redirects, hosted user content).
* No authentication or rate limiting yet; run it locally or behind a trusted network.
* Only `GET`/`POST` from the listed `CORS_ORIGINS` are allowed; add your Chrome-extension origin there later.

## Project layout

```
ai/url_detection/    features.py, dataset.py, predictor.py
ai/risk_engine/      scoring.py (score -> severity/verdict/confidence)
ai/models/           url_model.pkl, model_config.json (created by training)
threat_intelligence/ feeds/feed_manager.py (blocklist + whitelist)
backend/             main.py, api/, services/, database/
frontend/            index.html, style.css, app.js
data/threat_intelligence/  blocklist.csv, whitelist.csv
scripts/train_models.py
tests/               test_url_detection.py, test_api.py
docs/VISION.md       full AI-SOC vision / roadmap
```

## Responsible use

For defensive security, education and authorised testing only. The scanner never opens or executes the scanned URL.
