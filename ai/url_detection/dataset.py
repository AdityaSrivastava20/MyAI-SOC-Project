"""Training-data helpers.

IMPORTANT: ``generate_synthetic`` builds *synthetic* URLs from common
phishing/legitimate patterns so the project runs end-to-end offline. Metrics
measured on it are optimistic. For the report/viva, train on real data:

    python scripts/train_models.py --phishing-csv phishtank.csv --legit-csv tranco.csv

(see README -> "Training on real data").
"""
from __future__ import annotations

import random
import string

import pandas as pd

from .features import BRANDS, BRAND_DOMAINS, RISKY_TLDS, SUSPICIOUS_KEYWORDS

WORDS = (
    "alpha beta cloud data eagle falcon garden harbor island jungle kernel lemon "
    "mango nectar ocean pixel quartz river stone tiger urban velvet willow yellow "
    "zephyr bright coral delta ember frost grove haven ivory jade karma lunar "
    "maple noble opal prime quest raven solar topaz unity vivid wander xenon "
    "travel news shop store media tech labs studio books food fitness health "
    "academy school city market travel cars homes games music photo video sports"
).split()
GOOD_TLDS = ["com", "com", "com", "org", "net", "io", "in", "co.in", "edu", "co.uk", "dev", "app", "info"]
RISKY = sorted(RISKY_TLDS)
PATH_WORDS = ["about", "products", "blog", "contact", "pricing", "docs", "help", "news", "careers", "store",
              "category", "item", "post", "article", "search", "events", "team", "faq", "download", "gallery"]
KW = [k for k in SUSPICIOUS_KEYWORDS if "-" not in k]
REAL_LEGIT = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "stackoverflow.com", "amazon.com",
    "microsoft.com", "apple.com", "mozilla.org", "python.org", "kaggle.com", "reddit.com", "nytimes.com",
    "bbc.com", "cloudflare.com", "medium.com", "linkedin.com", "paypal.com", "netflix.com", "flipkart.com",
    "paytm.com", "irctc.co.in", "sbi.co.in", "hdfcbank.com", "icicibank.com", "dropbox.com", "zoom.us",
    "adobe.com", "spotify.com", "ebay.com", "openai.com", "anthropic.com", "owasp.org", "npmjs.com",
]
LEGIT_LOGIN_HOSTS = [
    "accounts.google.com", "login.microsoftonline.com", "account.apple.com", "www.paypal.com",
    "secure.hdfcbank.com", "netbanking.hdfcbank.com", "www.amazon.com", "signin.ebay.com",
    "github.com", "login.live.com", "id.zoom.us", "auth.openai.com",
]
SHORTENER_HOSTS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy"]


def _rand(rng: random.Random, n: int, chars: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(rng.choice(chars) for _ in range(n))


def _word_domain(rng: random.Random) -> str:
    return rng.choice(WORDS) + rng.choice(["", "-", ""]) + rng.choice(WORDS)


def _legit_path(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.3:
        return "/"
    if kind < 0.6:
        return "/" + "/".join(rng.sample(PATH_WORDS, rng.randint(1, 3)))
    if kind < 0.8:
        return f"/{rng.choice(PATH_WORDS)}/{rng.choice(WORDS)}-{rng.choice(WORDS)}-{rng.randint(1, 9999)}"
    return f"/{rng.choice(PATH_WORDS)}?q={rng.choice(WORDS)}&page={rng.randint(1, 20)}&sort={rng.choice(['new', 'top'])}"


def _legit_url(rng: random.Random) -> str:
    scheme = "https" if rng.random() < 0.93 else "http"
    roll = rng.random()
    if roll < 0.28:
        host = rng.choice(REAL_LEGIT)
        if rng.random() < 0.4:
            host = rng.choice(["www", "docs", "blog", "support", "mail", "shop"]) + "." + host
    elif roll < 0.36:
        host = rng.choice(LEGIT_LOGIN_HOSTS)
        path = rng.choice(["/", "/signin", "/login", "/v3/signin/identifier", "/account/security"])
        return f"https://{host}{path}"
    elif roll < 0.42:
        host = rng.choice(SHORTENER_HOSTS)
        return f"https://{host}/{_rand(rng, rng.randint(5, 8), string.ascii_letters + string.digits)}"
    else:
        host = _word_domain(rng) + "." + rng.choice(GOOD_TLDS)
        if rng.random() < 0.5:
            host = "www." + host
        if rng.random() < 0.08:
            host = rng.choice(WORDS) + str(rng.randint(1, 99)) + "." + host.split(".", 1)[-1]
    return f"{scheme}://{host}{_legit_path(rng)}"


def _mutate_brand(rng: random.Random, brand: str) -> str:
    leet = {"o": "0", "l": "1", "e": "3", "a": "4", "i": "1", "s": "5"}
    choice = rng.random()
    chars = list(brand)
    if choice < 0.4:
        idxs = [i for i, c in enumerate(chars) if c in leet]
        if idxs:
            i = rng.choice(idxs)
            chars[i] = leet[chars[i]]
    elif choice < 0.65 and len(chars) > 3:
        i = rng.randrange(len(chars) - 1)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    elif choice < 0.85:
        i = rng.randrange(len(chars))
        chars.insert(i, chars[i])
    elif len(chars) > 4:
        del chars[rng.randrange(len(chars))]
    out = "".join(chars)
    return out if out != brand else out + "s"


def _phish_url(rng: random.Random) -> str:
    brand = rng.choice(BRANDS)
    kw1, kw2 = rng.sample(KW, 2)
    tld = rng.choice(RISKY) if rng.random() < 0.55 else rng.choice(["com", "net", "org", "info", "online", "site"])
    scheme = "http" if rng.random() < 0.6 else "https"
    pattern = rng.randrange(10)

    if pattern == 0:   # keyword stuffed hyphen domain
        host = f"{kw1}-{kw2}-{rng.choice([brand, rng.choice(WORDS)])}.{tld}"
        path = rng.choice(["/", f"/{kw1}", f"/{kw1}/{kw2}.php", f"/{kw2}/index.html"])
    elif pattern == 1:  # brand in subdomain of attacker domain
        host = f"{brand}.{kw1}.{_word_domain(rng)}.{tld}"
        path = f"/{kw2}"
    elif pattern == 2:  # raw IP
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4)) + rng.choice(["", ":8080", ":8443", ""])
        path = rng.choice([f"/{kw1}/index.php", f"/{brand}/{kw2}.html", "/login.php"])
        scheme = "http"
    elif pattern == 3:  # typosquat
        host = f"{_mutate_brand(rng, brand)}.{rng.choice(['com', 'net', tld])}"
        if rng.random() < 0.5:
            host = f"www.{host}"
        path = rng.choice(["/", f"/{kw1}", f"/{kw1}.php", f"/{kw2}/{kw1}"])
    elif pattern == 4:  # userinfo '@' trick
        host = f"{brand}.com@{_word_domain(rng)}.{tld}"
        path = f"/{kw1}/{_rand(rng, 6)}"
    elif pattern == 5:  # random / DGA-like domain
        host = f"{_rand(rng, rng.randint(9, 18))}.{tld}"
        path = rng.choice(["/", f"/{_rand(rng, 8)}.php", f"/{_rand(rng, 5)}/{_rand(rng, 7)}"])
    elif pattern == 6:  # long URL with token noise
        host = f"{_word_domain(rng)}.{tld}"
        path = f"/{kw1}/{kw2}/{_rand(rng, 40)}?id={_rand(rng, 24)}&session={_rand(rng, 32)}&redirect={brand}"
    elif pattern == 7:  # punycode / homograph
        host = f"xn--{_rand(rng, rng.randint(6, 12), string.ascii_lowercase)}-{_rand(rng, 4, string.ascii_lowercase)}.{rng.choice(['com', tld])}"
        path = f"/{kw1}"
    elif pattern == 8:  # compromised site hosting a brand kit
        host = f"{rng.choice(WORDS)}{rng.randint(10, 9999)}.{rng.choice(['com', 'in', 'net', tld])}"
        path = f"/wp-content/{brand}/{kw1}/{kw2}.php"
    else:               # deep subdomain chain
        host = ".".join([brand, kw1, rng.choice(WORDS), _rand(rng, 6), tld])
        path = f"/{kw2}"
    return f"{scheme}://{host}{path}"


def generate_synthetic(n_per_class: int = 6000, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = [(_legit_url(rng), 0) for _ in range(n_per_class)]
    rows += [(_phish_url(rng), 1) for _ in range(n_per_class)]
    rng.shuffle(rows)
    return pd.DataFrame(rows, columns=["url", "label"]).drop_duplicates("url").reset_index(drop=True)


def load_real_csvs(phishing_csv: str, legit_csv: str, limit: int | None = None) -> pd.DataFrame:
    """Load real datasets. Each CSV needs a column named 'url' (a 'domain' column also works for Tranco-style lists)."""
    frames = []
    for path, label in ((phishing_csv, 1), (legit_csv, 0)):
        df = pd.read_csv(path)
        col = "url" if "url" in df.columns else ("domain" if "domain" in df.columns else df.columns[-1])
        s = df[col].astype(str).str.strip()
        s = s.where(s.str.contains("://"), "http://" + s)
        frame = pd.DataFrame({"url": s, "label": label}).dropna()
        if limit:
            frame = frame.sample(min(limit, len(frame)), random_state=42)
        frames.append(frame)
    return pd.concat(frames, ignore_index=True).drop_duplicates("url")
