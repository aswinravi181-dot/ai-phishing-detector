"""
AI Phishing Detector - detection engine (EDUCATIONAL PROTOTYPE).

How it works:
  1. Turn the input (URL or message) into numeric features (length, keywords, ...).
  2. A Logistic Regression model (scikit-learn) is trained on data/dataset.csv.
  3. The model predicts SAFE / SUSPICIOUS / PHISHING with probabilities.
  4. The same features are used to explain the decision in plain English.

Nothing is ever downloaded or opened - the input is analysed as plain text only.
"""
import csv
import os
import re
from urllib.parse import urlparse

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(BASE_DIR, "data", "dataset.csv")

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

SUSPICIOUS_TLDS = {"xyz", "top", "click", "tk", "work", "info", "cc", "live", "ru", "ml", "ga", "cf", "gq", "icu", "buzz"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
TRUSTED = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "amazon.in", "paypal.com", "netflix.com",
    "facebook.com", "instagram.com", "github.com", "python.org", "wikipedia.org", "linkedin.com",
    "bbc.com", "nytimes.com", "stackoverflow.com", "coursera.org", "irs.gov", "hdfcbank.com",
    "onlinesbi.sbi", "microsoftonline.com", "ox.ac.uk", "youtube.com",
}
BRANDS = ["paypal", "amazon", "amaz0n", "google", "microsoft", "apple", "netflix", "facebook",
          "instagram", "hdfc", "sbi", "icici", "dhl", "fedex", "irs"]

URL_WORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password",
             "banking", "wallet", "billing", "suspend", "unlock", "kyc", "otp", "payment"]
URGENT = ["urgent", "immediately", "within 24 hours", "act now", "final notice", "suspended",
          "expire", "limited time", "last warning", "right away", "today only", "avoid"]
CREDENTIAL = ["password", "otp", "pin", "cvv", "card number", "ssn", "credentials", "pan",
              "bank details", "verify your", "confirm your", "login"]
LURE = ["click", "attachment", "voicemail", "shared a document", "delivered", "sign-in", "review your activity",
        "tracking", "selected", "offer", "deal", "work from home", "shop now", "trial"]
MONEY = ["prize", "winner", "lottery", "gift card", "reward", "refund", "free", "claim", "bonus", "cash", "won"]

FEATURES = [
    "url_length", "dots", "hyphens", "has_at", "has_ip", "no_https", "bad_tld", "shortener",
    "url_words", "brand_mismatch", "many_subdomains", "digit_ratio", "punycode", "urgent_words",
    "credential_words", "money_words", "has_link", "exclaims", "caps_ratio", "trusted",
    "lure_words", "clean_message", "untrusted_login", "path_login",
]


def registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "ac", "gov"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def count_hits(text, words):
    return sum(1 for w in words if w in text)


def split_input(text):
    """Return (url_or_None, message_text). A bare URL has no spaces."""
    text = text.strip()
    found = URL_RE.search(text)
    if found and " " not in text:
        return found.group(0), ""
    if " " not in text and "." in text and "/" in text.split(".")[-1] + "/":
        return text, ""
    return (found.group(0) if found else None), text


def extract(text):
    """Return (feature_vector, details) for the input text."""
    url, message = split_input(text)
    f = dict.fromkeys(FEATURES, 0.0)
    d = {"host": "", "domain": "", "is_url": bool(url) and not message}

    if url:
        full = url if re.match(r"https?://", url, re.I) else "http://" + url
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()
        domain = registered_domain(host)
        name = domain.split(".")[0]
        d.update(host=host, domain=domain)
        f["url_length"] = min(len(full), 200) / 50
        f["dots"] = min(host.count("."), 6)
        f["hyphens"] = min(host.count("-"), 6)
        f["has_at"] = 1.0 if "@" in parsed.netloc else 0.0
        f["has_ip"] = 1.0 if IP_RE.match(host) else 0.0
        f["no_https"] = 1.0 if full.lower().startswith("http://") else 0.0
        f["bad_tld"] = 1.0 if host.split(".")[-1] in SUSPICIOUS_TLDS else 0.0
        f["shortener"] = 1.0 if domain in SHORTENERS else 0.0
        f["url_words"] = min(count_hits(full.lower(), URL_WORDS), 4)
        f["brand_mismatch"] = 1.0 if any(b in host and name != b for b in BRANDS) and domain not in TRUSTED else 0.0
        f["many_subdomains"] = 1.0 if host.count(".") >= 3 else 0.0
        f["digit_ratio"] = sum(c.isdigit() for c in host) / max(len(host), 1)
        f["punycode"] = 1.0 if "xn--" in host else 0.0
        f["trusted"] = 1.0 if domain in TRUSTED and not f["has_at"] else 0.0
        f["path_login"] = 1.0 if any(w in parsed.path.lower() for w in URL_WORDS) and not f["trusted"] else 0.0
        f["untrusted_login"] = 1.0 if f["url_words"] >= 1 and not f["trusted"] else 0.0

    if message:
        low = message.lower()
        f["urgent_words"] = min(count_hits(low, URGENT), 4)
        f["credential_words"] = min(count_hits(low, CREDENTIAL), 4)
        f["money_words"] = min(count_hits(low, MONEY), 4)
        f["has_link"] = 1.0 if url else 0.0
        f["exclaims"] = min(message.count("!"), 5)
        f["lure_words"] = min(count_hits(low, LURE), 3)
        f["clean_message"] = 1.0 if not (f["urgent_words"] or f["credential_words"] or f["money_words"]
                                         or f["lure_words"] or f["has_link"] or f["exclaims"]) else 0.0
        letters = [c for c in message if c.isalpha()]
        f["caps_ratio"] = sum(c.isupper() for c in letters) / max(len(letters), 1)
    d["has_message"] = bool(message)
    return np.array([f[k] for k in FEATURES]), f, d


def build_reasons(f, d):
    r = []
    if f["has_ip"]: r.append("URL uses a raw IP address instead of a domain name")
    if f["has_at"]: r.append("URL contains '@', which can hide the real destination")
    if f["punycode"]: r.append("Domain uses punycode (possible look-alike characters)")
    if f["brand_mismatch"]: r.append("Domain imitates a well-known brand but is not the official domain")
    if f["bad_tld"]: r.append("Untrusted domain pattern: high-risk top-level domain (." + d["host"].split(".")[-1] + ")")
    if f["shortener"]: r.append("Shortened link hides the real destination")
    if f["url_words"] >= 1 and not f["trusted"]: r.append("Login/verification-related keywords in the URL")
    if f["hyphens"] >= 2: r.append("Suspicious URL structure: many hyphens in the domain")
    if f["many_subdomains"]: r.append("Suspicious URL structure: unusually many subdomains")
    if f["digit_ratio"] > 0.15: r.append("Domain contains many digits")
    if d["is_url"] and f["no_https"] and not f["trusted"]: r.append("Connection is not encrypted (HTTP instead of HTTPS)")
    if f["url_length"] > 2.4: r.append("Unusually long URL")
    if f["urgent_words"]: r.append("Urgent or threatening language to pressure the reader")
    if f["credential_words"]: r.append("Asks for or mentions sensitive credentials (password, OTP, card, SSN)")
    if f["money_words"]: r.append("Prize / reward / money bait wording")
    if f["lure_words"]: r.append("Contains click-bait / delivery / sign-in lure wording")
    if f["has_link"] and d["has_message"]: r.append("Message contains a link to an external site")
    if f["exclaims"] >= 3 or f["caps_ratio"] > 0.35: r.append("Excessive capital letters or exclamation marks")
    if f["trusted"]: r.append("Domain (" + d["domain"] + ") is on the trusted-domain list")
    return r


def load_dataset():
    X, y = [], []
    with open(DATASET, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            X.append(extract(row["text"])[0])
            y.append(row["label"])
    return np.array(X), np.array(y)


class PhishingDetector:
    def __init__(self):
        X, y = load_dataset()
        self.model = make_pipeline(StandardScaler(), LogisticRegression(C=10, max_iter=2000))
        self.model.fit(X, y)
        self.train_size = len(y)

    def analyze(self, text):
        vec, f, d = extract(text)
        proba = self.model.predict_proba([vec])[0]
        probs = dict(zip(self.model.classes_, proba))
        label = max(probs, key=probs.get)
        risk_score = probs.get("PHISHING", 0) + 0.5 * probs.get("SUSPICIOUS", 0)
        risk = "Low" if risk_score < 0.35 else "Medium" if risk_score < 0.65 else "High"
        reasons = build_reasons(f, d)
        if label != "SAFE" and not reasons:
            reasons.append("Overall pattern resembles known phishing samples")
        if label == "SAFE" and not reasons:
            reasons.append("No common phishing indicators were found")
        advice = {
            "SAFE": "No major threat indicators found. Still stay alert and avoid sharing passwords unless you typed the address yourself.",
            "SUSPICIOUS": "Be careful. Do not click links or download files. Verify the sender through an official website or app.",
            "PHISHING": "Do not open the link or enter personal credentials. Report it to your IT/security team and delete the message.",
        }[label]
        return {
            "label": label, "risk": risk, "confidence": round(float(probs[label]) * 100, 1),
            "reasons": reasons, "recommendation": advice,
            "probabilities": {k: round(float(v) * 100, 1) for k, v in probs.items()},
        }
