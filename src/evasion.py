"""Simulate SMARTER (evasive) login brute-forcers and measure what evasion costs the attacker.
All traffic here is synthetic.
"""
import math
import numpy as np
import pandas as pd
from features import sessionize, build_features, model_matrix
from rules import apply_rules

CHROME = ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/32.0.1700.107 Safari/537.36")
PYUA = "python-requests/2.2.1 CPython/2.7.6"
BENIGN = ["/", "/blog/", "/about/", "/archive/", "/projects/"]

# name: dict(mean delay between requests, mimic browser, benign padding per attempt, burst size, sleep)
CONFIGS = {
    "E0 baseline (1 s, python UA)":          dict(delay=1.0, mimic=False, pad=0, burst=None, attempts=200),
    "E1 + browser UA & fetch CSS/img":        dict(delay=1.0, mimic=True,  pad=0, burst=None, attempts=200),
    "E2 + slow, jittered (mean 5 s)":         dict(delay=5.0, mimic=True,  pad=0, burst=None, attempts=200),
    "E3 + slower (mean 30 s)":                dict(delay=30.0, mimic=True, pad=0, burst=None, attempts=200),
    "E4 + pad 3 benign GETs per guess (8 s)": dict(delay=8.0, mimic=True,  pad=3, burst=None, attempts=100),
    "E5 burst of 10, sleep 31 min":           dict(delay=2.0, mimic=True,  pad=0, burst=10, attempts=40),
    "E6 burst of 6 + 2 benign GETs each, sleep 31 min": dict(delay=3.0, mimic=True, pad=2, burst=6, attempts=24),
}


def _simulate_one(cfg, ip, start, rng):
    rows, t = [], start
    ua = CHROME if cfg["mimic"] else PYUA

    def add(method, url, status, size=300):
        rows.append((ip, t, method, url, status, size, "-", ua))

    def step():
        return pd.Timedelta(seconds=float(rng.exponential(cfg["delay"])) + 0.05)

    def preamble():
        nonlocal t
        if cfg["mimic"]:
            add("GET", "/login", 200, 2000); t += step()
            add("GET", "/static/site.css", 200, 5000); t += step()
            add("GET", "/static/logo.png", 200, 9000); t += step()

    if cfg["burst"] is None:
        preamble()
        for _ in range(cfg["attempts"]):
            add("POST", "/login", 401); t += step()
            for _ in range(cfg["pad"]):
                add("GET", str(rng.choice(BENIGN)), 200, 4000); t += step()
    else:
        for _ in range(cfg["attempts"] // cfg["burst"]):
            preamble()
            for _ in range(cfg["burst"]):
                add("POST", "/login", 401); t += step()
                for _ in range(cfg["pad"]):
                    add("GET", str(rng.choice(BENIGN)), 200, 4000); t += step()
            t += pd.Timedelta(minutes=31)
    return rows


def evaluate_evasion(t0, scaler, iforest, n_bots=20, seed=1, guesses_target=10_000):
    rng = np.random.default_rng(seed)
    out = []
    for name, cfg in CONFIGS.items():
        rows = []
        for i in range(n_bots):
            ip = f"192.0.2.{i + 1}"  # RFC 5737 TEST-NET-1
            rows += _simulate_one(cfg, ip, t0 + pd.Timedelta(minutes=int(rng.integers(0, 600))), rng)
        d = pd.DataFrame(rows, columns=["ip", "timestamp", "method", "url", "status", "bytes", "referrer", "user_agent"])
        f = build_features(sessionize(d))
        r = apply_rules(f)
        f["rule"] = r.ANY_RULE.values
        f["iforest"] = iforest.predict(scaler.transform(model_matrix(f))) == -1
        by_ip = f.groupby("ip")[["rule", "iforest"]].any()
        span_h = d.groupby("ip").timestamp.agg(lambda s: (s.max() - s.min()).total_seconds() / 3600).mean()
        attempts = (d.method == "POST").groupby(d.ip).sum().mean()
        per_hour = attempts / span_h
        out.append({
            "evasion level": name,
            "caught by rules (IPs)": f"{int(by_ip.rule.sum())}/{n_bots}",
            "caught by IForest (IPs)": f"{int(by_ip.iforest.sum())}/{n_bots}",
            "guesses/hour/IP": round(per_hour, 1),
            "days for 10k guesses (1 IP)": round(guesses_target / per_hour / 24, 1),
            "IPs needed for 10k in 24 h": math.ceil(guesses_target / (per_hour * 24)),
        })
    return pd.DataFrame(out)
