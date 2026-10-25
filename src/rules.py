"""Blocking rules derived from what the clusters / Isolation Forest / surrogate tree showed.

Evidence (see README): bots separate from real traffic on request rate, share of errors, and
absence of static assets. Real sessions with >=20 requests and no CSS/images are rare (8 of ~3,000)
and mostly self-declared crawlers.
"""
import pandas as pd

RULES = {
    "R1_fast_no_assets": "req_per_min >= 30 AND n_requests >= 30 AND no CSS AND no image",
    "R2_error_storm": "n_requests >= 15 AND error share (4xx/5xx) >= 0.8",
    "R3_anonymous_bulk": "empty/missing User-Agent AND n_requests >= 20 AND no CSS AND no image",
}


def apply_rules(f):
    no_assets = (f.has_css == 0) & (f.has_image == 0)
    r = pd.DataFrame(index=f.index)
    r["R1_fast_no_assets"] = (f.req_per_min >= 30) & (f.n_requests >= 30) & no_assets
    r["R2_error_storm"] = (f.n_requests >= 15) & (f.err_share >= 0.8)
    r["R3_anonymous_bulk"] = f.ua.isin(["-", ""]) & (f.n_requests >= 20) & no_assets
    r["ANY_RULE"] = r.any(axis=1)
    return r
