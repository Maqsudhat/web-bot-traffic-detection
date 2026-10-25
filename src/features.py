"""Sessionisation (per IP, 30-min inactivity gap) and per-session features."""
import numpy as np
import pandas as pd

SESSION_GAP = pd.Timedelta(minutes=30)
IMG_RE = r"\.(?:png|jpe?g|gif|ico|svg|webp)(?:\?|$)"
CSS_RE = r"\.css(?:\?|$)"
BROWSER_TOKENS = r"(?:Chrome|Firefox|Safari|MSIE|Trident|Opera|Edge)"
NOT_BROWSER = r"(?i)(?:bot|crawl|spider|slurp|feed|fetch|scan|curl|wget|python|java|http-?client|monitor|check|apt-http|urlgrabber|reader|rss)"
DECLARED_BOT = r"(?i)(?:bot|crawl|spider|slurp|feed|fetch|reader|rss|monitor|check|uptime|python|curl|wget|java)"


def sessionize(df, gap=SESSION_GAP):
    df = df.sort_values(["ip", "timestamp"], kind="stable").reset_index(drop=True)
    new = (df.ip != df.ip.shift()) | (df.timestamp.diff() > gap)
    df["session_id"] = new.cumsum() - 1
    return df


def looks_like_browser(ua):
    return bool(ua and ua.startswith("Mozilla/") and
                pd.Series([ua]).str.contains(BROWSER_TOKENS).iloc[0] and
                not pd.Series([ua]).str.contains(NOT_BROWSER).iloc[0])


def build_features(df, labels=None):
    """df: parsed log with session_id. labels: DataFrame(ip, bot_type) or None."""
    df = df.copy()
    df["is_err"] = (df.status >= 400).astype(int)
    df["is_img"] = df.url.str.contains(IMG_RE, regex=True, case=False)
    df["is_css"] = df.url.str.contains(CSS_RE, regex=True, case=False)
    df["gap"] = df.groupby("session_id").timestamp.diff().dt.total_seconds()

    g = df.groupby("session_id")
    f = pd.DataFrame({
        "ip": g.ip.first(),
        "start": g.timestamp.min(),
        "n_requests": g.size(),
        "duration_s": (g.timestamp.max() - g.timestamp.min()).dt.total_seconds(),
        "distinct_urls": g.url.nunique(),
        "err_share": g.is_err.mean(),
        "mean_gap": g.gap.mean(),
        "var_gap": g.gap.var(ddof=0),
        "has_image": g.is_img.any().astype(int),
        "has_css": g.is_css.any().astype(int),
        "top_url_share": g.url.agg(lambda s: s.value_counts(normalize=True).iloc[0]),
        "ua": g.user_agent.agg(lambda s: s.mode().iloc[0]),
    })
    # requests/min: duration floored at 1 minute so 1-2 request sessions aren't "infinitely fast"
    f["req_per_min"] = f.n_requests / np.maximum(f.duration_s / 60.0, 1.0)
    # single-request sessions have no gaps: treat as idle (= the session timeout), variance 0
    f["mean_gap"] = f.mean_gap.fillna(SESSION_GAP.total_seconds())
    f["var_gap"] = f.var_gap.fillna(0.0)
    f["ua_browser"] = f.ua.map(looks_like_browser).astype(int)
    f["declared_bot_ua"] = f.ua.str.contains(DECLARED_BOT, regex=True).astype(int)  # diagnostics only, not a model input

    if labels is not None:
        m = labels.set_index("ip").bot_type
        f["bot_type"] = f.ip.map(m).fillna("human_or_real")
        f["is_injected"] = (f.bot_type != "human_or_real").astype(int)
    return f.reset_index()


# model inputs
FEATURES = ["req_per_min", "n_requests", "distinct_urls", "err_share", "mean_gap",
            "var_gap", "top_url_share", "ua_browser", "has_image", "has_css"]
LOG_COLS = ["req_per_min", "n_requests", "distinct_urls", "mean_gap", "var_gap"]


def model_matrix(f):
    X = f[FEATURES].astype(float).copy()
    X[LOG_COLS] = np.log1p(X[LOG_COLS])  # heavy-tailed -> log before scaling
    return X
