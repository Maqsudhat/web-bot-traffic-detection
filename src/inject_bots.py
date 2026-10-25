"""Inject SYNTHETIC bot sessions into a real access log.

Everything produced here is fake. Bot IPs are drawn from the reserved
documentation ranges 203.0.113.0/24 and 198.51.100.0/24 (RFC 5737), so they can
never collide with real clients in the log.

Outputs
  data/access_with_bots.log      real lines + injected lines, same combined format
  data/injected_labels.csv       ip, bot_type  (ground truth for evaluation)
"""
import argparse
import numpy as np
import pandas as pd
from parse_logs import parse_file

STATIC_RE = r"\.(?:css|js|png|jpe?g|gif|ico|svg|woff2?)(?:\?|$)"

SCAN_PATHS = [
    "/wp-login.php", "/wp-admin/", "/administrator/", "/admin/", "/admin.php", "/phpmyadmin/",
    "/pma/", "/.env", "/.git/config", "/config.php", "/backup.zip", "/backup.sql", "/db.sql",
    "/server-status", "/cgi-bin/test.cgi", "/cgi-bin/php", "/xmlrpc.php", "/shell.php",
    "/upload.php", "/manager/html", "/console/", "/login.php", "/user/login", "/etc/passwd",
    "/robots.txt.bak", "/old/", "/test/", "/tmp/", "/.htaccess", "/web.config", "/setup.php",
    "/install/", "/solr/", "/jenkins/", "/api/v1/users", "/api/", "/debug/", "/info.php",
    "/phpinfo.php", "/joomla/", "/drupal/", "/sites/default/files/", "/uploads/", "/files/",
    "/wp-content/plugins/", "/wp-includes/", "/blog/wp-login.php", "/mysql/", "/sql/", "/dump.sql",
    "/.svn/entries", "/id_rsa", "/composer.json", "/package.json", "/Dockerfile", "/.DS_Store",
    "/index.php.bak", "/readme.html", "/license.txt", "/changelog.txt", "/status", "/health",
]
CHROME_UA = ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/32.0.1700.107 Safari/537.36")
BOT_TYPES = ["fast_scraper", "url_scanner", "login_bruteforce", "empty_ua"]


def fmt(ts, ip, method, url, status, size, ref, ua):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def make_bot(kind, ip, start, pages, rng):
    """Return list of (timestamp, method, url, status, bytes, referrer, ua)."""
    reqs = []
    t = start
    if kind == "fast_scraper":
        n = int(rng.integers(150, 400))
        ua = rng.choice(["python-requests/2.2.1 CPython/2.7.6", CHROME_UA])
        urls = rng.choice(pages, size=n, replace=True)
        for u in urls:
            t += pd.Timedelta(seconds=float(rng.uniform(0.1, 0.8)))
            reqs.append((t, "GET", u, 200, int(rng.integers(3000, 30000)), "-", ua))
    elif kind == "url_scanner":
        n = int(rng.integers(40, len(SCAN_PATHS)))
        ua = rng.choice(["-", "curl/7.35.0", "Nikto/2.1.5", "Mozilla/5.0 (compatible; scanner)"])
        for u in rng.choice(SCAN_PATHS, size=n, replace=False):
            t += pd.Timedelta(seconds=float(rng.uniform(0.2, 2.0)))
            st = int(rng.choice([404, 404, 404, 404, 403, 301, 200], p=[.3, .3, .2, .1, .05, .03, .02]))
            reqs.append((t, "GET", u, st, int(rng.integers(150, 600)), "-", ua))
    elif kind == "login_bruteforce":
        n = int(rng.integers(80, 300))
        ua = rng.choice(["python-requests/2.2.1 CPython/2.7.6", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"])
        for _ in range(n):
            t += pd.Timedelta(seconds=float(rng.lognormal(mean=0.0, sigma=0.5)))
            st = 401 if rng.random() < 0.97 else 302
            reqs.append((t, "POST", "/login", st, int(rng.integers(200, 500)), "-", ua))
    elif kind == "empty_ua":
        n = int(rng.integers(30, 120))
        ua = rng.choice(["-", ""])
        for u in rng.choice(pages, size=n, replace=True):
            t += pd.Timedelta(seconds=float(rng.uniform(1, 6)))
            st = int(rng.choice([200, 404], p=[0.85, 0.15]))
            reqs.append((t, "GET", u, st, int(rng.integers(1000, 20000)), "-", ua))
    else:
        raise ValueError(kind)
    return reqs


def inject(df, per_type=10, seed=42):
    rng = np.random.default_rng(seed)
    pages = df.loc[(df.status == 200) & ~df.url.str.contains(STATIC_RE, regex=True), "url"].value_counts().index[:300].to_numpy()
    t0, t1 = df.timestamp.min(), df.timestamp.max() - pd.Timedelta(minutes=10)
    pool = [f"203.0.113.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)]
    ips = iter(rng.permutation(pool))
    lines, labels = [], []
    for kind in BOT_TYPES:
        for _ in range(per_type):
            ip = str(next(ips))
            start = t0 + (t1 - t0) * float(rng.random())
            for (ts, m, u, st, size, ref, ua) in make_bot(kind, ip, start, pages, rng):
                lines.append((ts, fmt(ts, ip, m, u, st, size, ref, ua)))
            labels.append({"ip": ip, "bot_type": kind})
    return lines, pd.DataFrame(labels)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="data/access.log")
    ap.add_argument("--out", default="data/access_with_bots.log")
    ap.add_argument("--labels", default="data/injected_labels.csv")
    ap.add_argument("--per-type", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    real = parse_file(a.log)
    raw = [l.rstrip("\n") for l in open(a.log, encoding="utf-8", errors="replace")]
    new, labels = inject(real, a.per_type, a.seed)
    # real lines keep their original text; sort everything by timestamp
    from parse_logs import LOG_RE, TS_FORMAT
    merged = []
    for l in raw:
        m = LOG_RE.match(l)
        if m:
            merged.append((pd.to_datetime(m["ts"], format=TS_FORMAT, utc=True), l))
    merged += new
    merged.sort(key=lambda x: x[0])
    with open(a.out, "w") as fh:
        fh.write("\n".join(l for _, l in merged) + "\n")
    labels.to_csv(a.labels, index=False)
    print(f"real lines: {len(raw)}  injected lines: {len(new)}  injected bot IPs: {len(labels)}")
    print(labels.bot_type.value_counts().to_string())
