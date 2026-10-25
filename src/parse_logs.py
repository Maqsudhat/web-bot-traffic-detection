"""Parse nginx/Apache *combined* access logs into a pandas DataFrame."""
import re
import pandas as pd

# %h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-agent}i"
# The closing quote of the user agent is optional because the real log contains
# one truncated line (cut off mid user-agent); we keep it rather than drop it.
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+|-) ?(?P<url>\S*)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"?$'
)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_lines(lines):
    rows, bad = [], 0
    for line in lines:
        m = LOG_RE.match(line.rstrip("\n"))
        if m is None:
            bad += 1
            continue
        rows.append(m.groupdict())
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df.pop("ts"), format=TS_FORMAT, utc=True)
    df["status"] = df["status"].astype(int)
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype(int)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    df.attrs["unparsed_lines"] = bad
    return df


def parse_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)


if __name__ == "__main__":
    import sys
    d = parse_file(sys.argv[1])
    print(d.head())
    print(f"{len(d)} parsed, {d.attrs['unparsed_lines']} unparsed")
