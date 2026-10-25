"""End-to-end: parse -> (inject) -> sessions -> features -> k-means / DBSCAN / IForest -> rules -> evasion.
Run from the repo root:  python src/run_pipeline.py
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import average_precision_score
from parse_logs import parse_file, parse_lines
from inject_bots import inject
from features import sessionize, build_features, FEATURES
from models import (scale, run_kmeans, eval_flags, cluster_table, bot_clusters,
                    run_dbscan, fit_iforest, SEED)
from rules import apply_rules, RULES
from evasion import evaluate_evasion

OUT = "results"; os.makedirs(OUT, exist_ok=True)
pd.set_option("display.width", 220); pd.set_option("display.max_columns", 40)


def md(df):
    return df.to_markdown(index=False)


# 1-2. data ------------------------------------------------------------------
real = parse_file("data/access.log")
dev = parse_file("data/access_with_bots.log")
dev_labels = pd.read_csv("data/injected_labels.csv")
print(f"real parsed {len(real)} (unparsed {real.attrs['unparsed_lines']}); with bots {len(dev)}")

# a second, independent set of synthetic bots (seed 7) used ONLY to check the rules
lines7, labels7 = inject(real, 10, 7)
test = pd.concat([real, parse_lines([l for _, l in lines7])]).sort_values("timestamp", kind="stable").reset_index(drop=True)

# 3-4. sessions + features -----------------------------------------------------
dev_s = sessionize(dev); f = build_features(dev_s, dev_labels)
test_s = sessionize(test); ft = build_features(test_s, labels7)
f.to_csv(f"{OUT}/session_features_dev.csv", index=False)
n_req_share = len(dev) - len(real)
overview = {
    "log_lines_real": len(real), "log_lines_injected": int(n_req_share),
    "sessions_total": len(f), "sessions_injected": int(f.is_injected.sum()),
    "sessions_real": int((1 - f.is_injected).sum()),
    "real_sessions_with_declared_bot_ua": int(((1 - f.is_injected) * f.declared_bot_ua).sum()),
}
print(overview)

sc, Z = scale(f)
y = f.is_injected.values
per_type = {}
rows = []

# 5. k-means -------------------------------------------------------------------
sil = run_kmeans(Z)
k_star = max(sil, key=sil.get)               # label-free choice
km_rows = []
for k in sorted({4, 8, 12, k_star}):
    lab = KMeans(k, n_init=10, random_state=SEED).fit_predict(Z)
    fl = np.isin(lab, list(bot_clusters(f, lab)))
    r = eval_flags(f, fl, f"k-means k={k}" + (" (best silhouette)" if k == k_star else ""))
    km_rows.append(r)
    if k == k_star:
        km_lab, km_flag, km_r = lab, fl, r
rows.append(km_r)
km_tab = cluster_table(f, km_lab, f"kmeans_k{k_star}")
per_type["k-means"] = f.assign(x=km_flag).groupby("bot_type").x.mean()

# 6. DBSCAN --------------------------------------------------------------------
db_rows = []
for q in (0.90, 0.95, 0.98):
    eps, lab = run_dbscan(Z, 5, q)
    noise = lab == -1
    bc = bot_clusters(f, lab)
    db_rows.append(eval_flags(f, noise, f"DBSCAN noise only (eps={eps:.2f}, q={q})"))
    db_rows.append(eval_flags(f, noise | np.isin(lab, list(bc)), f"DBSCAN noise + bot clusters (eps={eps:.2f}, q={q})"))
    if q == 0.90:
        db_lab, db_noise, db_both = lab, noise, noise | np.isin(lab, list(bc))
rows += [db_rows[0], db_rows[1]]
db_tab = cluster_table(f, db_lab, "dbscan_q0.90")
per_type["DBSCAN noise"] = f.assign(x=db_noise).groupby("bot_type").x.mean()
per_type["DBSCAN noise+bot clusters"] = f.assign(x=db_both).groupby("bot_type").x.mean()

# 7. Isolation Forest ----------------------------------------------------------
if_rows = []
for c in (0.01, 0.02, 0.03, 0.05):
    m = fit_iforest(Z, c)
    if_rows.append(eval_flags(f, m.predict(Z) == -1, f"Isolation Forest contamination={c}"))
iforest = fit_iforest(Z, 0.03)
if_flag = iforest.predict(Z) == -1
if_score = -iforest.score_samples(Z)
rows.append(eval_flags(f, if_flag, "Isolation Forest contamination=0.03"))
per_type["Isolation Forest 3%"] = f.assign(x=if_flag).groupby("bot_type").x.mean()
ap = average_precision_score(y, if_score)
top40 = float(y[np.argsort(-if_score)[:40]].mean())

# 8. rules ---------------------------------------------------------------------
rd = apply_rules(f); rt = apply_rules(ft)
rows.append(eval_flags(f, rd.ANY_RULE, "Rules R1-R3 (dev bots, seed 42)"))
rule_test = eval_flags(ft, rt.ANY_RULE, "Rules R1-R3 (NEW bots, seed 7)")
rows.append(rule_test)
per_type["Rules R1-R3"] = f.assign(x=rd.ANY_RULE.values).groupby("bot_type").x.mean()
rule_rows = []
for c in rd.columns:
    e = eval_flags(f, rd[c], c); e2 = eval_flags(ft, rt[c], c)
    rule_rows.append({"rule": c, "dev TP": e["TP"], "dev FP": e["FP"], "test TP": e2["TP"], "test FP": e2["FP"]})
rule_fp = f[rd.ANY_RULE & (f.is_injected == 0)][["ip", "n_requests", "req_per_min", "err_share", "ua"]]

results = pd.DataFrame(rows)
recall_by_type = pd.DataFrame(per_type).round(2).reset_index().rename(columns={"bot_type": "bot type"})
recall_by_type = recall_by_type[recall_by_type["bot type"] != "human_or_real"]

# false positives of Isolation Forest
if_fp = f[if_flag & (y == 0)]
if_fp_summary = {
    "IF FP total": len(if_fp),
    "IF FP with declared-bot UA": int(if_fp.declared_bot_ua.sum()),
    "IF FP browser UA + CSS/img (heavy page loads)": int(((if_fp.ua_browser == 1) & ((if_fp.has_css + if_fp.has_image) > 0)).sum()),
}

# 10. evasion ------------------------------------------------------------------
evasion = evaluate_evasion(f.start.min(), sc, iforest)

# 11. incident summary (worst injected session = most failed logins) ------------
bots = f[f.is_injected == 1].copy()
bf = bots[bots.bot_type == "login_bruteforce"]
worst = bf.sort_values("n_requests", ascending=False).iloc[0]
sess = dev_s[(dev_s.ip == worst.ip)].sort_values("timestamp")
t_start, t_end = sess.timestamp.min(), sess.timestamp.max()
i15 = sess.timestamp.iloc[14]
idx = f.index[(f.ip == worst.ip)][0]
incident = f"""**Synthetic incident (injected, not real traffic): credential-stuffing burst against /login**

- **Source:** {worst.ip} (documentation range, synthetic), UA `{worst.ua}`
- **Window:** {t_start:%Y-%m-%d %H:%M:%S}–{t_end:%H:%M:%S} UTC ({(t_end - t_start).total_seconds():.0f} s)
- **Volume:** {int(worst.n_requests)} `POST /login` requests, ~{worst.req_per_min:.0f}/min, {worst.err_share:.0%} answered 401, {int(round(worst.n_requests * (1 - worst.err_share)))} succeeded (302)
- **Footprint:** a single URL (`distinct_urls = {int(worst.distinct_urls)}`), no CSS/images, no referrer
- **Detection:** Isolation Forest anomaly score rank {int((if_score > if_score[idx]).sum()) + 1} of {len(f)}; flagged by {'IForest, ' if if_flag[idx] else ''}k-means bot cluster, rule R2 (error storm){' and ' + 'R1' if rd.R1_fast_no_assets[idx] else ''}.
- **Time to rule trigger:** R2 fires at request 15, {(i15 - t_start).total_seconds():.0f} s after the first request, i.e. after 14 free guesses.
- **Impact if unblocked:** {int(round(worst.n_requests * (1 - worst.err_share)))} guesses got a non-401 answer; each is a potentially valid credential and must be treated as a compromised-account candidate until verified.
- **Recommended response:** block/rate-limit the IP at the edge, force password reset for any account that returned 302 to this IP, and add per-account failed-login throttling.
"""

# ---- figures -----------------------------------------------------------------
P = PCA(2, random_state=0).fit_transform(Z)
fig, ax = plt.subplots(1, 2, figsize=(11, 4.5))
real_m = y == 0
ax[0].scatter(P[real_m, 0], P[real_m, 1], s=6, c="#b0b8c4", label="real sessions")
cols = {"fast_scraper": "#d62728", "url_scanner": "#ff7f0e", "login_bruteforce": "#9467bd", "empty_ua": "#2ca02c"}
for t, c in cols.items():
    mm = f.bot_type.values == t
    ax[0].scatter(P[mm, 0], P[mm, 1], s=22, c=c, label=f"injected: {t}")
ax[0].set_title("Sessions in PCA space (scaled features)"); ax[0].legend(fontsize=7)
ax[0].set_xlabel("PC1"); ax[0].set_ylabel("PC2")
ax[1].scatter(f.req_per_min[real_m], f.err_share[real_m], s=6, c="#b0b8c4")
for t, c in cols.items():
    mm = f.bot_type.values == t
    ax[1].scatter(f.req_per_min[mm], f.err_share[mm], s=22, c=c)
ax[1].set_xscale("log"); ax[1].set_xlabel("requests per minute (log)"); ax[1].set_ylabel("share of 4xx/5xx")
ax[1].set_title("Rate vs error share")
plt.tight_layout(); plt.savefig(f"{OUT}/fig_sessions.png", dpi=130); plt.close()

# ---- save --------------------------------------------------------------------
results.to_csv(f"{OUT}/results_table.csv", index=False)
recall_by_type.to_csv(f"{OUT}/recall_by_bot_type.csv", index=False)
evasion.to_csv(f"{OUT}/evasion.csv", index=False)
km_tab.to_csv(f"{OUT}/kmeans_clusters.csv", index=False); db_tab.to_csv(f"{OUT}/dbscan_clusters.csv", index=False)
open(f"{OUT}/incident.md", "w").write(incident)
extra = {
    "overview": overview, "k_star": int(k_star), "silhouette": {int(k): round(v, 3) for k, v in sil.items()},
    "iforest_average_precision": round(ap, 3), "iforest_precision_at_40": top40, "if_fp_summary": if_fp_summary,
}
json.dump(extra, open(f"{OUT}/metrics.json", "w"), indent=2)
with open(f"{OUT}/summary.md", "w") as fh:
    fh.write("## Main results\n\n" + md(results) + "\n\n## k-means sensitivity\n\n" + md(pd.DataFrame(km_rows)) +
             "\n\n## DBSCAN sensitivity\n\n" + md(pd.DataFrame(db_rows)) +
             "\n\n## Isolation Forest sensitivity\n\n" + md(pd.DataFrame(if_rows)) +
             "\n\n## Recall by bot type\n\n" + md(recall_by_type) +
             "\n\n## Rules\n\n" + md(pd.DataFrame(rule_rows)) + "\n\nRule FPs (dev):\n\n" + md(rule_fp) +
             "\n\n## k-means clusters containing bots\n\n" + md(km_tab[km_tab.injected > 0]) +
             "\n\n## DBSCAN clusters containing bots\n\n" + md(db_tab[db_tab.injected > 0]) +
             "\n\n## Evasion\n\n" + md(evasion) + "\n\n## Incident\n\n" + incident)
print(open(f"{OUT}/summary.md").read()); print(json.dumps(extra, indent=1))
