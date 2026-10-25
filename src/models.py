"""k-means, DBSCAN and Isolation Forest on scaled session features + evaluation."""
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score, average_precision_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
from features import model_matrix

SEED = 0


def scale(f):
    sc = StandardScaler().fit(model_matrix(f))
    return sc, sc.transform(model_matrix(f))


def run_kmeans(Z, k_range=range(2, 16)):
    scores = {k: silhouette_score(Z, KMeans(k, n_init=10, random_state=SEED).fit_predict(Z)) for k in k_range}
    return scores


def eval_flags(f, flag, name):
    y = f.is_injected.values
    flag = np.asarray(flag).astype(bool)
    tp = int((flag & (y == 1)).sum()); fp = int((flag & (y == 0)).sum()); fn = int((~flag & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fp_df = f[flag & (y == 0)]
    return {"method": name, "flagged": int(flag.sum()), "TP": tp, "FP": fp, "FN": fn,
            "precision": round(prec, 3), "recall": round(rec, 3), "F1": round(f1, 3),
            "FP_declared_bot_ua": int(fp_df.declared_bot_ua.sum()),
            "FP_other": int((1 - fp_df.declared_bot_ua).sum())}


def cluster_table(f, labels, name):
    t = f.assign(cluster=labels).groupby("cluster").agg(
        sessions=("ip", "size"), injected=("is_injected", "sum"),
        req_per_min=("req_per_min", "median"), distinct_urls=("distinct_urls", "median"),
        err_share=("err_share", "mean"), ua_browser=("ua_browser", "mean"),
        has_css=("has_css", "mean"), has_image=("has_image", "mean"))
    t["injected_share"] = (t.injected / t.sessions).round(3)
    t.insert(0, "model", name)
    return t.round(2).reset_index()


def bot_clusters(f, labels, thresh=0.5):
    """clusters where >=50% of sessions are injected bots (uses labels: this is the 'look at which clusters contain the bots' step)"""
    s = f.assign(c=labels).groupby("c").is_injected.mean()
    return set(s[s >= thresh].index) - {-1}


def run_dbscan(Z, min_samples=5, q=0.90):
    d, _ = NearestNeighbors(n_neighbors=min_samples).fit(Z).kneighbors(Z)
    eps = float(np.quantile(d[:, -1], q))  # k-distance heuristic: eps at the 90th pct of the 5-NN distance
    return eps, DBSCAN(eps=eps, min_samples=min_samples).fit_predict(Z)


def fit_iforest(Z, contamination=0.03):
    return IsolationForest(n_estimators=300, contamination=contamination, random_state=SEED).fit(Z)
