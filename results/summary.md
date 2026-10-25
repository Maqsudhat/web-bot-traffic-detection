## Main results

| method                                        |   flagged |   TP |   FP |   FN |   precision |   recall |    F1 |   FP_declared_bot_ua |   FP_other |
|:----------------------------------------------|----------:|-----:|-----:|-----:|------------:|---------:|------:|---------------------:|-----------:|
| k-means k=15 (best silhouette)                |        42 |   40 |    2 |    0 |       0.952 |      1   | 0.976 |                    2 |          0 |
| DBSCAN noise only (eps=0.38, q=0.9)           |       243 |   16 |  227 |   24 |       0.066 |      0.4 | 0.113 |                   68 |        159 |
| DBSCAN noise + bot clusters (eps=0.38, q=0.9) |       267 |   40 |  227 |    0 |       0.15  |      1   | 0.261 |                   68 |        159 |
| Isolation Forest contamination=0.03           |        93 |   40 |   53 |    0 |       0.43  |      1   | 0.602 |                    3 |         50 |
| Rules R1-R3 (dev bots, seed 42)               |        41 |   40 |    1 |    0 |       0.976 |      1   | 0.988 |                    1 |          0 |
| Rules R1-R3 (NEW bots, seed 7)                |        41 |   40 |    1 |    0 |       0.976 |      1   | 0.988 |                    1 |          0 |

## k-means sensitivity

| method                         |   flagged |   TP |   FP |   FN |   precision |   recall |    F1 |   FP_declared_bot_ua |   FP_other |
|:-------------------------------|----------:|-----:|-----:|-----:|------------:|---------:|------:|---------------------:|-----------:|
| k-means k=4                    |         0 |    0 |    0 |   40 |       0     |      0   | 0     |                    0 |          0 |
| k-means k=8                    |         0 |    0 |    0 |   40 |       0     |      0   | 0     |                    0 |          0 |
| k-means k=12                   |        22 |   20 |    2 |   20 |       0.909 |      0.5 | 0.645 |                    1 |          1 |
| k-means k=15 (best silhouette) |        42 |   40 |    2 |    0 |       0.952 |      1   | 0.976 |                    2 |          0 |

## DBSCAN sensitivity

| method                                         |   flagged |   TP |   FP |   FN |   precision |   recall |    F1 |   FP_declared_bot_ua |   FP_other |
|:-----------------------------------------------|----------:|-----:|-----:|-----:|------------:|---------:|------:|---------------------:|-----------:|
| DBSCAN noise only (eps=0.38, q=0.9)            |       243 |   16 |  227 |   24 |       0.066 |    0.4   | 0.113 |                   68 |        159 |
| DBSCAN noise + bot clusters (eps=0.38, q=0.9)  |       267 |   40 |  227 |    0 |       0.15  |    1     | 0.261 |                   68 |        159 |
| DBSCAN noise only (eps=0.67, q=0.95)           |       118 |    6 |  112 |   34 |       0.051 |    0.15  | 0.076 |                   28 |         84 |
| DBSCAN noise + bot clusters (eps=0.67, q=0.95) |       152 |   40 |  112 |    0 |       0.263 |    1     | 0.417 |                   28 |         84 |
| DBSCAN noise only (eps=1.18, q=0.98)           |        47 |    5 |   42 |   35 |       0.106 |    0.125 | 0.115 |                    8 |         34 |
| DBSCAN noise + bot clusters (eps=1.18, q=0.98) |        82 |   40 |   42 |    0 |       0.488 |    1     | 0.656 |                    8 |         34 |

## Isolation Forest sensitivity

| method                              |   flagged |   TP |   FP |   FN |   precision |   recall |    F1 |   FP_declared_bot_ua |   FP_other |
|:------------------------------------|----------:|-----:|-----:|-----:|------------:|---------:|------:|---------------------:|-----------:|
| Isolation Forest contamination=0.01 |        31 |   30 |    1 |   10 |       0.968 |     0.75 | 0.845 |                    0 |          1 |
| Isolation Forest contamination=0.02 |        62 |   40 |   22 |    0 |       0.645 |     1    | 0.784 |                    3 |         19 |
| Isolation Forest contamination=0.03 |        93 |   40 |   53 |    0 |       0.43  |     1    | 0.602 |                    3 |         50 |
| Isolation Forest contamination=0.05 |       155 |   40 |  115 |    0 |       0.258 |     1    | 0.41  |                   17 |         98 |

## Recall by bot type

| bot type         |   k-means |   DBSCAN noise |   DBSCAN noise+bot clusters |   Isolation Forest 3% |   Rules R1-R3 |
|:-----------------|----------:|---------------:|----------------------------:|----------------------:|--------------:|
| empty_ua         |         1 |            1   |                           1 |                     1 |             1 |
| fast_scraper     |         1 |            0.4 |                           1 |                     1 |             1 |
| login_bruteforce |         1 |            0.2 |                           1 |                     1 |             1 |
| url_scanner      |         1 |            0   |                           1 |                     1 |             1 |

## Rules

| rule              |   dev TP |   dev FP |   test TP |   test FP |
|:------------------|---------:|---------:|----------:|----------:|
| R1_fast_no_assets |       30 |        1 |        30 |         1 |
| R2_error_storm    |       20 |        0 |        20 |         0 |
| R3_anonymous_bulk |       12 |        0 |        12 |         0 |
| ANY_RULE          |       40 |        1 |        40 |         1 |

Rule FPs (dev):

| ip           |   n_requests |   req_per_min |   err_share | ua                                              |
|:-------------|-------------:|--------------:|------------:|:------------------------------------------------|
| 65.55.213.73 |           39 |            39 |           0 | msnbot/2.0b (+http://search.msn.com/msnbot.htm) |

## k-means clusters containing bots

|   cluster | model      |   sessions |   injected |   req_per_min |   distinct_urls |   err_share |   ua_browser |   has_css |   has_image |   injected_share |
|----------:|:-----------|-----------:|-----------:|--------------:|----------------:|------------:|-------------:|----------:|------------:|-----------------:|
|         7 | kmeans_k15 |         10 |         10 |         54.38 |               1 |        0.97 |         0.1  |         0 |           0 |             1    |
|        12 | kmeans_k15 |         32 |         30 |         49    |              62 |        0.36 |         0.19 |         0 |           0 |             0.94 |

## DBSCAN clusters containing bots

|   cluster | model        |   sessions |   injected |   req_per_min |   distinct_urls |   err_share |   ua_browser |   has_css |   has_image |   injected_share |
|----------:|:-------------|-----------:|-----------:|--------------:|----------------:|------------:|-------------:|----------:|------------:|-----------------:|
|        -1 | dbscan_q0.90 |        243 |         16 |          4    |             4   |        0.11 |         0.51 |      0.31 |        0.46 |             0.07 |
|        23 | dbscan_q0.90 |         10 |         10 |         50.5  |            50.5 |        0.94 |         0    |      0    |        0    |             1    |
|        24 | dbscan_q0.90 |          8 |          8 |         53.32 |             1   |        0.97 |         0    |      0    |        0    |             1    |
|        25 | dbscan_q0.90 |          6 |          6 |        136.18 |           181.5 |        0    |         1    |      0    |        0    |             1    |

## Evasion

| evasion level                                    | caught by rules (IPs)   | caught by IForest (IPs)   |   guesses/hour/IP |   days for 10k guesses (1 IP) |   IPs needed for 10k in 24 h |
|:-------------------------------------------------|:------------------------|:--------------------------|------------------:|------------------------------:|-----------------------------:|
| E0 baseline (1 s, python UA)                     | 20/20                   | 20/20                     |            3474.2 |                           0.1 |                            1 |
| E1 + browser UA & fetch CSS/img                  | 20/20                   | 20/20                     |            3334.7 |                           0.1 |                            1 |
| E2 + slow, jittered (mean 5 s)                   | 20/20                   | 20/20                     |             713.6 |                           0.6 |                            1 |
| E3 + slower (mean 30 s)                          | 20/20                   | 20/20                     |             119.7 |                           3.5 |                            4 |
| E4 + pad 3 benign GETs per guess (8 s)           | 0/20                    | 20/20                     |             111.9 |                           3.7 |                            4 |
| E5 burst of 10, sleep 31 min                     | 0/20                    | 20/20                     |              25.3 |                          16.4 |                           17 |
| E6 burst of 6 + 2 benign GETs each, sleep 31 min | 0/20                    | 20/20                     |              14.8 |                          28.1 |                           29 |

## Incident

**Synthetic incident (injected, not real traffic): credential-stuffing burst against /login**

- **Source:** 203.0.113.242 (documentation range, synthetic), UA `python-requests/2.2.1 CPython/2.7.6`
- **Window:** 2015-05-19 09:50:31–09:55:47 UTC (316 s)
- **Volume:** 279 `POST /login` requests, ~53/min, 97% answered 401, 8 succeeded (302)
- **Footprint:** a single URL (`distinct_urls = 1`), no CSS/images, no referrer
- **Detection:** Isolation Forest anomaly score rank 10 of 3092; flagged by IForest, k-means bot cluster, rule R2 (error storm) and R1.
- **Time to rule trigger:** R2 fires at request 15, 16 s after the first request, i.e. after 14 free guesses.
- **Impact if unblocked:** 8 guesses got a non-401 answer; each is a potentially valid credential and must be treated as a compromised-account candidate until verified.
- **Recommended response:** block/rate-limit the IP at the edge, force password reset for any account that returned 302 to this IP, and add per-account failed-login throttling.
