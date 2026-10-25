**Synthetic incident (injected, not real traffic): credential-stuffing burst against /login**

- **Source:** 203.0.113.242 (documentation range, synthetic), UA `python-requests/2.2.1 CPython/2.7.6`
- **Window:** 2015-05-19 09:50:31–09:55:47 UTC (316 s)
- **Volume:** 279 `POST /login` requests, ~53/min, 97% answered 401, 8 succeeded (302)
- **Footprint:** a single URL (`distinct_urls = 1`), no CSS/images, no referrer
- **Detection:** Isolation Forest anomaly score rank 10 of 3092; flagged by IForest, k-means bot cluster, rule R2 (error storm) and R1.
- **Time to rule trigger:** R2 fires at request 15, 16 s after the first request, i.e. after 14 free guesses.
- **Impact if unblocked:** 8 guesses got a non-401 answer; each is a potentially valid credential and must be treated as a compromised-account candidate until verified.
- **Recommended response:** block/rate-limit the IP at the edge, force password reset for any account that returned 302 to this IP, and add per-account failed-login throttling.
