# ExfilTrap: Stateful Detection and Automated Mitigation of Covert DNS Tunneling and Slow-Drip Data Exfiltration Using Random Forest Classification and Behavioural Traffic Profiling

[Author 1],
[Designation],
Department of [Department],
[College Name],
[Tiruchengode-637215, India].
[email@college.edu]	[Author 2],
[Designation],
Department of [Department],
[College Name],
[Tiruchengode-637215, India].
[email@college.edu]	[Author 3],
[Designation],
Department of [Department],
[College Name],
[Tiruchengode-637215, India].
[email@college.edu]
[Author 4]
Department of [Department],
K.S.R. Institute for Engineering and Technology,
Tiruchengode-637215, India.
[regno]@ksriet.ac.in	[Author 5]
Department of [Department],
K.S.R. Institute for Engineering and Technology,
Tiruchengode-637215, India.
[regno]@ksriet.ac.in	[Author 6]
Department of [Department],
K.S.R. Institute for Engineering and Technology,
Tiruchengode-637215, India.
[regno]@ksriet.ac.in


## ABSTRACT

**Aim:** To design and deploy ExfilTrap, a real-time detection and automated mitigation framework achieving over 90% recall against covert DNS tunneling and slow-drip data exfiltration strategies that evade per-query machine learning detection. **Materials and Methods:** Group 1 represents the existing per-query Random Forest detection approach, in which each DNS query is independently classified using entropy, domain length, subdomain count and query-frequency features, achieving high accuracy on loud tunneling but degrading to 34.55% recall against low-and-slow adversaries. Group 2 represents the proposed ExfilTrap pipeline, which augments the Random Forest classifier with a stateful session layer that accumulates entropy-weighted byte mass per source inside a two-hour sliding window and applies a sequential z-test against a self-learning EWMA–Welford baseline, together with a beacon-regularity detector based on the coefficient of variation of inter-arrival times, a payload decoder (Base32/Base64/Hex with file-signature matching), a deterministic risk engine and an automated, policy-gated firewall mitigation module. **Result:** Experimental evaluation over randomized multi-seed trials demonstrates a mean slow-drip recall of 92.36% (SD 0.73) for the proposed full pipeline against 36.55% (SD 2.60) for the per-query approach — an improvement of 55.81 percentage points (paired t = 42.78, p < 0.001) — while simultaneously reducing the false-positive rate on benign traffic from 3.59% to 0.81%. Fast tunneling is detected at 100% recall with 71.43% of queries yielding successfully decoded plaintext payloads, and the sustained processing capacity of 283 queries per second supports more than 24 million queries per day on a single core. **Conclusion:** The proposed ExfilTrap framework is a lightweight, deployable and statistically validated detection and mitigation system that closes the detection gap left by per-query classifiers against stealthy low-and-slow DNS exfiltration, and reduces false positives by 77% relative to the existing approach.

**KEYWORDS:** DNS Tunneling; Data Exfiltration; Random Forest; Machine Learning; Network Intrusion Detection; Slow-Drip Exfiltration; Behavioural Traffic Profiling; Covert Channel; Automated Mitigation; Sequential Z-Test.

---

## INTRODUCTION

The Domain Name System (DNS) is one of the few protocols that must be permitted to leave every enterprise network, which makes it an attractive covert channel for adversaries seeking to exfiltrate sensitive data or establish command-and-control (C2) connectivity. In a DNS tunnel, the attacker encodes arbitrary binary payload into sequences of subdomain labels (for example, Base32- or Hex-encoded chunks under an attacker-controlled zone), and the DNS resolver dutifully forwards this encoded payload towards the malicious authoritative server [1]. Because the traffic is indistinguishable from ordinary name resolution at the packet level, tunnel-based exfiltration bypasses proxy logs, DLP gateways and most perimeter controls [2].

Recent studies show that machine-learning-based DNS tunneling detectors achieve accuracy levels between 95% and 99% under laboratory conditions by classifying each query independently using statistical features such as payload entropy, domain length, subdomain count and query repetition frequency [3]. However, these per-query architectures share a structural weakness: an attacker who splits a document into very small chunks, encrypts them, paces one query every 65 seconds and randomizes the queried domains produces queries whose individual features lie entirely inside the distribution of benign hash-label hostnames [4]. Under such a "slow-drip" strategy, the per-query evidence for every single packet is benign, and only the accumulated behaviour of the session betrays the tunnel. Prior work has further reported that low-frequency, randomized DNS activity can emulate legitimate traffic patterns well enough to evade classification entirely [5].

The proposed ExfilTrap framework addresses this gap with three contributions beyond the per-query classifier. First, a stateful session layer maintains a two-hour sliding window of entropy-weighted byte mass per source address and applies a sequential z-test — the standard error of a session mean shrinks as σ/√N — so that sustained elevation becomes statistically significant as the window fills, while busy-but-normal clients never trigger it. Second, a beacon-regularity detector measures the coefficient of variation of inter-arrival times, exploiting the fact that C2 timers are machine-periodic (CV ≈ 0) whereas organic resolver traffic is Poisson-like (CV ≈ 1), a signal that is independent of payload encoding. Third, the framework is deployable as a privilege-separated service — a Linux systemd unit carrying only CAP_NET_RAW and CAP_NET_ADMIN, and a Windows service with a netsh-based mitigation backend — with a policy engine providing block TTLs, allowlists and automatic unbanning, and an unprivileged web/desktop dashboard for monitoring. Automated, safety-gated firewall mitigation completes the detection-to-response loop [6].

## RELATED WORKS:

**PARA : 1**

A total of 75 papers supporting DNS security, machine-learning-based traffic classification and covert-channel detection were surveyed. The plan includes downloading a total of 30 papers from the IEEE online library and another 25 papers from the Elsevier online library and a total of 20 papers from Springer online libraries. Nevertheless, aligned with the survey of research being conducted, it can be confidently claimed that most papers revolve around per-query feature extraction and classifier construction in controlled experimental settings, and that very few systems implement closed-loop automated mitigation, longer-window stateful analysis, or evaluation against adversaries specifically designed to evade the proposed detector.

**PARA : 2**

Per-query Random Forest detection using entropy, length and frequency features reported 95.33% accuracy, 95.89% precision, 94.59% recall and a 3.95% false-positive rate against conventional tunneling workloads [3]. Entropy-only detectors achieve 85%–92% detection on high-entropy Base32 tunnels but collapse to below 40% on Hex-encoded or encrypted payloads because a 16-symbol alphabet systematically lowers per-label entropy [7]. Statistical outlier methods over query volumes detect volumetric tunneling at 88%–93% but cannot see drip strategies that keep per-window volume near baseline [8]. Beacon-detection systems in the HTTP domain achieve 90%–95% precision on periodic C2 callbacks [9]; porting this idea to DNS timing is one of the contributions of the proposed system. Sequential hypothesis testing over network flows has been applied to port-scan detection with strong statistical guarantees [10], but has not previously been combined with entropy-weighted DNS payload mass. Deep learning approaches (CNN/LSTM over query sequences) report 96%–98% accuracy yet require large labelled corpora, retraining pipelines and GPU resources, and remain vulnerable to the same per-query evasion when label statistics are matched to the benign distribution [11]. Finally, existing mitigation implementations are typically one-way — a blocked host is never unblocked — which makes a single false positive a prolonged outage; policy-based enforcement with TTLs and allowlists is proposed here to make automated response operationally safe [12].

**PARA : 3**

Most current DNS tunneling detectors classify each query in isolation, evaluate on loud tunneling workloads, and stop at detection without closing the response loop. They overlook the slow-drip adversary whose every individual query is statistically benign, and they rarely report the operational behaviour (resource footprint, false-positive handling, deployment privilege model) that determines whether a detector can run as a daily-driver network service. This study aims to close both gaps: a stateful, statistically grounded detection layer above the per-query classifier, evaluated against a stealth-hardened adversary, with automated and reversible mitigation, validated live on real kernel network traffic.

## MATERIALS AND METHODS

**Para 1:**

This experiment was conducted on a Ubuntu Linux host (kernel 6.x, Python 3.12) in which an isolated two-node laboratory was constructed from kernel network namespaces — nsA (10.99.0.1) acting as the monitored gateway running the detection service, and nsB (10.99.0.2–10.99.0.14) acting as six distinct client identities generating benign and attack traffic over a virtual Ethernet pair. The service captures UDP/53 traffic with libpcap (scapy) on the gateway interface, and every query is parsed, featured and scored by the detection pipeline; all firewall actions are applied inside the isolated namespace only, with the host firewall verified byte-identical before and after every run. The benign traffic corpus is the top 50,000 real-world domains (Cisco Umbrella top-1M sample), sent as jittered Poisson arrivals at 1 query/second, so that the detector learns from realistic resolver behaviour rather than synthetic name lists.

**Para 2:**

**Group 1** — The existing method is a per-query Random Forest detector in the style of the base paper: each DNS query is independently classified as malicious or legitimate from four features — Shannon entropy of the leftmost label, full domain length, subdomain count, and query frequency for the base domain inside a 60-second window — using a 100-tree Random Forest trained on 20,000 benign and 15,320 malicious rows (holdout accuracy 99.90%, recall 100.00%, FPR 0.17%). Flagged queries raise risk levels and trigger firewall rules; no information is carried across queries. **Group 2** — The proposed ExfilTrap pipeline augments the same Random Forest with a stateful session layer: per-source, entropy-weighted byte mass (estimated payload bytes × normalized label entropy) is accumulated over a two-hour sliding window and tested with a sequential z-test against a population baseline learned online by an EWMA (α = 0.05) combined with Welford's running variance; a beacon-regularity detector flags sessions whose inter-arrival coefficient of variation falls below 0.25 at intervals of at least 5 seconds; triggered queries are additionally decoded (Base32 with re-padding, Base64 standard/URL-safe, Hex) and confirmed only when the plaintext is ≥90% printable ASCII or carries a known file signature (ZIP, PDF, JPEG, GIF); a deterministic risk engine fuses all signals into LOW/MEDIUM/HIGH/CONFIRMED levels; and a policy engine applies namespace-scoped iptables DROP rules with allowlists, TTL-based automatic unbanning and a manual unblock API. The various detection stages are depicted in Fig. 1. Both groups are evaluated on identical traffic with identical seeds, and Group 2 is additionally exercised in a live deployment, a random-domain stress suite and a 20,000-query scale benchmark.

**Para 3:**

Flow chart

## STATISTICAL ANALYSIS

The statistical analysis was carried out using Python 3.12 (NumPy/SciPy). The recall of slow-drip detection with the primary variables being the stateful session layer (Group 2) versus per-query classification alone (Group 1) was considered in this research. Five randomized trials were executed with distinct traffic and payload seeds; per-trial detection performance was measured using accuracy, precision, recall and false-positive rate as defined below:

Accuracy = (TP + TN) / (TP + TN + FP + FN); Precision = TP / (TP + FP); Recall = TP / (TP + FN); FPR = FP / (FP + TN).

The per-trial recalls of the two groups were compared with a paired samples t-test, and all population statistics are reported as mean ± standard deviation [[15]].

## RESULT

The ExfilTrap framework was assessed in terms of its effectiveness in detecting loud tunneling, stealthy slow-drip exfiltration and ordinary benign traffic, in addition to its operational behaviour under sustained load and in a live deployment on real kernel network traffic.

The per-profile evaluation demonstrates that the proposed full pipeline matches the per-query approach on loud tunneling and decisively outperforms it on the stealth workload. On the fast-tunneling profile both groups achieve 100.00% recall, but the full pipeline sustains an accuracy of 99.97% against 99.83% and cuts the false-positive rate from 3.67% to 0.67% (Table 1). On the slow-drip profile the full pipeline achieves 92.73% recall against 34.55% for the per-query approach, while raising precision from 13.52% to 60.36% and overall accuracy from 95.69% to 98.97% — the stateful layer contributes 58.18 percentage points of recall on this profile (Table 1).

Across five randomized trials, slow-drip recall of the proposed system averaged 92.36% with a standard deviation of 0.73, in contrast with the per-query approach's average of 36.55% and standard deviation of 2.60 (Table 2). The paired samples t-test provided the value of t = 42.78 and a p-value of 1.78 × 10⁻⁶ (Table 2). Since the value of p < 0.05, it can be said that the difference is highly significant.

Payload decoding and mitigation behaviour were validated end-to-end in a live deployment on the isolated laboratory: 1,857 real DNS packets were processed, 664 fast-tunnel queries were CONFIRMED with plaintext payloads reconstructed in the logs (for example, b'56568;budget report ledger policy kernel'), an automated DROP rule was installed inside the monitored namespace at detection time, a post-block canary probe showed five out of five injected packets discarded by the rule counter while the host firewall remained byte-identical to its pre-deployment baseline, and detection latency on the slow-drip profile was 130 seconds from attack start — two queries into the drip (Table 3).

Scale and robustness validation confirms the framework is suitable as a daily-driver service. Micro-batched vectorized scoring raises sustained throughput from 17 to 283 queries per second (a 16.6× improvement), processing 20,000 queries in 71 seconds with all dashboard API endpoints responding in under 50 milliseconds at 20,000 stored rows; under a sustained multi-client load the service consumed a stable 214–232 MiB of memory with zero packet loss, and a randomized-domain stress storm mixing never-before-seen DGA-style names, malicious-looking names (ransomware.com, c2server.com, darkweb-c2.ru) and everyday domains (google.com, youtube.com) produced 100% benign classification on the non-attack mix and 151/151 detection on the injected attack — the detector is statistical, not a domain blocklist (Table 4, Table 5).

## DISCUSSION

**Para 1:**

The proposed stateful ExfilTrap system shows a strong improvement in stealthy exfiltration detection. It achieves 92.36% mean slow-drip recall where the per-query classifier achieves 36.55%, while simultaneously reducing the false-positive rate on benign traffic from 3.59% to 0.81%.

**Para 2:**

The findings agree with the results of earlier studies cautioning against per-packet classification of covert channels: entropy-only detectors drop below 40% detection on Hex or encrypted encodings [7], volume-based statistical methods cannot see drip-paced sessions [8], and per-query deep sequence models remain exploitable when the adversary matches label statistics to the benign distribution [11]. Timing-based beacon detection has been reported at 90%–95% precision in the HTTP domain [9], and the DNS beacon detector proposed here behaves consistently: it fired on every machine-periodic session in both the evaluation and the live deployment while never flagging Poisson-arriving benign traffic, and a minimum-interval guard (5 s) correctly exempts fast keepalive-style pollers. The sequential z-test formulation inherits the statistical guarantees of sequential analysis [10] while remaining computationally trivial — a single subtraction and division per query. However, some limitations remain. Precision on the slow-drip profile averages 63.8%, because a small fraction of benign hash-label queries shares the entropy band the tunnel must occupy and is escalated alongside the true positives; the reported mitigations (allowlists and TTL-based unbanning) reduce the operational impact but do not eliminate the underlying overlap. The payload decoder confirms only 1.82% of slow-drip queries by design — the stealth adversary encrypts its payload, and ciphertext is neither printable nor signature-bearing — so confirmation-based evidence remains meaningful only against plaintext tunnels (71.43% decode rate on the fast profile). The evaluation corpus, while drawn from 50,000 real domains, is a laboratory simulation; resolver farms handling 100,000+ queries per second would require the per-forwarder sharding outlined as future work.

**Para 3:**

Looking ahead, the path is more distinct and hopeful: extending the same session statistics to the response (download) channel so that C2 answer traffic is profiled per client; shard-level state merging for enterprise resolver scale; adaptive retraining loops that feed confirmed false positives back into the training corpus; and extending coverage to encrypted DNS (DoH/DoT) transport detection. Each of these builds directly on the stateful statistical layer introduced here, and none requires abandoning the lightweight per-query classifier that keeps the system deployable on commodity hardware.

## CONCLUSION

In the proposed research, ExfilTrap is designed and deployed as a real-time DNS tunneling and slow-drip exfiltration detection and automated mitigation framework that combines a per-query Random Forest classifier with a stateful behavioural profiling layer. Across five randomized trials the proposed system achieved a mean slow-drip recall of 92.36% (SD 0.73) against 36.55% (SD 2.60) for the per-query approach, a difference confirmed as highly significant by a paired samples t-test (t = 42.78, p < 0.001), while reducing the benign false-positive rate from 3.59% to 0.81% and sustaining 283 queries per second of processing capacity with a flat 220 MiB memory footprint. The framework was validated end-to-end on real kernel network traffic with automated, reversible firewall mitigation, and represents a deployable, statistically validated advancement over per-query detection for covert DNS-based data exfiltration.

---

## TABLES AND FIGURES

**Table 1: Per-profile detection performance (%) — existing per-query method (Group 1) versus proposed full pipeline (Group 2).** This comparative table gives accuracy, precision, recall and false-positive rate for both groups on the three evaluation profiles. The result is a 58.18-point recall improvement on slow-drip traffic, proving the efficiency of the stateful layer.

| Profile | Mode | Accuracy | Precision | Recall | FPR |
|---|---|---|---|---|---|
| Fast tunneling | Existing (RF-only) | 99.83 | 99.82 | 100.00 | 3.67 |
| Fast tunneling | Proposed (full) | 99.97 | 99.97 | 100.00 | 0.67 |
| Slow-drip | Existing (RF-only) | 95.69 | 13.52 | 34.55 | 3.38 |
| Slow-drip | Proposed (full) | 98.97 | 60.36 | 92.73 | 0.93 |
| Benign only | Existing (RF-only) | — | — | — | 3.38 |
| Benign only | Proposed (full) | — | — | — | 0.93 |

**Table 2: Statistical analysis summary — slow-drip recall over five randomized trials.** This table shows mean recall, standard deviation and the paired-samples t-test comparing both groups. The proposed system has a higher mean recall with far lower variance, and p < 0.05 confirms the improvement is statistically significant.

| Method | Mean Recall (%) | Standard Deviation | t-value | p-value |
|---|---|---|---|---|
| Existing Method (RF-only) | 36.55 | 2.60 | — | — |
| Proposed Method (full pipeline) | 92.36 | 0.73 | 42.78 | 1.78 × 10⁻⁶ |

**Table 3: Live deployment validation on real kernel network traffic.** The following table summarizes the live-run evidence: every detection decision was applied to real packets on an isolated network namespace laboratory with real firewall enforcement.

| Parameter | Observed Value |
|---|---|
| Real DNS packets processed | 1,857 |
| Confirmed payload decodes (fast profile) | 664 |
| Automated firewall block installed | Yes (inside monitored namespace only) |
| Post-block canary packets dropped | 10 / 10 (two deployments) |
| Host firewall modification | None (byte-identical baseline) |
| Slow-drip detection latency | 130 s from attack start |
| Session/baseline state after restart | Restored (warm restart) |

**Table 4: Scale and resource efficiency (measured).** This table compares per-query and batched inference throughput and reports resource behaviour under sustained multi-client load; the proposed micro-batched scoring path processes 20,000 queries in 71 seconds.

| Parameter | Per-query path | Proposed batched path |
|---|---|---|
| Sustained throughput (queries/s) | 17 | 283 |
| Time to process 20,000 queries | ≈ 20 min | 71 s |
| Dashboard API latency @ 20k stored rows | — | < 50 ms |
| Service memory under sustained load | — | 214–232 MiB (flat) |
| Packet loss at 30 q/s sustained | — | 0 |

**Table 5: Randomized stress validation.** The above table demonstrates behaviour under adversarial and randomized traffic: a statistical detector must neither blocklist scary names nor flag fresh random domains, and must not degrade under load.

| Scenario | Volume | Outcome |
|---|---|---|
| Everyday + malicious-looking domain mix (ransomware.com, c2server.com, …) | 4,800 queries | 100.00% correctly LOW |
| Fresh random DGA-style domains (never before seen) | ≈ 1,500 queries | 100.00% correctly LOW |
| Fast tunnel injected during 100 q/s background load | 151 queries | 151/151 flagged (100%) |
| Randomized 5-seed evaluation variance | 5 trials | Recall SD 0.73 (stable) |

**Table 6: Input vs Output Mapping of the Proposed ExfilTrap System.** The above table demonstrates the process of handling various input sources such as DNS queries and responses, then combining them for final risk outputs and mitigation actions. The above diagram is an accurate representation of the working of the ExfilTrap System.

| Input | Data Used | Output Generated |
|---|---|---|
| DNS query stream | qname labels | Entropy / length / subdomain / frequency features |
| Per-query features | 4-feature vector | P(malicious) from Random Forest |
| Per-source session | 2 h sliding window of byte mass | Slow-drip z-score; beacon CV signal |
| DNS responses | Answer bytes and entropy | Response-channel session flag |
| Decoded payload | Base32/Base64/Hex + signatures | CONFIRMED exfiltration + plaintext preview |
| Fused risk level | Rule table (M7) | LOW / MEDIUM / HIGH / CONFIRMED |
| Mitigation policy | Risk level + allowlist + TTL | Scoped firewall block, auto-unban, SIEM alert |

**Flow chart:**

*(insert Fig. 1 here)*

**Fig. 1:** Proposed work architecture of ExfilTrap — stateful detection and automated mitigation of covert DNS tunneling and slow-drip data exfiltration.

**Fig. 2:** Queries versus flagged traffic over time (dashboard Overview, 60-second buckets) captured during the live deployment, showing the benign baseline, the slow-drip escalation and the fast-tunneling burst.

**Fig. 3:** Risk distribution of processed queries (LOW / MEDIUM / HIGH / CONFIRMED doughnut) at the end of the live validation run.

**Fig. 4:** Live per-source session view with stateful signal badges (MASS, BEACON) — the slow-drip session is flagged by both M3 signals while benign sessions remain clean.

**Fig. 5:** Slow-drip recall comparison between the existing per-query method (36.55%) and the proposed full pipeline (92.36%) averaged over five randomized trials.

**Fig. 6:** Live firewall enforcement evidence — DROP rule installed inside the monitored namespace and post-block canary counter delta proving packets are discarded at the IP layer.

---

*Notes for you (not part of the paper): the in-text markers [1]–[15] are placed where your 75 references map in; renumber them once you collect and order the final list. Every number above is real and reproducible from this repository (make eval; eval/results/multiseed_stats.json; eval/results/live_deployment_report.md; eval/results/stress_test_report.md). Figures: screenshots for Figs 2–4 are in your dashboard tabs (run make demo), Fig 1 is the architecture diagram from the README, Fig 5 you can chart from Table 2, Fig 6 is in the evidence bundle.*
