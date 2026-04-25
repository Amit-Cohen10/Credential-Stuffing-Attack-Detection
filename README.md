# HW1 — Credential Stuffing Attack Detection

**Course:** 3917 — AI Techniques for Malware Detection  
**Semester:** 2 / 2026  
**Students:** Amit Cohen (318556016) · Sagi Levhar (206590457)

---

## What This Assignment Is About

We were given a real-world dataset of ~530,000 login attempts captured during an active
credential stuffing attack. The goal was to:

1. Understand the data through exploratory analysis (Part A)
2. Build a feature table per IP, email, tool, and network (Part B)
3. Design our own heuristic detection rules and label each row as malicious/legitimate (Part C)
4. Apply statistical anomaly detection — z-scores, IQR fences, Shannon entropy — and
   combine them into a layered confidence score (Part D)
5. Write a short attack-profiling report that a security team could actually read (Part E)
6. Three bonus analyses: temporal burst detection, country×tool heatmap, creative features (Bonus)

---

## Files in This Submission

| File | What it is |
|---|---|
| `HW1_Credential_Stuffing.ipynb` | The main notebook — all code, all plots, all written answers |
| `helpers.py` | Shared helper functions imported by the notebook (entropy, z-score, IQR, plot utils) |
| `assignment_labeled.csv` | The original dataset with two new columns: `is_malicious` (Part C) and `is_malicious_refined` (Part D) |
| `compromised_credentials.csv` | Emails that had at least one successful login (status 200) flagged as malicious — the "compromised credentials" list |
| `figures/` | All 23 plots saved as PNGs (auto-created when the notebook runs) |

> `assignment.csv` (the raw input from the course) is **not** included — the grader already
> has it and it's 83 MB.

---

## How to Run

```
pip install pandas numpy matplotlib seaborn scipy upsetplot
```

Then open `HW1_Credential_Stuffing.ipynb` in Jupyter and do:
**Kernel → Restart & Run All**

Make sure `assignment.csv` is in the same folder as the notebook before running.
Total runtime is about 30 seconds on a normal laptop.

Everything is reproducible — `RANDOM_STATE = 42` is set at the top of both the notebook
and `helpers.py`, and passed to every operation that accepts it.

---

## Key Results (quick summary)

| Metric | Value |
|---|---|
| Total login attempts | 530,816 |
| Flagged malicious (Part C heuristics) | 323,614 (61.0 %) |
| Refined malicious label (Part D layered) | 308,487 (58.1 %) |
| Unique attacking IPs | see E.1 in notebook |
| Compromised credentials found | 22,813 email accounts |

The `risk_indication` vendor label flags ~59 % of all traffic as risky, which is way too
high to be useful as ground truth. That's exactly why we built our own detector in Part C
and cross-validated it statistically in Part D.

---

## Question Map — Where Every PDF Question Is Answered

Use this to jump directly to any answer. Every answer has a header like
`**Answer to X.Y QZ —`  in the notebook, so Ctrl+F works too.

| PDF Question | What it asks | Notebook section | Cell / heading to look for |
|---|---|---|---|
| **A.1 Q3** | What each HTTP status code likely represents | Part A → A.1 | `A1_status_dist` + markdown below it |
| **A.2 Q1** | Exact time range of the dataset | Part A → A.2 | `A2_time_range` + markdown |
| **A.2 Q2** | Are there traffic bursts? (>2× median rate) | Part A → A.2 | `A2_per_minute` + markdown |
| **A.2 Q3** | What does the risk_indication split show? | Part A → A.2 | `A2_per_minute_split` + markdown |
| **A.3 Q1** | Which countries look suspicious and why | Part A → A.3 | `A3_countries` + markdown |
| **A.3 Q2** | Which tools have near-100 % risk rates | Part A → A.3 | `A3_tools` + markdown |
| **A.3 Q3** | Threshold justification for emails-per-IP | Part A → A.3 | `A3_emails_per_ip` + markdown |
| **B.1 Q** | Why IP-level features? When does it fail? | Part B → B.1 | Markdown cell after `B1_ip_features` |
| **B.4 Q2** | How we handled missing `network_type` (77 % missing) | Part B → B.4 | Markdown after `B4_merge` |
| **B.4 Q3** | Why one-hot for network_type, frequency for others | Part B → B.4 | Same markdown cell |
| **C.1 Q1–Q3** | Label quality: flag rate, cross-tab by status, per-tool breakdown | Part C → C.1 | `C1_label_quality`, `C1_tool_risk_bar` |
| **C.1 Q4** | Why build our own detector even if the vendor label were perfect | Part C → C.1 | Markdown "Answer to C.1 Q4" |
| **C.2 Q1** | The 4 detection rules with thresholds and justifications | Part C → C.2 | Markdown "Answer to C.2 Q1" |
| **C.2 Q2** | Apply the rules → produce `is_malicious` column | Part C → C.2 | `C2_apply` |
| **C.2 Q3** | Compare our label to `risk_indication`, disagreement analysis | Part C → C.2 | `C2_compare` + `C2_disagree` + markdown |
| **C.2 Q4** | Rule overlap visualisation (UpSet plot) | Part C → C.2 | `C2_upset` |
| **D.1 Q1–Q4** | Z-score computation, counts at z>2 and z>3 | Part D → D.1 | `D1_zscores`, `D1_zscore_histograms` |
| **D.1 Q5** | Are the distributions actually normal? | Part D → D.1 | Markdown "Answer to D.1 Q5" |
| **D.2 Q1–Q3** | IQR upper fences, outlier counts, 2-of-3 rule | Part D → D.2 | `D2_iqr` |
| **D.2 Q4** | Why IQR is more robust than z-score on skewed data | Part D → D.2 | Markdown "Answer to D.2 Q4" |
| **D.3 Q1–Q4** | Shannon entropy per IP, scatter plot, threshold choice | Part D → D.3 | `D3_entropy`, `D3_scatter` |
| **D.3 Q2** | What high email entropy / status entropy means | Part D → D.3 | Markdown "Answer to D.3 Q2" |
| **D.3 Q5** | Can a user retrying 3 times be confused with an attacker? | Part D → D.3 | Same markdown cell |
| **D.4 Q1–Q5** | Layered confidence score + refined label | Part D → D.4 | `D4_layered`, `D4_plots` |
| **D.4 Q4** | How many FPs were removed / FNs introduced by refinement | Part D → D.4 | Markdown "Answer to D.4 Q4" |
| **D.4 Q6** | Why layered detection is more reliable than any single method | Part D → D.4 | Markdown "Answer to D.4 Q6" |
| **E.1** | Attack summary table + timeline + top attacking IPs | Part E → E.1 | `E1_summary`, `E1_timeline`, `E1_top_attackers` |
| **E.2** | Source breakdown by country, network type, and tool | Part E → E.2 | `E2_country`, `E2_network_type`, `E2_tool_attack_rate` |
| **E.3** | Compromised credentials: top-20 table + CSV export | Part E → E.3 | `E3_compromised` |
| **Bonus 1** | Temporal burst detection using inter-arrival times + CV | Bonus section | `BONUS_1_burst`, `BONUS_1_scatter` |
| **Bonus 2** | Country × tool attack-rate heatmap | Bonus section | `BONUS_2_heatmap` |
| **Bonus 3** | Three creative features (timing, email entropy KDE, tool×country interaction) | Bonus section | `BONUS_3_creative` |

---

## Code Structure

The notebook is split into the same parts as the assignment rubric (A → E + Bonus).
All reusable logic lives in `helpers.py` so nothing is copy-pasted across cells:

```
helpers.py
 ├── shannon_entropy(series)          # Shannon entropy of a categorical Series (bits)
 ├── zscore(series)                   # Population z-score, NaN-safe
 ├── iqr_upper_fence(series, k=1.5)   # Tukey upper fence Q3 + k*IQR
 ├── coefficient_of_variation(arr)    # std/mean, safe for empty/zero-mean arrays
 ├── styled_hist(series, ax, ...)     # Consistent histogram style across all plots
 ├── annotate_thresholds(ax, ...)     # Draws labelled vertical threshold lines
 ├── savefig(name)                    # Saves to ./figures/{name}.png at 150 dpi
 ├── pretty_print_section(name)       # Section banner in notebook output
 └── apply_heuristic_rules(df, ...)   # Applies R1–R4 detection rules, returns df + is_malicious
```

The notebook imports everything with `from helpers import *` at the top of the setup cell.

---

## AI Disclosure

**Tool used:** Claude (Anthropic) via Claude Code, April 2026.

### Prompts we used (in order)

**Prompt 1 — understanding the dataset before writing any code:**
> "I have a CSV with ~530K login attempts from a credential stuffing attack. Columns are:
> hashed_ip, email_hash, tool_id, network_id, network_type (77% missing), country,
> status_code, epoch (ms timestamp), risk_indication (vendor boolean label).
> Before I start coding, what are the most important things to check in EDA for this
> kind of dataset? What does each status code likely mean in the context of a
> credential stuffing attack? And why is network_type being mostly missing not
> necessarily a problem?"

**Prompt 2 — feature engineering design:**
> "For credential stuffing detection, I want to build IP-level, email-level, tool-level,
> and network-level feature tables using pandas groupby. What aggregations make the most
> sense at each level? For IP-level specifically: I want total attempts, unique emails,
> unique tools, success rate (status=200), 429 rate, 403 rate, and average login rate
> per second. Can you write a safe rate-per-second function that handles single-event
> IPs without returning inf or NaN? Also explain WHY IP-level is the natural unit and
> when it breaks down (residential proxies, NAT)."

**Prompt 3 — heuristic detection rules:**
> "Based on my EDA histograms, I want to design 4 detection rules:
> R1: IPs with >30 unique emails (knee I see in the log-log histogram)
> R2: tools with risk_ratio >= 0.95 AND volume >= 100 (to avoid small-sample noise)
> R3: IPs with rate_per_second > 1.0 (humans can't sustain this)
> R4: hosted-network IPs with >= 5 attempts (consumer logins don't come from datacenters)
> Implement this as apply_heuristic_rules() in helpers.py, return df with one boolean
> column per rule plus is_malicious = any(R1..R4). Then show me how to do a
> disagreement analysis vs the vendor risk_indication label."

**Prompt 4 — statistical anomaly detection:**
> "I need to implement three statistical methods on my ip_features table:
> 1. Z-scores (using scipy.stats.zscore) on ip_total_attempts, ip_unique_emails,
>    ip_rate_per_second, ip_unique_tools — then combine into a single anomaly_score
>    by clipping negatives to 0 and summing.
> 2. IQR upper fence (Tukey, k=1.5) on the same three continuous metrics, flag IPs
>    that are outliers on >= 2 of 3.
> 3. Shannon entropy per IP over email_hash and status_code distributions.
> For each method explain WHY it's appropriate here and WHY IQR is more robust than
> z-score when the data is heavily right-skewed (which credential stuffing data always is)."

**Prompt 5 — layered detection and refined label:**
> "Now I want to combine all four detection signals into a layered confidence score.
> Each IP gets a flag from: (a) Part C heuristics, (b) z-score anomaly_score > 4,
> (c) IQR 2-of-3 outlier, (d) email entropy > 4 bits AND >= 20 attempts.
> Count how many flags fire per IP, map to clean/low/medium/high/critical,
> and define is_malicious_refined = n_flags >= 2.
> Explain why requiring agreement from 2 independent methods reduces false positives
> (the FP rate becomes the product of individual FP rates, not the sum)."

**Prompt 6 — bonus: temporal burst detection:**
> "I want to detect bots by their inter-arrival time (IAT) regularity.
> Compute df['iat_ms'] = df.groupby('hashed_ip')['epoch'].diff(), then per-IP:
> mean IAT, std IAT, coefficient of variation (CV = std/mean).
> A bot firing at fixed intervals has CV ≈ 0; human traffic has CV >> 1.
> Flag IPs with CV < 0.3 AND mean_IAT < 1000ms AND at least 10 events.
> Plot mean_IAT (log x) vs CV, colour by is_malicious_refined, and highlight the
> mechanical bot region with a translucent rectangle."

### Working process

We read the assignment PDF and broke it into the same parts as the rubric (A → E + Bonus).
We designed the thresholds ourselves based on the EDA histograms (the knee at 30 emails/IP,
the 1 req/s rate threshold, the entropy > 4 bits cutoff) and used Claude to scaffold
the helper functions, write the matplotlib boilerplate, and double-check the pandas
aggregation syntax.

Every threshold was verified against the actual data distributions — we did not accept any
"magic number" without first running the plot and confirming the empirical break-point.
The markdown answers to each PDF question were written by us after running the cells
and reading the outputs.

### What we learned

One thing that surprised us early on was how badly z-scores behave on this kind of data.
We expected them to cleanly separate attackers from normal users, but because a handful
of very active bots inflate the mean and standard deviation, the threshold ends up moving
upward and many moderate attackers slip through. Switching to IQR (Q1 and Q3) fixed
this immediately — those percentiles don't care about extreme values in the tail, which
is exactly what you want when the "outliers" are what you're hunting for.

The entropy insight took a bit longer to click. At first we tried flagging IPs purely
by email entropy, but then we noticed some legitimate shared IPs (think: a university
Wi-Fi gateway) also had high email entropy simply because many real users were logging in
through the same exit node. The fix was combining entropy with volume: a real attacker
has both high entropy AND high volume, whereas a shared gateway has high entropy but
each individual user contributes only a few requests. Once we added the volume gate
the false positives dropped significantly.

The most important thing we learned about detection in general is that no single method
is reliable on its own. Our heuristic rules (Part C) caught the obvious attackers but
missed subtle ones. Z-scores flagged statistical anomalies but broke on skewed data.
IQR was more robust but could miss small systematic shifts. Entropy caught high fan-out
but was blind to low-volume attackers. The layered approach — requiring at least 2 out
of 4 methods to agree — turns out to be much stronger than any individual method,
because the false-positive rates multiply rather than add. If each method independently
mis-flags a legitimate IP 5% of the time, two methods doing so simultaneously is only
0.05 × 0.05 = 0.25%. That's the core intuition behind ensemble and layered detection
in real security systems.

Finally, the exercise with the vendor label (risk_indication) was eye-opening. It flags
~59% of all traffic as "risky," which is clearly not a usable ground truth — it's
essentially noise. Building our own detector and then comparing it back to the vendor
label showed us exactly where they disagreed and why. That's a skill we didn't expect
to practice in this assignment but it's probably the most practical thing we took away.
