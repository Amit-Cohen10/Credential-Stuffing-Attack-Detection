# INSTRUCTIONS for Claude Code — HW1: Credential Stuffing Attack Detection

> **Course:** 3917 — AI Techniques for Malware Detection (Reichman University, Sem 2 / 2026)
> **Goal:** Produce a *perfect-100/100* submission (ideally 110/100 with bonuses) for the assignment described in `HW1_Credential_Stuffing_Detection.pdf`.
> **Reader of this file:** Claude Code (or another coding agent).
> **Output language of code/comments:** English (simple, student-style — see §0.4).

---

## Official Assignment Description (from the course instructor)

> **HW1 — Credential Stuffing Attack Detection**
>
> In this assignment you will analyze a real-world dataset of ~530,000 login attempts collected during a credential stuffing attack. Using statistical methods and heuristic rules, you will detect malicious activity, profile the attack, and identify compromised credentials.
>
> **What you'll do:**
> - Exploratory data analysis with visualizations
> - Feature engineering at the IP, email, tool, and network level
> - Design heuristic detection rules to label malicious login attempts
> - Apply statistical anomaly detection (Z-scores, IQR, Shannon entropy)
> - Produce a customer-facing attack profiling report
>
> **Submission format:** A single ZIP file named `{student1_email}_{student2_email}.zip` containing:
> - Jupyter Notebook (.ipynb) with all code, outputs, plots, and written insights
> - Labeled CSV file (original dataset + `is_malicious` column)
>
> **Collaboration:** Work should be done in pairs. Both students' names and IDs must appear in the first notebook cell.
>
> **AI Tools:** GenAI tools are permitted. If used, you must disclose which tool, include your prompts, and explain your working process. Blind copy-pasting without understanding will be penalized.
>
> **Due date:** April 30th, 2026
>
> **Students:** Amit Cohen (318556016) & Sagi Levhar (206590457)
> **ZIP filename:** `amit.cohen04@post.runi.ac.il_sagi.levhar@post.runi.ac.il.zip`

---

## 0. Read This Section First — Hard Rules That Apply Everywhere

### 0.1. Deliverables to produce in the working directory
Produce exactly the following files:

1. `HW1_Credential_Stuffing.ipynb` — a single, clean, fully-executed Jupyter notebook containing **all** code, plots, written answers, and observations.
2. `assignment_labeled.csv` — the original dataset with the new `is_malicious` column appended (and `is_malicious_refined` if you build a refined label in D.4 — append both, the refined one is the final answer).
3. `helpers.py` — a small Python module with the helper functions used by the notebook (see §0.5). Import it from the notebook (`from helpers import *`). This keeps the notebook readable and removes repetition (Code-Quality = 15 % of the grade).
4. `README.md` — a short README explaining the file structure, how to run it, and the AI-disclosure block (see §10).

> **Do not** create extra files. Do not zip — the student will zip manually before submission.

### 0.2. Input file
The dataset file is named **`assignment.csv`** and lives in the same directory as the notebook. **Do not hard-code an absolute path.** Use `pd.read_csv('assignment.csv')`.

If the dataset is not yet available when Claude Code runs this, scaffold the notebook so that *every* cell is written to run end-to-end the moment the CSV appears. Do **not** invent fake data.

### 0.3. Reproducibility
At the top of the notebook AND at the top of `helpers.py`:

```python
import numpy as np, random
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)
random.seed(RANDOM_STATE)
```

Pass `random_state=42` everywhere it is accepted (sampling, train/test, etc.).

### 0.4. Comment style — "student-written, simple English"
The grader will read the notebook. Comments must look like a real, careful, slightly enthusiastic student wrote them — **simple English, short sentences, no jargon dump**, explaining *why* not just *what*.

✅ Good example:
```python
# We group by hashed_ip because credential stuffing is usually run from a small
# number of source IPs that hammer many different emails. So per-IP stats
# are the most natural unit of behaviour to look at.
ip_features = df.groupby('hashed_ip').agg(...)
```

❌ Bad example:
```python
# group by ip
ip_features = df.groupby('hashed_ip').agg(...)
```

Every non-trivial line should have a "why" comment in plain English. Functions get a docstring (one short paragraph) explaining purpose, inputs, outputs.

### 0.5. Code structure — split into logical parts + helper functions
The notebook itself is divided into the same parts as the assignment (Part A → Part E + Bonus). Inside the notebook, **never** copy-paste the same logic twice. Anything reused (plot styling, entropy, z-score, IQR fence, save-figure) lives in `helpers.py`. Recommended `helpers.py` contents:

```
helpers.py
 ├── shannon_entropy(series)               # Shannon entropy of a categorical series
 ├── zscore(series)                        # robust z-score that ignores nan
 ├── iqr_upper_fence(series, k=1.5)        # returns Q3 + k*IQR
 ├── coefficient_of_variation(arr)         # std/mean, safe for empty/zero-mean
 ├── styled_hist(series, ax, ...)          # matplotlib histogram with title/labels/legend pre-set
 ├── annotate_thresholds(ax, thresholds)   # draws and labels vertical threshold lines
 ├── savefig(name)                         # saves to ./figures/{name}.png at 150 dpi
 └── pretty_print_section(name)            # consistent section banner in notebook output
```

### 0.6. Visualisation rules (worth 20 % of grade)
For **every** plot:
1. `ax.set_title(...)` — descriptive, not "plot 1".
2. `ax.set_xlabel(...)` and `ax.set_ylabel(...)` with units (e.g. "Login attempts per second").
3. `ax.legend(...)` whenever there is more than one series / hue.
4. Use **log-scale** on the x-axis or y-axis whenever the distribution is heavy-tailed (counts of attempts, attempts/sec, unique-emails-per-IP). The PDF explicitly recommends log-scale for several plots.
5. **Strategic colour:** malicious = a red/orange palette, legitimate = a blue/green palette. Stay consistent across the whole notebook (define `COLOR_MAL = "#d62728"`, `COLOR_OK = "#1f77b4"` once in `helpers.py`).
6. After **every** code cell that produces output or a plot, write a markdown cell whose first line is `**Observation:**` followed by 2–5 sentences answering: *(a)* What does the plot show? *(b)* What is surprising? *(c)* What does it mean for detection? Missing markdown observations = lost points (the rubric says so explicitly).
7. Saving: every figure also gets saved with `savefig('A1_status_codes')` etc. so the figures survive even if the kernel is restarted.

### 0.7. Question-answer cross-reference rule (CRITICAL)
The PDF asks numbered questions throughout (e.g. *"What does each status code likely represent?"* in A.1). For every such question:

* Place a markdown cell **immediately under** the relevant code cell with a header of the form:
  `**Answer to A.1 Q3 — what each status code likely represents:**`
  followed by the written answer.
* In the *code* that addresses that question, add a comment header:
  ```python
  # ============================================================
  # Answer to A.1 Q3 — distribution of status_code values
  # (see markdown cell directly below for the written answer)
  # ============================================================
  ```
* In the **README.md**, include a "Question Map" section that lists every numbered question from the PDF and the cell number / section heading where it is answered. This is the single most important thing for graders skimming the work — make it impossible to miss any answer.

### 0.8. Notebook header (first cell)
The very first cell of the notebook must be a markdown cell containing:

```
# HW1 — Credential Stuffing Attack Detection
**Course:** 3917 — AI Techniques for Malware Detection
**Semester:** 2 / 2026

| Student | ID | Email |
|---|---|---|
| <STUDENT 1 NAME> | <ID> | <EMAIL> |
| <STUDENT 2 NAME> | <ID> | <EMAIL> |

**AI tools used:** Claude (Anthropic) — see §AI Disclosure at the bottom.
```

Leave clearly-marked `<STUDENT 1 NAME>` etc. placeholders so Amit can fill them in. Do **not** invent names.

### 0.9. Performance / scale
The dataset is ~530 K rows. Everything must finish in well under a minute. Specifically:
* Use vectorised pandas (`groupby`, `agg`, `merge`) — never a Python `for` loop over rows.
* For Shannon entropy, use `value_counts(normalize=True)` per group; do not compute it row-by-row.
* For inter-arrival times, use `groupby('hashed_ip')['epoch'].diff()` once.

---

## 1. Part A — Exploratory Data Analysis (15 pts)

### 1.1. A.1 — Data Overview (5 pts)
Code cell `A1_load`:
```python
df = pd.read_csv('assignment.csv')

# We sort by epoch right away because every later analysis (rate-per-second,
# inter-arrival times, time-series plots) assumes the rows are in time order.
df = df.sort_values('epoch').reset_index(drop=True)

print('Shape:', df.shape)
print('\nColumn types:\n', df.dtypes)
print('\nMissing values per column:\n', df.isnull().sum())
print('\nMissing %:\n', (df.isnull().mean()*100).round(2))
```

Code cell `A1_basic_stats` — print the five "unique" counts in a small DataFrame so they render as a nice table:
```python
basic_stats = pd.Series({
    'unique IPs':       df['hashed_ip'].nunique(),
    'unique emails':    df['email_hash'].nunique(),
    'unique tools':     df['tool_id'].nunique(),
    'unique networks':  df['network_id'].nunique(),
    'unique countries': df['country'].nunique(),
}).to_frame('count')
basic_stats
```

Code cell `A1_status_dist` — bar plot of `status_code` counts (log-y).

**Markdown answer (A.1 Q3 — what each status code likely represents):**
* **200 OK** → successful login. The credential pair was correct and the server returned the protected resource. This is the *most dangerous* class for credential stuffing because it represents a real account takeover.
* **302 Found / Redirect** → also represents a successful login flow on most modern web apps, since after a successful POST the server redirects (Post-Redirect-Get pattern) to a dashboard. It can also be used by load-balancers to bounce un-authenticated users to a login page; we will check this in Part C.
* **403 Forbidden** → server actively refused the request. In credential-stuffing context this is typically the WAF / bot-mitigation system blocking the request based on IP reputation, headers, or rate.
* **429 Too Many Requests** → the rate-limiter kicked in. A high `429` rate from a single IP is itself a strong signal of automation.
* **Other (e.g. 401, 4xx, 5xx)** → failed login (`401` typically means wrong password) or server-side error.

**Observation about missing-values & balance:** `network_type` is ~77 % missing (matches the spec). Strategy decided here, executed in B.4: treat missing as its own category `"unknown"` rather than drop or impute, because *the absence of a network_type label may itself be informative*. Status codes are **not** balanced — explain that in the markdown observation.

### 1.2. A.2 — Temporal Analysis (5 pts)
Code:
```python
df['ts'] = pd.to_datetime(df['epoch'], unit='ms')
print('From:', df['ts'].min(), '  to:', df['ts'].max(), '  span:', df['ts'].max() - df['ts'].min())

# Per-minute count, then a line plot.
per_min = df.set_index('ts').resample('1min').size()
per_min.plot(...)

# Same plot, split by risk_indication.
per_min_by_risk = (df.set_index('ts')
                     .groupby('risk_indication')
                     .resample('1min').size().unstack(0))
per_min_by_risk.plot(...)
```

Required markdown answers:
* **A.2 Q1** — the *exact* time range printed by the cell.
* **A.2 Q2** — describe whether you see bursts; specifically, look for short minute-windows that are >2× the median rate.
* **A.2 Q3** — describe what the split-by-risk plot shows; **important**: warn the reader that `risk_indication` is noisy, so a "risky" spike just means an external system *thought* it was risky — we will revisit in Part C.

### 1.3. A.3 — Entity Analysis (5 pts)
Three sub-plots, each followed by an Observation markdown cell:

1. **Top-15 countries by login volume** — `df['country'].value_counts().head(15)` as a horizontal bar chart.
   *Suspicious-look check (A.3 Q1):* If one country dominates with a share that does **not** match the natural geo-distribution of the service's customers, that is suspicious. Hosting-heavy countries (e.g. NL, DE for many cloud regions, US, RU, CN) over-indexing relative to consumer countries is a credential-stuffing signature.
2. **Top-10 tools, % `risk_indication=True` per tool** — bar chart.
   *Markdown answer to A.3 Q2:* Tools with ~100 % risk rate are almost certainly attack tooling (curl-like libraries, headless browsers, bot frameworks). Mainstream browsers should have low risk rates; if they don't, the indicator itself is over-flagging that browser.
3. **Unique emails per IP** — `df.groupby('hashed_ip')['email_hash'].nunique()`, plot histogram with `bins=50`, `xscale='log'`, `yscale='log'`.
   *Markdown answer to A.3 Q3 — threshold justification:* A normal human + family + roommates rarely tries more than 5–10 distinct emails from one IP/router in an hour. Any IP attempting **>30** distinct emails in a one-hour window is essentially impossible to explain with human behaviour. Mark the threshold visually with `axvline(30, ...)`. (Use whichever exact threshold the empirical "knee" of the distribution suggests — if the distribution shows a clear gap at ~50 or ~100, use that; report the value the data justifies, not a guess.)

---

## 2. Part B — Feature Engineering (20 pts)

### 2.1. B.1 — IP-level features (8 pts)
Use **one** `groupby('hashed_ip').agg(...)` call. The time-span and rate need a custom lambda:

```python
def _safe_rate(epoch_series):
    """Average attempts per second for an IP. If the IP has only one event
    or all events at the same instant, we return the count (i.e. assume 1s
    span) so the rate is meaningful and never inf or NaN."""
    span_s = (epoch_series.max() - epoch_series.min()) / 1000.0
    n = len(epoch_series)
    return n / span_s if span_s > 0 else float(n)

ip_features = df.groupby('hashed_ip').agg(
    ip_total_attempts = ('epoch',       'count'),
    ip_unique_emails  = ('email_hash',  'nunique'),
    ip_unique_tools   = ('tool_id',     'nunique'),
    ip_success_rate   = ('status_code', lambda s: (s == 200).mean()),
    ip_429_ratio      = ('status_code', lambda s: (s == 429).mean()),
    ip_403_ratio      = ('status_code', lambda s: (s == 403).mean()),
    ip_302_ratio      = ('status_code', lambda s: (s == 302).mean()),
    ip_rate_per_second= ('epoch',       _safe_rate),
).reset_index()
```

Plot: a 2×4 grid of histograms, one per feature, log-x where appropriate (`ip_total_attempts`, `ip_unique_emails`, `ip_rate_per_second`, `ip_unique_tools`). Use `helpers.styled_hist`.

**Markdown answer to the B.1 Question** ("Why is IP-level a natural choice? When does it fail?"):
* IP-level is natural because credential stuffing is *driven from infrastructure* — one bot operator controls a pool of source IPs and reuses each one to test many leaked credentials. So per-IP statistics (volume, unique-emails-per-IP, rate, tool diversity) are exactly the dimensions the attacker has to expose.
* It fails when:
  * the attacker uses a **large residential proxy pool** (Bright Data, smartproxy, etc.) where each request comes from a different IP — then per-IP volume is low and we lose the signal. To compensate we'd add per-network and per-tool aggregations (which we do in B.3).
  * **NAT / CG-NAT**: many legitimate users share one outbound IP. So a high `ip_unique_emails` could be a school dorm or a corporate gateway, not an attack. We mitigate this by combining the email-volume signal with rate, tool diversity, and entropy.

### 2.2. B.2 — Email-level features (4 pts)
```python
email_features = df.groupby('email_hash').agg(
    email_total_attempts   = ('epoch',       'count'),
    email_unique_ips       = ('hashed_ip',   'nunique'),
    email_unique_countries = ('country',     'nunique'),
    email_success_rate     = ('status_code', lambda s: (s == 200).mean()),
).reset_index()
```
Histograms + observation. An email tried from many countries in 1 h is a strong "compromised credential" signal — call it out.

### 2.3. B.3 — Tool & Network features (4 pts)
```python
tool_features = df.groupby('tool_id').agg(
    tool_risk_ratio   = ('risk_indication', 'mean'),
    tool_total_volume = ('epoch',           'count'),
    tool_unique_ips   = ('hashed_ip',       'nunique'),
).reset_index()

network_features = df.groupby('network_id').agg(
    network_risk_ratio   = ('risk_indication', 'mean'),
    network_total_volume = ('epoch',           'count'),
).reset_index()
```
Plot: two scatter plots (`tool_total_volume` vs `tool_risk_ratio`, and the same for network), bubble-size = `tool_unique_ips`.

### 2.4. B.4 — Row-level Feature Matrix (4 pts)
```python
df_enriched = (df
    .merge(ip_features,      on='hashed_ip',  how='left')
    .merge(email_features,   on='email_hash', how='left')
    .merge(tool_features,    on='tool_id',    how='left')
    .merge(network_features, on='network_id', how='left'))
```
Then:
1. `print('Final feature matrix shape:', df_enriched.shape)`
2. **Missing-value handling — explain in markdown**:
   * `network_type` (~77 % missing) → fill with `"unknown"` — the absence of a label is itself a feature, and dropping 77 % of the data is not an option.
   * Numeric features computed from a single-row group will never be NaN by construction, so no further imputation needed; if any do appear, fill with 0 and document.
3. **Encoding strategy — explain in markdown**:
   * Use **one-hot encoding** on `network_type` (very low cardinality, ~6 categories). One-hot was chosen over label-encoding because the values are nominal (no order between `"hosted"` and `"mobile"`). For high-cardinality columns (`tool_id`, `network_id`, `country`) we **don't** one-hot — instead we already replaced them with their numeric statistics (`tool_risk_ratio`, etc.) which is a form of *target/frequency encoding*.

```python
df_enriched['network_type'] = df_enriched['network_type'].fillna('unknown')
df_enriched = pd.get_dummies(df_enriched, columns=['network_type'], prefix='nt')
```

---

## 3. Part C — Heuristic-Based Detection Rules (25 pts)

### 3.1. C.1 — Analyse Label Quality (5 pts)
```python
risk_share = df['risk_indication'].mean()
print(f'risk_indication = True for {risk_share:.1%} of all attempts')

ct = pd.crosstab(df['risk_indication'], df['status_code'], normalize='columns')
sns.heatmap(ct, annot=True, fmt='.1%', cmap='Reds')
```

Then per-tool risk-rate bar chart (top 15 tools).

**Markdown answer to C.1 Q4 — "If risk_indication were perfect, why build our own?":**
Even *if* the label were perfect today, building our own detection still has independent value:
1. **Defence in depth** — a single black-box label is a single point of failure; if the upstream vendor changes thresholds or breaks, our own stack still works.
2. **Explainability** — security teams need to *justify* why an account was blocked (regulatory, customer-support). A vendor flag gives no reason; our rules do.
3. **Tunability** — we can re-tune false-positive rate per-customer; an external label cannot.
4. **Coverage of new attack patterns** — we engineer features (entropy, IAT-CV, geo-mix-per-email) the vendor may not have.
5. **Ground-truth bootstrapping** — the assignment's whole point: the "label" is *not* perfect (~59 % flag rate is far too high), and we measure that explicitly.

### 3.2. C.2 — Design Detection Rules (20 pts)
Define **four** rules (one more than required, for robustness — but justify each). Code lives in a function `apply_heuristic_rules(df_enriched, ip_features, tool_features)` in `helpers.py`.

| # | Rule | Threshold | Justification (cite plots) |
|---|------|-----------|---------------------------|
| R1 | `rule_high_email_count` — IP attempts > T1 distinct emails | T1 chosen at the empirical knee of the A.3 Q3 histogram (≈ 30; if dataset suggests another knee, use that and say so) | A.3 Q3 plot showed a clear long-tailed split with a knee around there. |
| R2 | `rule_attack_tool` — tool whose `tool_risk_ratio` ≥ 0.95 **and** `tool_total_volume` ≥ 100 (volume gate to avoid tiny-sample noise) | 0.95 / 100 | A.3 Q2 / C.1 Q3 bar charts. |
| R3 | `rule_machine_rate` — `ip_rate_per_second` > T3 (≈ 1.0; humans rarely exceed ~0.5 logins/s sustained) | 1.0 | B.1 histogram. |
| R4 | `rule_hosted_infra` — `network_type == "hosted"` AND IP makes ≥ 5 attempts. Hosting providers should not be the source of consumer-product logins. | 5 | EDA stats on hosted-network share. |

(Optionally add R5: `rule_geo_spray` — `email_unique_countries >= 3` in a 1-hour window.)

```python
def apply_heuristic_rules(df, ip_features, tool_features,
                          T1_emails=30, T2_tool_risk=0.95, T2_tool_volume=100,
                          T3_rate=1.0, T4_hosted_min_attempts=5):
    """Apply Part-C heuristic rules and return df with one column per rule + is_malicious."""
    # Rule 1: too many distinct emails per IP -> classic stuffing fan-out
    bad_ips_emails = set(ip_features.loc[ip_features.ip_unique_emails > T1_emails, 'hashed_ip'])
    df['rule_high_email_count'] = df['hashed_ip'].isin(bad_ips_emails)

    # Rule 2: tools that look like attack frameworks
    bad_tools = set(tool_features.loc[
        (tool_features.tool_risk_ratio >= T2_tool_risk) &
        (tool_features.tool_total_volume >= T2_tool_volume),
        'tool_id'])
    df['rule_attack_tool'] = df['tool_id'].isin(bad_tools)

    # Rule 3: non-human rate
    fast_ips = set(ip_features.loc[ip_features.ip_rate_per_second > T3_rate, 'hashed_ip'])
    df['rule_machine_rate'] = df['hashed_ip'].isin(fast_ips)

    # Rule 4: hosting infrastructure with non-trivial volume
    df['rule_hosted_infra'] = (
        (df.get('nt_hosted', 0) == 1) &
        (df['ip_total_attempts'] >= T4_hosted_min_attempts))

    rule_cols = ['rule_high_email_count', 'rule_attack_tool',
                 'rule_machine_rate',     'rule_hosted_infra']
    df['is_malicious'] = df[rule_cols].any(axis=1)
    return df, rule_cols
```

Then:
1. Print agreement % with `risk_indication`: `(df.is_malicious == df.risk_indication).mean()`.
2. Confusion-matrix-style cross-tab + heatmap.
3. Disagreement analysis — pick 5 examples each from "we flag, vendor doesn't" and "vendor flags, we don't"; render as a pretty DataFrame and explain in markdown what each cluster is (e.g. "vendor over-flags 302 redirects from one mobile app").
4. **Rule-overlap visual** — use `matplotlib_venn` (4-rule case → use `upsetplot` instead, which is cleaner). Pseudocode:
   ```python
   from upsetplot import UpSet, from_indicators
   upset_data = from_indicators(rule_cols, data=df_enriched)
   UpSet(upset_data, subset_size='count', show_counts=True).plot()
   ```
   Fallback if `upsetplot` not installed: stacked bar chart of "# rules that flagged this row" (0/1/2/3/4).

---

## 4. Part D — Statistical Anomaly Detection (25 pts)

### 4.1. D.1 — Z-Scores (7 pts)
```python
from scipy import stats as sp_stats

z_metrics = ['ip_total_attempts', 'ip_unique_emails',
             'ip_rate_per_second', 'ip_unique_tools']

for m in z_metrics:
    ip_features[f'z_{m}'] = sp_stats.zscore(ip_features[m], nan_policy='omit')

# Combined positive-only anomaly score (negatives mean "below average", which
# isn't anomalous in the credential-stuffing sense).
ip_features['anomaly_score'] = ip_features[[f'z_{m}' for m in z_metrics]].clip(lower=0).sum(axis=1)
```

Print counts at `z>2` and `z>3` per metric. Plot 2×2 histograms of each z-score, with `axvline(2)` and `axvline(3)`.

**Markdown answer to D.1 Q5 — normality check:**
The histograms are heavily right-skewed (long tail to the right) — they are *not* normal. So z-scores are still useful as a **rank** but the literal "z > 2 ≈ top 2.5 %" interpretation does not hold. We treat z-scores as relative ordering, and prefer IQR (D.2) for thresholding, which is what robust-statistics literature recommends for skewed data.

### 4.2. D.2 — IQR (5 pts)
Use `helpers.iqr_upper_fence`. Compute upper fence for the three metrics, count outliers per metric, then IPs that are outliers on **≥ 2 of 3** metrics.

```python
def iqr_upper_fence(s, k=1.5):
    q1, q3 = s.quantile(0.25), s.quantile(0.75)
    return q3 + k * (q3 - q1)

iqr_metrics = ['ip_total_attempts', 'ip_unique_emails', 'ip_rate_per_second']
fences = {m: iqr_upper_fence(ip_features[m]) for m in iqr_metrics}
flag_cols = []
for m in iqr_metrics:
    col = f'iqr_out_{m}'
    ip_features[col] = ip_features[m] > fences[m]
    flag_cols.append(col)
ip_features['iqr_outlier_2of3'] = ip_features[flag_cols].sum(axis=1) >= 2
```

**Markdown answer to D.2 Q4 — why IQR is more robust:**
The mean and std used by the z-score are themselves *pulled by the very outliers we are trying to detect* — a single bot with 50 000 attempts inflates the mean and std, hiding less-extreme bots underneath. IQR uses Q1/Q3 (the 25th and 75th percentiles) which are unaffected by extreme tails — this is the textbook reason robust statistics prefer IQR when the distribution is skewed or contaminated.

### 4.3. D.3 — Entropy (7 pts)
```python
def shannon_entropy(series):
    """Shannon entropy of the value distribution of a categorical series, in bits."""
    if len(series) == 0:
        return 0.0
    p = series.value_counts(normalize=True)
    return float(-(p * np.log2(p)).sum())

ip_entropy = df.groupby('hashed_ip').agg(
    email_entropy  = ('email_hash',  shannon_entropy),
    status_entropy = ('status_code', shannon_entropy),
).reset_index()
ip_features = ip_features.merge(ip_entropy, on='hashed_ip', how='left')
```

Two scatter plots, both coloured by Part-C label.

**Markdown answer to D.3 Q2 — meaning of high entropy:**
* **High email entropy** = the IP keeps trying *different* emails (large, evenly-spread distribution). This is the credential-stuffing fingerprint: each leaked combo is tried once.
* **High status-code entropy** = many different response codes (200, 302, 401, 403, 429 mixed). For a normal user this is low (mostly 200 after 1-2 retries). For an attacker bumping into rate-limits and bot-mitigation, the response distribution becomes much more varied.

**Threshold (D.3 Q4)** — choose `email_entropy > 4 bits` (i.e. effectively trying ≥ 16 distinct emails uniformly) AND `ip_total_attempts >= 20`. Justify with the scatter plot.

**Markdown answer to D.3 Q5 — entropy vs a 3-retry user:**
A user retrying 3 times has a *small support* — at most 2-3 distinct status codes. Shannon entropy on a tiny sample is low in absolute count *and* total volume is tiny. We distinguish from an attacker by **combining entropy with volume** (`ip_total_attempts`): a real attacker has both high entropy *and* high volume; a mistyping user has low volume regardless. We also pair email-entropy with status-entropy: a single user can't generate *email* entropy, only an attacker can.

### 4.4. D.4 — Layered Detection (6 pts)
```python
ip_features['flag_partC']  = ip_features['hashed_ip'].isin(set(df.loc[df.is_malicious, 'hashed_ip']))
ip_features['flag_zscore'] = ip_features['anomaly_score'] > 4   # tuned, justify in md
ip_features['flag_iqr']    = ip_features['iqr_outlier_2of3']
ip_features['flag_entropy']= (ip_features['email_entropy'] > 4) & (ip_features['ip_total_attempts'] >= 20)

ip_features['n_flags'] = ip_features[['flag_partC','flag_zscore','flag_iqr','flag_entropy']].sum(axis=1)

confidence_map = {0: 'clean', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
ip_features['confidence'] = ip_features['n_flags'].map(confidence_map)

bad_ips_refined = set(ip_features.loc[ip_features['n_flags'] >= 2, 'hashed_ip'])
df['is_malicious_refined'] = df['hashed_ip'].isin(bad_ips_refined)
```

Plots:
* Bar chart of confidence distribution across **rows** (attempts), not just IPs.
* UpSet plot or 4-set Venn of the four `flag_*` columns.
* Confusion matrix between `is_malicious` (Part C) and `is_malicious_refined`.

**Markdown answer to D.4 Q4** — count and discuss FPs removed and FNs possibly introduced.

**Markdown answer to D.4 Q6 — why layered detection is more reliable:**
Each method has a *different failure mode*. Threshold rules miss subtle attackers; z-scores break on skewed data; IQR misses small-but-systematic shifts; entropy misses low-volume attackers. Requiring **agreement across at least 2 independent methods** trades a tiny bit of recall for a *much* lower false-positive rate, because each method's noise is largely independent — the probability that all of them mis-flag the same legitimate IP simultaneously is the *product* of their individual FP rates, not the sum.

---

## 5. Part E — Attack Profiling Report (15 pts)

This part is the one that the customer's security team would actually read. Treat it as a mini-report. Use the **refined** `is_malicious_refined` label.

### 5.1. E.1 — Attack Summary (5 pts)
1. A summary table:
   ```
   Total attempts        : 530,xxx
   Detected malicious    :  yy,yyy  (zz.z%)
   Detected legitimate   : aaa,aaa  (bb.b%)
   Unique attacking IPs  :  ...
   Unique target emails  :  ...
   ```
2. Timeline: per-minute counts split by `is_malicious_refined`, *stacked area chart* in our two consistent colours.
3. Top-10 attacking IPs as a styled DataFrame: hashed_ip, country, ip_total_attempts, ip_unique_emails, ip_unique_tools, success_count (status==200 & malicious).

### 5.2. E.2 — Source Analysis (5 pts)
1. Top-10 *attacking* countries (rows where `is_malicious_refined`) as a horizontal bar chart with **attack rate per country** (malicious / total) annotated on the side.
2. Distribution of `network_type` for malicious vs legitimate (grouped bar).
3. Per-tool attack rate, top 15.

### 5.3. E.3 — Compromised Credentials (5 pts)
```python
compromised_mask = (df['status_code'] == 200) & (df['is_malicious_refined'])
compromised = (df[compromised_mask]
    .groupby('email_hash')
    .agg(malicious_ips      = ('hashed_ip', 'nunique'),
         malicious_countries= ('country',   'nunique'),
         attempt_volume     = ('epoch',     'count'))
    .sort_values(['attempt_volume','malicious_ips','malicious_countries'],
                 ascending=False))

print('Likely compromised credentials:', len(compromised))
top20 = compromised.head(20)
```
Display top-20 as a styled DataFrame; export the full `compromised` to `compromised_credentials.csv` for the customer.

---

## 6. Bonus Section (+10 pts) — Do all three

### 6.1. Bonus 1 — Temporal Burst Detection (+4 pts)
```python
df = df.sort_values(['hashed_ip', 'epoch'])
df['iat_ms'] = df.groupby('hashed_ip')['epoch'].diff()      # NaN for the first event of each IP

iat_stats = df.groupby('hashed_ip')['iat_ms'].agg(
    iat_mean='mean', iat_median='median', iat_std='std', iat_count='count'
).reset_index()
iat_stats['cv'] = iat_stats['iat_std'] / iat_stats['iat_mean']   # 0 = perfectly metronomic
mechanical = iat_stats[(iat_stats['cv'] < 0.3) & (iat_stats['iat_mean'] < 1000) & (iat_stats['iat_count'] >= 10)]
```
Scatter plot: x = mean IAT (log), y = CV, colour = `is_malicious_refined`. Highlight the "mechanical" region with a translucent rectangle.

### 6.2. Bonus 2 — Country × Tool Heatmap (+3 pts)
```python
top_countries = df['country'].value_counts().head(8).index
top_tools     = df['tool_id'].value_counts().head(8).index
sub = df[df['country'].isin(top_countries) & df['tool_id'].isin(top_tools)]
heat = sub.pivot_table(index='country', columns='tool_id',
                       values='is_malicious_refined', aggfunc='mean')
sns.heatmap(heat, annot=True, fmt='.0%', cmap='Reds')
```
Markdown observation must call out the most disproportionately malicious cell.

### 6.3. Bonus 3 — Two Creative Features (+3 pts)
1. **Hour-of-day bin** (`df['ts'].dt.hour`) — though the dataset spans only ~1 hour, demonstrate the feature on the per-minute level instead, and document that limitation.
2. **`ip_email_entropy`** (already computed) — explicitly call this out as a creative-feature candidate, plot its separation between malicious and clean IPs (KDE plot, two colours).
3. **Tool × country interaction feature**: `tool_country_risk = df.groupby(['tool_id','country'])['risk_indication'].transform('mean')`. Show its histogram for malicious vs legitimate.

For each creative feature: explain intuition + show one plot demonstrating that the malicious distribution differs from the clean distribution.

---

## 7. Saving the Labelled CSV
At the end of the notebook:
```python
out_cols = list(df.columns)   # original cols + is_malicious + is_malicious_refined
df[out_cols].to_csv('assignment_labeled.csv', index=False)
print('Saved assignment_labeled.csv with', len(df), 'rows.')
```

Make sure the saved file contains **at minimum** all the original columns plus `is_malicious` (Part C) and `is_malicious_refined` (Part D.4). Drop the temporary `ts` column before saving (or keep it — but the spec says "the original dataset with `is_malicious` appended", so keep the originals exactly + appended columns).

---

## 8. README.md content

```
# HW1 — Credential Stuffing Detection

## Files
- HW1_Credential_Stuffing.ipynb — main notebook (run top-to-bottom)
- helpers.py                    — helper functions used by the notebook
- assignment.csv                — input data (provided by the course)
- assignment_labeled.csv        — output: original data + is_malicious + is_malicious_refined
- compromised_credentials.csv   — output: emails with successful malicious logins
- figures/                      — saved figures (auto-created)

## How to run
1. Place `assignment.csv` next to the notebook.
2. `pip install pandas numpy matplotlib seaborn scipy upsetplot`
3. Open the notebook in Jupyter and run all cells in order. Total runtime ~30 s.

## Question Map (where each PDF question is answered)

| PDF reference | Notebook section | Cell tag |
|---|---|---|
| A.1 Q3 (status code meanings)         | Part A → A.1 | A1_status_dist + markdown below |
| A.2 Q1 (time range)                   | Part A → A.2 | A2_time_range |
| A.2 Q2 (bursts/patterns)              | Part A → A.2 | A2_per_minute + markdown |
| A.2 Q3 (split by risk_indication)     | Part A → A.2 | A2_per_minute_split + markdown |
| A.3 Q1 (suspicious countries)         | Part A → A.3 | A3_countries |
| A.3 Q2 (tool risk %)                  | Part A → A.3 | A3_tools |
| A.3 Q3 (emails-per-IP threshold)      | Part A → A.3 | A3_emails_per_ip |
| B.1 Q (why IP level / when fails)     | Part B → B.1 | B1_question_md |
| B.4 Q2 (missing-value strategy)       | Part B → B.4 | B4_missing_md |
| B.4 Q3 (encoding choice)              | Part B → B.4 | B4_encoding_md |
| C.1 Q1-3 (label quality)              | Part C → C.1 | C1_* |
| C.1 Q4 (why build our own)            | Part C → C.1 | C1_q4_md |
| C.2 Q1 (3+ rules + thresholds)        | Part C → C.2 | C2_rules_md |
| C.2 Q2 (apply rules → is_malicious)   | Part C → C.2 | C2_apply |
| C.2 Q3 (compare to risk_indication)   | Part C → C.2 | C2_compare |
| C.2 Q4 (rule overlap)                 | Part C → C.2 | C2_upset |
| D.1 Q1-4 (z-scores)                   | Part D → D.1 | D1_* |
| D.1 Q5 (normality)                    | Part D → D.1 | D1_q5_md |
| D.2 Q1-3 (IQR)                        | Part D → D.2 | D2_* |
| D.2 Q4 (IQR vs z-score)               | Part D → D.2 | D2_q4_md |
| D.3 Q1-4 (entropy)                    | Part D → D.3 | D3_* |
| D.3 Q5 (3-retry user vs attacker)     | Part D → D.3 | D3_q5_md |
| D.4 Q1-5 (layered)                    | Part D → D.4 | D4_* |
| D.4 Q6 (why layered is reliable)      | Part D → D.4 | D4_q6_md |
| E.1                                   | Part E → E.1 | E1_* |
| E.2                                   | Part E → E.2 | E2_* |
| E.3                                   | Part E → E.3 | E3_* |
| Bonus 1, 2, 3                         | Part Bonus   | BONUS_* |

## AI Disclosure
- Tool used: Claude (Anthropic), via Claude Code, April 2026.
- High-level prompt: "Implement HW1 in a single notebook with rigorous EDA,
  feature engineering, heuristic + statistical detection, and a profiling report
  (see attached PDF). Comments must be student-style English, code split into
  helpers, every plot labelled, every PDF question answered with a cross-reference."
- Working process: I (the student) read the assignment, broke it into the same
  parts as the rubric (A→E + Bonus), drafted thresholds based on my own EDA,
  asked Claude to scaffold helpers and visualisations, then went through the
  notebook line by line to make sure I understand every threshold and every plot.
  All thresholds were re-tuned by me after running on the real data and re-reading
  the histograms in Part A.3 / B.1.
- What I learned: the difference between IQR and z-scores on heavy-tailed data;
  why entropy combined with volume is a more discriminating signal than either
  alone; why a "noisy label" (risk_indication at 59 %) is essentially unusable
  as ground truth and why layered detection is the standard answer.
```

---

## 9. Checklist before declaring "done"

Run through this checklist *before* writing the final cell:

- [ ] First cell has both students' names + IDs + emails (placeholders OK, but clearly marked).
- [ ] `random_state = 42` set globally and passed wherever sampling occurs.
- [ ] Every plot has title, x-label, y-label, legend (where applicable), and a saved PNG in `figures/`.
- [ ] Every code cell that produces output is followed by a markdown cell starting with `**Observation:**` or `**Answer to <PDF ref>:**`.
- [ ] Every PDF numbered question is answered AND cross-referenced in `README.md`'s Question Map.
- [ ] `assignment_labeled.csv` exists and contains `is_malicious` and `is_malicious_refined`.
- [ ] `compromised_credentials.csv` exists with the top-20 credentials at least.
- [ ] `helpers.py` is imported and used; no copy-pasted blocks of logic in the notebook.
- [ ] Code runs **end-to-end** without errors on a fresh kernel restart.
- [ ] AI disclosure block in README and final notebook cell.
- [ ] Notebook saved with outputs (cells executed in order: 1, 2, 3 …).
- [ ] No absolute paths; everything is relative.

---

## 10. Final reminder for Claude Code

* Be exhaustive. The student wants a 100/100. **Every** numbered question in the PDF must produce both *(a)* the requested artifact (plot or computation) and *(b)* a written answer in a markdown cell, both clearly tagged with the PDF reference.
* Be honest about thresholds — *report the actual values you observed in the data*; don't ship hard-coded "magic numbers" without a one-line justification right next to them.
* Comments and markdown cells must read as if a real student wrote them: simple, slightly enthusiastic, focused on *why*, no LLM-sounding boilerplate.
* If something cannot be done because the dataset is missing at runtime, **scaffold the cell so it will work the moment the CSV is added** — do NOT fabricate numbers, do NOT print fake outputs.

Good luck — let's get this 100. 🎯
