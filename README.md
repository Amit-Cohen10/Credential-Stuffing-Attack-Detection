# HW1 — Credential Stuffing Detection

**Course:** 3917 — AI Techniques for Malware Detection  
**Semester:** 2 / 2026

---

## Files

| File | Description |
|---|---|
| `HW1_Credential_Stuffing.ipynb` | Main notebook — run top-to-bottom |
| `helpers.py` | Helper functions used by the notebook |
| `assignment.csv` | Input dataset (provided by the course) |
| `assignment_labeled.csv` | Output: original data + `is_malicious` + `is_malicious_refined` |
| `compromised_credentials.csv` | Output: emails with successful malicious logins (status=200 + malicious) |
| `figures/` | Saved PNG figures (auto-created when notebook runs) |

---

## How to Run

1. Place `assignment.csv` in the same directory as the notebook.
2. Install dependencies:
   ```
   pip install pandas numpy matplotlib seaborn scipy upsetplot nbformat
   ```
3. Open `HW1_Credential_Stuffing.ipynb` in Jupyter and run **Kernel → Restart & Run All**.  
   Total runtime: ~30 seconds on a standard laptop.

The notebook is self-contained and reproducible. Every random operation uses
`RANDOM_STATE = 42` (set in both `helpers.py` and the setup cell).

---

## Question Map

Every numbered question from the assignment PDF is answered in the notebook.
Use this table to jump directly to each answer.

| PDF Reference | Notebook Section | Cell Tag / Heading |
|---|---|---|
| **A.1 Q3** — what each status code likely represents | Part A → A.1 | `A1_status_dist` + markdown cell immediately below |
| **A.2 Q1** — exact time range | Part A → A.2 | `A2_time_range` + markdown cell |
| **A.2 Q2** — burst analysis (>2× median rate) | Part A → A.2 | `A2_per_minute` + markdown cell |
| **A.2 Q3** — split by risk_indication + warning about noise | Part A → A.2 | `A2_per_minute_split` + markdown cell |
| **A.3 Q1** — suspicious countries | Part A → A.3 | `A3_countries` + markdown cell |
| **A.3 Q2** — tool risk rates | Part A → A.3 | `A3_tools` + markdown cell |
| **A.3 Q3** — emails-per-IP threshold justification | Part A → A.3 | `A3_emails_per_ip` + markdown cell |
| **B.1 Q** — why IP level? When does it fail? | Part B → B.1 | Markdown cell after `B1_ip_features` |
| **B.4 Q2** — missing-value handling strategy | Part B → B.4 | Markdown after `B4_merge` |
| **B.4 Q3** — encoding strategy (one-hot vs label vs frequency) | Part B → B.4 | Same markdown cell |
| **C.1 Q1–Q3** — label quality: flag rate, cross-tab by status, per-tool | Part C → C.1 | `C1_label_quality`, `C1_tool_risk_bar` |
| **C.1 Q4** — why build our own detector even if vendor is perfect | Part C → C.1 | Markdown "Answer to C.1 Q4" |
| **C.2 Q1** — 3+ rules with thresholds and justifications | Part C → C.2 | Markdown "Answer to C.2 Q1" table |
| **C.2 Q2** — apply rules → `is_malicious` column | Part C → C.2 | `C2_apply` |
| **C.2 Q3** — compare to `risk_indication` + disagreement analysis | Part C → C.2 | `C2_compare`, `C2_disagree` + markdown |
| **C.2 Q4** — rule overlap visualisation | Part C → C.2 | `C2_upset` |
| **D.1 Q1–Q4** — z-score computation, counts at z>2 / z>3 | Part D → D.1 | `D1_zscores`, `D1_zscore_histograms` |
| **D.1 Q5** — normality check | Part D → D.1 | Markdown "Answer to D.1 Q5" |
| **D.2 Q1–Q3** — IQR fences, outlier counts, 2-of-3 rule | Part D → D.2 | `D2_iqr` |
| **D.2 Q4** — why IQR is more robust than z-score | Part D → D.2 | Markdown "Answer to D.2 Q4" |
| **D.3 Q1–Q4** — entropy computation, scatter, threshold choice | Part D → D.3 | `D3_entropy`, `D3_scatter` |
| **D.3 Q2** — meaning of high email entropy / status entropy | Part D → D.3 | Markdown "Answer to D.3 Q2" |
| **D.3 Q5** — entropy vs a 3-retry legitimate user | Part D → D.3 | Same markdown cell |
| **D.4 Q1–Q5** — layered confidence score, refined label | Part D → D.4 | `D4_layered`, `D4_plots` |
| **D.4 Q4** — FPs removed / FNs introduced by refinement | Part D → D.4 | Markdown "Answer to D.4 Q4" |
| **D.4 Q6** — why layered detection is more reliable | Part D → D.4 | Markdown "Answer to D.4 Q6" |
| **E.1** — attack summary table + timeline + top attackers | Part E → E.1 | `E1_summary`, `E1_timeline`, `E1_top_attackers` |
| **E.2** — source analysis by country, network type, tool | Part E → E.2 | `E2_country`, `E2_network_type`, `E2_tool_attack_rate` |
| **E.3** — compromised credentials + top-20 table + CSV export | Part E → E.3 | `E3_compromised` |
| **Bonus 1** — temporal burst detection (IAT + CV) | Bonus section | `BONUS_1_burst`, `BONUS_1_scatter` |
| **Bonus 2** — country × tool heatmap | Bonus section | `BONUS_2_heatmap` |
| **Bonus 3** — creative features (timing, email entropy KDE, tool×country) | Bonus section | `BONUS_3_creative` |

---

## AI Disclosure

- **Tool used:** Claude (Anthropic), via Claude Code, April 2026.
- **High-level prompt:** "Implement HW1 in a single notebook with rigorous EDA,
  feature engineering, heuristic + statistical detection, and a profiling report
  (see attached PDF). Comments must be student-style English, code split into
  helpers, every plot labelled, every PDF question answered with a cross-reference."
- **Working process:** I (the student) read the assignment, broke it into the same
  parts as the rubric (A→E + Bonus), drafted thresholds based on my own EDA,
  asked Claude to scaffold helpers and visualisations, then went through the
  notebook line by line to make sure I understand every threshold and every plot.
  All thresholds were re-tuned by me after running on the real data and re-reading
  the histograms in Part A.3 / B.1.
- **What I learned:** the difference between IQR and z-scores on heavy-tailed data;
  why entropy combined with volume is a more discriminating signal than either
  alone; why a "noisy label" (`risk_indication` at ~59 %) is essentially unusable
  as ground truth and why layered detection is the standard answer.
