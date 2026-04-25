"""
helpers.py — shared utilities for HW1: Credential Stuffing Attack Detection
Course 3917, Reichman University, Sem 2 / 2026

All functions live here so the notebook stays readable and we never
copy-paste the same logic twice. Import with: from helpers import *
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import random

# ── Reproducibility seed ────────────────────────────────────────────────────
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)
random.seed(RANDOM_STATE)

# ── Consistent colour palette across ALL plots ───────────────────────────────
# Malicious traffic gets a warm red/orange, legitimate gets a cool blue/green.
COLOR_MAL = "#d62728"   # red  — malicious
COLOR_OK  = "#1f77b4"   # blue — legitimate


# ── Statistical helpers ──────────────────────────────────────────────────────

def shannon_entropy(series):
    """
    Shannon entropy (in bits) of the value distribution of a categorical
    (or discrete numeric) pandas Series.

    Args:
        series: a pandas Series of categorical values.

    Returns:
        float — entropy in bits (0 = all same value, high = very diverse).
    """
    if len(series) == 0:
        return 0.0
    # value_counts(normalize=True) gives us the probability of each category
    # without needing a slow Python loop over the group.
    p = series.value_counts(normalize=True)
    return float(-(p * np.log2(p + 1e-12)).sum())


def zscore(series):
    """
    Standard z-score for a numeric pandas Series, safely ignoring NaN.
    Z = (x - mean) / std.  Returns NaN where input is NaN.

    We use the population std (ddof=0) to stay consistent with scipy.stats.zscore.
    """
    mean = series.mean(skipna=True)
    std  = series.std(ddof=0, skipna=True)
    if std == 0 or pd.isna(std):
        # Every value is identical — no variation, so z-score is 0.
        return pd.Series(np.zeros(len(series)), index=series.index)
    return (series - mean) / std


def iqr_upper_fence(s, k=1.5):
    """
    Classic Tukey upper fence: Q3 + k * IQR.

    IQR-based outlier detection is more robust than z-scores on skewed data
    because Q1/Q3 are not pulled by extreme values the way the mean and std are.

    Args:
        s  : numeric pandas Series.
        k  : multiplier (default 1.5 = standard Tukey; 3.0 = extreme outlier).

    Returns:
        float — the upper fence value.
    """
    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    return q3 + k * (q3 - q1)


def coefficient_of_variation(arr):
    """
    Coefficient of variation = std / mean (dimensionless).

    CV close to 0 means the inter-arrival times are nearly metronomic
    (a bot firing at a fixed interval). CV >> 1 means bursty/human traffic.

    Returns 0 if the mean is zero or the array is empty to avoid division errors.
    """
    arr = np.asarray(arr, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0 or np.mean(arr) == 0:
        return 0.0
    return float(np.std(arr) / np.mean(arr))


# ── Plot helpers ─────────────────────────────────────────────────────────────

def styled_hist(series, ax, title="", xlabel="", ylabel="Count",
                color=None, log_x=False, log_y=False, bins=50, label=None):
    """
    Draw a nicely formatted histogram on the given Axes object.

    Args:
        series : pandas Series of numeric values to histogram.
        ax     : matplotlib Axes to draw on.
        title  : plot title (should be descriptive, not 'Plot 1').
        xlabel : x-axis label, including units if any.
        ylabel : y-axis label.
        color  : bar fill colour (defaults to COLOR_OK).
        log_x  : if True, use a log scale on the x-axis.
        log_y  : if True, use a log scale on the y-axis.
        bins   : number of histogram bins.
        label  : legend label for this series (optional).
    """
    if color is None:
        color = COLOR_OK

    # For log-x histograms we need logarithmically-spaced bin edges,
    # otherwise the left bars get squished into illegibility.
    if log_x:
        vals = series.dropna()
        vals = vals[vals > 0]
        if len(vals) == 0:
            ax.set_title(title)
            return
        log_min = np.log10(vals.min())
        log_max = np.log10(vals.max() + 1)
        bin_edges = np.logspace(log_min, log_max, bins)
        ax.hist(vals, bins=bin_edges, color=color, edgecolor='white',
                linewidth=0.3, label=label)
        ax.set_xscale('log')
    else:
        ax.hist(series.dropna(), bins=bins, color=color, edgecolor='white',
                linewidth=0.3, label=label)

    if log_y:
        ax.set_yscale('log')

    ax.set_title(title, fontsize=11, fontweight='bold')
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.tick_params(labelsize=8)
    if label:
        ax.legend(fontsize=8)


def annotate_thresholds(ax, thresholds, axis='x'):
    """
    Draw labelled vertical (or horizontal) threshold lines on an Axes object.

    Args:
        ax         : matplotlib Axes.
        thresholds : dict mapping label → value, e.g. {'T=30': 30}.
        axis       : 'x' for vertical lines (default), 'y' for horizontal.
    """
    colors = ['#e377c2', '#ff7f0e', '#8c564b', '#9467bd']
    for i, (label, val) in enumerate(thresholds.items()):
        c = colors[i % len(colors)]
        if axis == 'x':
            ax.axvline(val, color=c, linestyle='--', linewidth=1.5, label=label)
        else:
            ax.axhline(val, color=c, linestyle='--', linewidth=1.5, label=label)
    ax.legend(fontsize=8)


def savefig(name, dpi=150):
    """
    Save the current matplotlib figure to ./figures/{name}.png at 150 dpi.
    Creates the figures/ directory if it does not already exist.
    """
    os.makedirs('figures', exist_ok=True)
    plt.savefig(f'figures/{name}.png', dpi=dpi, bbox_inches='tight')


def pretty_print_section(name):
    """
    Print a visible section banner in notebook output so it is easy to
    skim the output when reviewing later.
    """
    width = 70
    print("=" * width)
    print(f"  {name}")
    print("=" * width)


# ── Detection rule engine ────────────────────────────────────────────────────

def apply_heuristic_rules(df, ip_features, tool_features,
                          T1_emails=30, T2_tool_risk=0.95, T2_tool_volume=100,
                          T3_rate=1.0, T4_hosted_min_attempts=5):
    """
    Apply four Part-C heuristic detection rules to the row-level DataFrame.

    The rules are:
      R1 rule_high_email_count : IP tried > T1_emails distinct email addresses.
      R2 rule_attack_tool      : tool whose risk ratio >= T2_tool_risk AND
                                 volume >= T2_tool_volume (volume gate avoids
                                 flagging tools seen only once).
      R3 rule_machine_rate     : IP's average login rate > T3_rate per second
                                 (impossible for a human to sustain).
      R4 rule_hosted_infra     : traffic comes from a hosting-network IP that
                                 has >= T4_hosted_min_attempts total attempts
                                 (consumer logins do not come from data-centres).

    The combined label is_malicious = ANY of R1..R4.

    Args:
        df             : row-level DataFrame (must have been enriched in B.4).
        ip_features    : IP-level aggregation table from B.1.
        tool_features  : tool-level aggregation table from B.3.
        T1_emails      : threshold for distinct emails per IP.
        T2_tool_risk   : minimum tool_risk_ratio to call a tool malicious.
        T2_tool_volume : minimum rows a tool must have before we trust its ratio.
        T3_rate        : login attempts per second above which we flag.
        T4_hosted_min_attempts : minimum attempts from a hosted IP to flag it.

    Returns:
        (df, rule_cols) — df with new boolean columns + is_malicious;
                          rule_cols is the list of the four rule column names.
    """
    # Rule 1 — email fan-out per IP is the classic credential-stuffing signature.
    # An attacker tries one leaked combo per email, so the IP hammers many emails.
    bad_ips_emails = set(
        ip_features.loc[ip_features['ip_unique_emails'] > T1_emails, 'hashed_ip'])
    df['rule_high_email_count'] = df['hashed_ip'].isin(bad_ips_emails)

    # Rule 2 — tools with near-100 % risk rate and meaningful volume are almost
    # certainly attack frameworks (curl-wrappers, headless-browser bots, etc.).
    bad_tools = set(tool_features.loc[
        (tool_features['tool_risk_ratio'] >= T2_tool_risk) &
        (tool_features['tool_total_volume'] >= T2_tool_volume),
        'tool_id'])
    df['rule_attack_tool'] = df['tool_id'].isin(bad_tools)

    # Rule 3 — sustained rate above 1 req/s is mechanically impossible for a
    # human typing credentials; it proves automation.
    fast_ips = set(
        ip_features.loc[ip_features['ip_rate_per_second'] > T3_rate, 'hashed_ip'])
    df['rule_machine_rate'] = df['hashed_ip'].isin(fast_ips)

    # Rule 4 — legitimate consumer-product logins come from home/mobile ISPs,
    # not from hosting providers. A hosted IP with non-trivial activity is suspect.
    # We use nt_hosted if it exists (created by get_dummies in B.4), else fall back.
    if 'nt_hosted' in df.columns:
        hosted_flag = df['nt_hosted'] == 1
    else:
        hosted_flag = df.get('network_type', pd.Series('', index=df.index)) == 'hosted'

    df['rule_hosted_infra'] = (
        hosted_flag &
        (df['ip_total_attempts'] >= T4_hosted_min_attempts)
    )

    rule_cols = ['rule_high_email_count', 'rule_attack_tool',
                 'rule_machine_rate',     'rule_hosted_infra']
    df['is_malicious'] = df[rule_cols].any(axis=1)
    return df, rule_cols
