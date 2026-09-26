"""Figures for the ExFilTrap paper.

Every number plotted here is read from the project's own evaluation output:
  eval/results/summary.csv          (per-profile detection metrics, real runs)
  eval/results/multiseed_stats.json (5 randomized paired trials + t-test)
  eval/results/live_deployment_report.md, stress_test_report.md (operational)

Style matches the reference sample: SPSS-like grouped bars, blue for the
existing method and teal for the proposed one, light horizontal gridlines,
no top/right spines.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = "figs/"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})

EX = "#1191e8"   # existing method (sample's blue)
PR = "#005e60"   # proposed method (sample's teal)
FILL = "#cbe5fe"  # diagram fill (sample's light blue)
EDGE = "#2f3542"


def style_axes(ax, ylab, title, ylim=None):
    ax.set_ylabel(ylab, fontsize=8)
    ax.set_title(title, fontsize=9, fontweight="bold", pad=6)
    if ylim:
        ax.set_ylim(*ylim)
    ax.grid(axis="y", color="#d0d4da", alpha=0.9, lw=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#8a9099")
    ax.tick_params(labelsize=7.5)


def grouped(ax, labels, existing, proposed, ylab, title, ylim=None,
            fmt="{:.1f}", legend=True, fs=6.4, legend_out=False):
    x = np.arange(len(labels))
    w = 0.36
    b1 = ax.bar(x - w / 2, existing, w, label="Existing Method", color=EX,
                edgecolor="white", lw=0.6)
    b2 = ax.bar(x + w / 2, proposed, w, label="Proposed Method", color=PR,
                edgecolor="white", lw=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    # Value labels are pushed outward (left of the existing bar, right of the
    # proposed one) so close pairs such as 99.81 / 99.98 never collide.
    for bars, ha, dx in ((b1, "right", -0.03), (b2, "left", 0.03)):
        for b in bars:
            h = b.get_height()
            if h == h:  # skip NaN
                ax.annotate(fmt.format(h),
                            (b.get_x() + b.get_width() / 2 + dx, h),
                            ha=ha, va="bottom", fontsize=fs)
    style_axes(ax, ylab, title, ylim)
    if legend:
        if legend_out:
            ax.legend(fontsize=6.6, frameon=False, ncol=2,
                      loc="upper center", bbox_to_anchor=(0.5, -0.16))
        else:
            ax.legend(fontsize=6.8, frameon=False, loc="upper right")


# --------------------------------------------------------------------------
# Real measured values
# --------------------------------------------------------------------------
FAST_E = dict(acc=99.87, prec=99.87, rec=100.00, fpr=2.67)
FAST_P = dict(acc=99.98, prec=99.98, rec=100.00, fpr=0.50)
SLOW_E = dict(acc=96.35, prec=21.66, rec=54.55, fpr=3.01)
SLOW_P = dict(acc=99.25, prec=71.65, rec=82.73, fpr=0.50)
BEN_E = 3.01
BEN_P = 0.50
F1_SLOW_E = 2 * SLOW_E["prec"] * SLOW_E["rec"] / (SLOW_E["prec"] + SLOW_E["rec"])
F1_SLOW_P = 2 * SLOW_P["prec"] * SLOW_P["rec"] / (SLOW_P["prec"] + SLOW_P["rec"])

TRIALS_E = [53.64, 57.27, 62.73, 55.45, 62.73]   # RF-only control, 5 seeds
TRIALS_P = [85.45, 83.64, 83.64, 85.45, 83.64]   # full pipeline, same seeds
MEAN_E, SD_E = 58.36, 4.19
MEAN_P, SD_P = 84.36, 1.00

PROFILES = ["Fast tunneling", "Slow-drip"]


# --------------------------------------------------------------------------
# Fig. 1 — proposed architecture / flow chart
# --------------------------------------------------------------------------
def fig1():
    W, H = 7.2, 4.9
    fig, ax = plt.subplots(figsize=(W, H))
    ax.set_xlim(0, W)
    ax.set_ylim(-0.4, H)
    ax.axis("off")

    def box(x, y, w, h, title, sub=None, acc=False, ts=7.4, ss=6.3):
        ax.add_patch(FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.015,rounding_size=0.06",
            lw=1.2 if acc else 1.0,
            edgecolor=PR if acc else EDGE,
            facecolor=FILL if acc else "#f4f7fb", zorder=3))
        if sub:
            ax.text(x + w / 2, y + h * 0.66, title, ha="center", va="center",
                    fontsize=ts, fontweight="bold", zorder=4)
            ax.text(x + w / 2, y + h * 0.27, sub, ha="center", va="center",
                    fontsize=ss, zorder=4, color="#1d2430")
        else:
            ax.text(x + w / 2, y + h / 2, title, ha="center", va="center",
                    fontsize=ts, fontweight="bold", zorder=4)

    def arrow(x1, y1, x2, y2):
        ax.add_patch(FancyArrowPatch(
            (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9,
            lw=1.1, color=EDGE, zorder=2, shrinkA=0, shrinkB=0))

    def line(pts):
        ax.plot([p[0] for p in pts], [p[1] for p in pts],
                color=EDGE, lw=1.1, zorder=2)

    L, R = 0.06, 7.14
    FW = R - L
    MID = L + FW / 2

    # --- acquisition and feature stage (full width) ------------------------
    box(L, 3.96, FW, 0.46, "M1  DNS Traffic Capture",
        "scapy \u00b7 UDP + TCP/53 \u00b7 all interfaces \u00b7 BPF pre-filter")
    arrow(MID, 3.96, MID, 3.80)
    box(L, 3.34, FW, 0.46, "M2  Per-Query Feature Extraction",
        "entropy \u00b7 length \u00b7 subdomains \u00b7 frequency \u00b7 n-gram \u00b7 digits")

    # --- three detection columns ------------------------------------------
    C1 = (0.10, 2.24)   # M5 random forest
    C2 = (2.52, 1.90)   # M4 dynamic baseline
    C3 = (4.60, 2.54)   # M3 / M3b stateful layer

    line([(C1[0] + C1[1] / 2, 3.34), (C3[0] + C3[1] / 2, 3.34)])
    arrow(C1[0] + C1[1] / 2, 3.34, C1[0] + C1[1] / 2, 3.08)
    arrow(C3[0] + C3[1] / 2, 3.34, C3[0] + C3[1] / 2, 3.08)

    box(C1[0], 2.48, C1[1], 0.60, "M5  Random Forest",
        "per-query P(malicious)", acc=True, ts=7.2, ss=6.1)
    box(C2[0], 2.48, C2[1], 0.60, "M4  Dynamic Baseline",
        "EWMA + Welford \u03c3", ts=6.9, ss=6.1)
    box(C3[0], 2.48, C3[1], 0.60, "M3  Stateful Session Layer",
        "entropy-weighted byte mass \u00b7 sequential z-test", acc=True,
        ts=7.0, ss=6.0)

    # M4 supplies the learned baseline to the stateful layer
    arrow(C2[0] + C2[1], 2.78, C3[0], 2.78)

    box(C3[0], 1.84, C3[1], 0.52, "M3b  Beacon + Attribution",
        "beacon CV \u00b7 owning process \u00b7 resolver \u00b7 record type", ts=6.9, ss=6.0)
    arrow(C3[0] + C3[1] / 2, 2.48, C3[0] + C3[1] / 2, 2.36)

    # --- fusion ------------------------------------------------------------
    RY, RH = 1.10, 0.52
    box(L, RY, FW, RH, "M7  Risk Engine",
        "LOW \u00b7 MEDIUM \u00b7 HIGH \u00b7 CONFIRMED", acc=True)

    MERGE = 1.76
    RAIL = 0.16
    line([(RAIL, 2.48), (RAIL, MERGE), (C3[0] + C3[1] / 2, MERGE)])
    line([(C3[0] + C3[1] / 2, 1.84), (C3[0] + C3[1] / 2, MERGE)])
    arrow(MID, MERGE, MID, RY + RH)

    # --- response chain ----------------------------------------------------
    arrow(MID, RY, MID, 0.98)
    box(L, 0.50, FW, 0.48, "M6  Payload Decoder",
        "Base32 \u00b7 Base64 \u00b7 Hex \u00b7 file signatures")
    arrow(MID, 0.50, MID, 0.34)
    box(L, 0.00, FW, 0.34, "M8  Evidence-Gated Response \u00b7 sinkhole strikes \u00b7 canary traps \u00b7 TTL")
    arrow(MID, 0.00, MID, -0.12)
    ax.text(MID, -0.26,
            "M9  WAL SQLite \u2192 REST API + SSE \u2192 Web / Desktop console \u00b7 intercept ledger",
            ha="center", va="center", fontsize=6.7, color=PR, fontweight="bold")

    fig.savefig(OUT + "fig1_arch.png", dpi=300, bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


fig1()

# --------------------------------------------------------------------------
# Fig. 2 — detection performance by profile (three panels)
# --------------------------------------------------------------------------
fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.8))
for ax, key, name in zip(axes, ("acc", "prec", "rec"),
                         ("Accuracy", "Precision", "Recall")):
    grouped(ax, ["Fast", "Slow-drip"],
            [FAST_E[key], SLOW_E[key]], [FAST_P[key], SLOW_P[key]],
            f"{name} (%)", f"{name} by Profile", ylim=(0, 122),
            legend=False, fs=6.4)
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, fontsize=6.9, frameon=False, ncol=2,
           loc="lower center", bbox_to_anchor=(0.5, 0.99))
fig.tight_layout()
fig.savefig(OUT + "fig2_profiles.png", dpi=300, bbox_inches="tight")
plt.close(fig)

# --------------------------------------------------------------------------
# Fig. 3 — slow-drip detection performance (precision / recall / F1)
# --------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(7.2, 2.6))
grouped(ax, ["Precision", "Recall", "F1-Score"],
        [SLOW_E["prec"], SLOW_E["rec"], F1_SLOW_E],
        [SLOW_P["prec"], SLOW_P["rec"], F1_SLOW_P],
        "Percentage (%)", "Slow-Drip Detection Performance Analysis",
        ylim=(0, 108))
fig.tight_layout()
fig.savefig(OUT + "fig3_slowdrip.png", dpi=300, bbox_inches="tight")
plt.close(fig)

for fname, ev, pv, metric in (
        ("fig3_1_precision.png", SLOW_E["prec"], SLOW_P["prec"], "Precision"),
        ("fig3_2_recall.png", SLOW_E["rec"], SLOW_P["rec"], "Recall"),
        ("fig3_3_f1.png", F1_SLOW_E, F1_SLOW_P, "F1-Score")):
    fig, ax = plt.subplots(figsize=(3.4, 2.7))
    grouped(ax, ["Slow-drip"], [ev], [pv], f"{metric} (%)",
            f"Slow-Drip {metric}", ylim=(0, 112), legend_out=True)
    fig.tight_layout()
    fig.savefig(OUT + fname, dpi=300, bbox_inches="tight")
    plt.close(fig)

# --------------------------------------------------------------------------
# Fig. 4 — five randomized trials (stability of the stateful gain)
# --------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(7.2, 2.5))
grouped(ax, [f"Trial {i+1}" for i in range(5)], TRIALS_E, TRIALS_P,
        "Slow-Drip Recall (%)", "Slow-Drip Recall Across Five Randomized Trials",
        ylim=(0, 112))
fig.tight_layout()
fig.savefig(OUT + "fig4_trials.png", dpi=300, bbox_inches="tight")
plt.close(fig)

# Fig. 4 sub-figures: Fig. 4 above is the trial overview, so the subs show the
# aggregate view (mean with spread) and the stability comparison — distinct
# information rather than a re-plot of the same bars.
fig, ax = plt.subplots(figsize=(3.4, 2.7))
x = np.arange(2)
ax.bar(x, [MEAN_E, MEAN_P], 0.45, yerr=[SD_E, SD_P], capsize=5,
       color=[EX, PR], edgecolor="white", lw=0.6)
ax.set_xticks(x)
ax.set_xticklabels(["Existing\nMethod", "Proposed\nMethod"], fontsize=7.5)
for xi, v, s in zip(x, [MEAN_E, MEAN_P], [SD_E, SD_P]):
    ax.annotate(f"{v:.2f}\n\u00b1{s:.2f}", (xi, v + s + 5), ha="center",
                va="bottom", fontsize=6.6)
style_axes(ax, "Mean Recall (%)", "Mean Slow-Drip Recall \u00b1 SD", ylim=(0, 118))
fig.tight_layout()
fig.savefig(OUT + "fig4_1_meansd.png", dpi=300, bbox_inches="tight")
plt.close(fig)

fig, ax = plt.subplots(figsize=(3.4, 2.7))
ax.bar([0, 1], [SD_E, SD_P], 0.45, color=[EX, PR], edgecolor="white", lw=0.6)
ax.set_xticks([0, 1])
ax.set_xticklabels(["Existing\nMethod", "Proposed\nMethod"], fontsize=7.5)
for xi, v in zip([0, 1], [SD_E, SD_P]):
    ax.annotate(f"{v:.2f}", (xi, v + 0.12), ha="center", va="bottom", fontsize=6.6)
style_axes(ax, "Standard Deviation (pp)", "Trial-to-Trial Spread of Recall",
           ylim=(0, 5.4))
fig.tight_layout()
fig.savefig(OUT + "fig4_2_spread.png", dpi=300, bbox_inches="tight")
plt.close(fig)

# --------------------------------------------------------------------------
# Fig. 5 — overall system evaluation (slow-drip scenario)
# --------------------------------------------------------------------------
OMS = ["Accuracy", "Precision", "Recall", "F1-Score"]
fig, ax = plt.subplots(figsize=(7.2, 2.6))
grouped(ax, OMS,
        [SLOW_E["acc"], SLOW_E["prec"], SLOW_E["rec"], F1_SLOW_E],
        [SLOW_P["acc"], SLOW_P["prec"], SLOW_P["rec"], F1_SLOW_P],
        "Percentage (%)", "Overall System Evaluation \u2014 Slow-Drip Scenario",
        ylim=(0, 118))
fig.tight_layout()
fig.savefig(OUT + "fig5_overall.png", dpi=300, bbox_inches="tight")
plt.close(fig)

for fname, ev, pv, metric in (
        ("fig5_1_acc.png", SLOW_E["acc"], SLOW_P["acc"], "Accuracy"),
        ("fig5_2_prec.png", SLOW_E["prec"], SLOW_P["prec"], "Precision"),
        ("fig5_3_rec.png", SLOW_E["rec"], SLOW_P["rec"], "Recall"),
        ("fig5_4_f1.png", F1_SLOW_E, F1_SLOW_P, "F1-Score")):
    fig, ax = plt.subplots(figsize=(3.4, 2.7))
    grouped(ax, ["Slow-drip"], [ev], [pv], f"{metric} (%)",
            f"Overall {metric}", ylim=(0, 122), legend_out=True)
    fig.tight_layout()
    fig.savefig(OUT + fname, dpi=300, bbox_inches="tight")
    plt.close(fig)

print("figures written")
print(f"F1 slow-drip: existing {F1_SLOW_E:.2f}  proposed {F1_SLOW_P:.2f}")