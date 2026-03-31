
# phase2/dashboard.py

"""
dashboard.py — Attack visualization dashboard (Phase 2).

Reads phase4/attack_stats.json and produces 3 plots:
  1. Bar chart   — queries used per byte
  2. Histogram   — query distribution across bytes
  3. Cumulative  — bytes recovered over total queries

Run:
  python dashboard.py
"""

import json
import os
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

STATS_FILE = "../phase4/attack_stats.json"
OUT_FILE   = "../phase4/dashboard.png"


def load_stats(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def plot_dashboard(stats: dict):
    per_byte      = stats["per_byte"]
    total_queries = stats["total_queries"]
    target        = stats["target"]
    recovered     = stats["recovered"]
    n_bytes       = len(per_byte)

    # ── Figure layout ──────────────────────────────────────────────────────
    fig = plt.figure(figsize=(15, 10), facecolor="#0d1117")
    fig.suptitle(
        f"Padding Oracle Attack — Visualization Dashboard\n"
        f"Target: \"{target}\"   |   Recovered: \"{recovered}\"   |   "
        f"Total queries: {total_queries}   |   Bytes: {n_bytes}",
        color="#c9d1d9", fontsize=13, fontweight="bold", y=0.98
    )

    gs = gridspec.GridSpec(2, 2, figure=fig,
                           hspace=0.45, wspace=0.35,
                           left=0.07, right=0.97,
                           top=0.91, bottom=0.08)

    ax1 = fig.add_subplot(gs[0, :])   # full top row
    ax2 = fig.add_subplot(gs[1, 0])   # bottom left
    ax3 = fig.add_subplot(gs[1, 1])   # bottom right

    ACCENT  = "#58a6ff"
    WARN    = "#f85149"
    SUCCESS = "#3fb950"
    BG      = "#161b22"
    GRID    = "#21262d"
    TEXT    = "#8b949e"

    def style_ax(ax, title):
        ax.set_facecolor(BG)
        ax.tick_params(colors=TEXT, labelsize=8)
        ax.set_title(title, color="#c9d1d9", fontsize=10, pad=8)
        for spine in ax.spines.values():
            spine.set_edgecolor(GRID)
        ax.yaxis.label.set_color(TEXT)
        ax.xaxis.label.set_color(TEXT)
        ax.grid(axis="y", color=GRID, linewidth=0.6, linestyle="--")

    # ── Plot 1: Queries per byte (bar chart) ──────────────────────────────
    byte_indices = list(range(n_bytes))
    colors = [WARN if q > 200 else ACCENT if q > 100 else SUCCESS
              for q in per_byte]

    bars = ax1.bar(byte_indices, per_byte, color=colors,
                   edgecolor="#0d1117", linewidth=0.5)

    # Annotate bars with recovered character
    for i, (bar, q) in enumerate(zip(bars, per_byte)):
        ch = target[i] if i < len(target) else "?"
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 3,
                 f"'{ch}'", ha="center", va="bottom",
                 color="#c9d1d9", fontsize=7)

    # Threshold line at 128 (half of max)
    ax1.axhline(128, color=WARN, linewidth=0.8, linestyle="--", alpha=0.6,
                label="128 query midpoint")
    ax1.axhline(np.mean(per_byte), color=SUCCESS, linewidth=1,
                linestyle="-.", alpha=0.8,
                label=f"Mean = {np.mean(per_byte):.1f}")

    ax1.set_xlabel("Byte index (right-to-left attack order → left-to-right display)")
    ax1.set_ylabel("Oracle queries")
    ax1.set_xticks(byte_indices)
    ax1.set_xticklabels([str(i) for i in byte_indices])
    ax1.set_ylim(0, 280)
    ax1.legend(fontsize=8, facecolor=BG, edgecolor=GRID,
               labelcolor="#c9d1d9", loc="upper right")
    style_ax(ax1, "Oracle Queries per Byte")

    # ── Plot 2: Query distribution histogram ──────────────────────────────
    ax2.hist(per_byte, bins=10, range=(0, 256),
             color=ACCENT, edgecolor="#0d1117", alpha=0.85)
    ax2.axvline(np.mean(per_byte), color=SUCCESS, linewidth=1.2,
                linestyle="--", label=f"Mean={np.mean(per_byte):.1f}")
    ax2.axvline(np.median(per_byte), color=WARN, linewidth=1.2,
                linestyle=":", label=f"Median={np.median(per_byte):.1f}")
    ax2.set_xlabel("Queries used")
    ax2.set_ylabel("Number of bytes")
    ax2.legend(fontsize=8, facecolor=BG, edgecolor=GRID, labelcolor="#c9d1d9")
    style_ax(ax2, "Query Distribution Histogram")

    # ── Plot 3: Cumulative bytes recovered vs queries ─────────────────────
    # Attack recovers bytes right-to-left; cumulate in that order
    cumulative_queries = np.cumsum(list(reversed(per_byte)))
    bytes_recovered    = list(range(1, n_bytes + 1))

    ax3.plot(cumulative_queries, bytes_recovered,
             color=SUCCESS, linewidth=2, marker="o",
             markersize=4, markerfacecolor=ACCENT)
    ax3.fill_between(cumulative_queries, bytes_recovered,
                     alpha=0.15, color=SUCCESS)

    # Worst-case line: 256 queries per byte
    worst_x = [i * 256 for i in range(n_bytes + 1)]
    worst_y = list(range(n_bytes + 1))
    ax3.plot(worst_x, worst_y, color=WARN, linewidth=0.8,
             linestyle="--", alpha=0.6, label="Worst case (256/byte)")

    ax3.set_xlabel("Cumulative oracle queries")
    ax3.set_ylabel("Bytes recovered")
    ax3.legend(fontsize=8, facecolor=BG, edgecolor=GRID, labelcolor="#c9d1d9")
    style_ax(ax3, "Cumulative Recovery Progress")

    # ── Save ──────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    plt.savefig(OUT_FILE, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    print(f"[✔] Dashboard saved to {OUT_FILE}")
    plt.show()


if __name__ == "__main__":
    stats = load_stats(STATS_FILE)
    plot_dashboard(stats)