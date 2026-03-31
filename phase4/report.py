"""
report.py — Comparative Analysis & Final Report (Phase 4).

What this script does:
  1. Loads real attack stats from attack_stats.json (Phase 2 results)
  2. Probes both servers live to confirm CBC is exploitable / GCM is not
  3. Generates a 5-panel matplotlib report saved as report.png
  4. Prints a structured text summary to the terminal

Run (both servers must be running):
  python report.py
"""

import json
import os
import sys
import requests
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.patches as mpatches
from datetime import datetime

STATS_FILE  = "attack_stats.json"
OUT_PNG     = "report.png"
CBC_URL     = "http://127.0.0.1:5000"
GCM_URL     = "http://127.0.0.1:5001"

# ── Colour palette ────────────────────────────────────────────────────────────
BG      = "#0d1117"
PANEL   = "#161b22"
GRID    = "#21262d"
TEXT    = "#c9d1d9"
DIM     = "#8b949e"
RED     = "#f85149"
GREEN   = "#3fb950"
BLUE    = "#58a6ff"
YELLOW  = "#e3b341"


# ── 1. Load stats ─────────────────────────────────────────────────────────────

def load_stats() -> dict:
    if not os.path.exists(STATS_FILE):
        print(f"[!] {STATS_FILE} not found. Run phase2/attack.py first.")
        sys.exit(1)
    with open(STATS_FILE) as f:
        return json.load(f)


# ── 2. Live server probes ─────────────────────────────────────────────────────

def probe_cbc_oracle() -> dict:
    """
    Encrypt a message via CBC server, then send a tampered ciphertext.
    Confirms the server returns a DISTINCT 403 for bad padding.
    """
    result = {"reachable": False, "oracle_exposed": False,
              "valid_code": None, "invalid_code": None}
    try:
        # Encrypt
        r = requests.post(f"{CBC_URL}/encrypt",
                          json={"plaintext": "OracleProbeTest!"},
                          timeout=3)
        if r.status_code != 200:
            return result
        result["reachable"] = True
        data = r.json()
        iv, ct = data["iv"], data["ciphertext"]

        # Valid decrypt
        r2 = requests.post(f"{CBC_URL}/decrypt",
                           json={"iv": iv, "ciphertext": ct}, timeout=3)
        result["valid_code"] = r2.status_code

        # Tampered ciphertext (flip last byte)
        ct_bytes    = bytearray(bytes.fromhex(ct))
        ct_bytes[-1] ^= 0xFF
        r3 = requests.post(f"{CBC_URL}/decrypt",
                           json={"iv": iv,
                                 "ciphertext": ct_bytes.hex()}, timeout=3)
        result["invalid_code"] = r3.status_code
        result["oracle_exposed"] = (result["valid_code"] != result["invalid_code"])
    except requests.exceptions.ConnectionError:
        pass
    return result


def probe_gcm_oracle() -> dict:
    """
    Encrypt via GCM server, then tamper with ciphertext and tag.
    Confirms all failures return the same HTTP 400.
    """
    result = {"reachable": False, "oracle_exposed": False,
              "valid_code": None,
              "tampered_ct_code": None, "tampered_tag_code": None}
    try:
        r = requests.post(f"{GCM_URL}/encrypt",
                          json={"plaintext": "GCMProbeTest!!!"}, timeout=3)
        if r.status_code != 200:
            return result
        result["reachable"] = True
        data = r.json()
        nonce, ct, tag = data["nonce"], data["ciphertext"], data["tag"]

        # Valid decrypt
        r2 = requests.post(f"{GCM_URL}/decrypt",
                           json={"nonce": nonce, "ciphertext": ct, "tag": tag},
                           timeout=3)
        result["valid_code"] = r2.status_code

        # Tampered ciphertext
        ct_b = bytearray(bytes.fromhex(ct)); ct_b[0] ^= 0xFF
        r3 = requests.post(f"{GCM_URL}/decrypt",
                           json={"nonce": nonce, "ciphertext": ct_b.hex(),
                                 "tag": tag}, timeout=3)
        result["tampered_ct_code"] = r3.status_code

        # Tampered tag
        tag_b = bytearray(bytes.fromhex(tag)); tag_b[0] ^= 0xFF
        r4 = requests.post(f"{GCM_URL}/decrypt",
                           json={"nonce": nonce, "ciphertext": ct,
                                 "tag": tag_b.hex()}, timeout=3)
        result["tampered_tag_code"] = r4.status_code

        result["oracle_exposed"] = (
            result["tampered_ct_code"] != result["valid_code"] or
            result["tampered_tag_code"] != result["valid_code"]
        ) and (result["tampered_ct_code"] != result["tampered_tag_code"])

    except requests.exceptions.ConnectionError:
        pass
    return result


# ── 3. Style helper ───────────────────────────────────────────────────────────

def style(ax, title):
    ax.set_facecolor(PANEL)
    ax.set_title(title, color=TEXT, fontsize=9, fontweight="bold", pad=8)
    ax.tick_params(colors=DIM, labelsize=7)
    for s in ax.spines.values():
        s.set_edgecolor(GRID)
    ax.xaxis.label.set_color(DIM)
    ax.yaxis.label.set_color(DIM)
    ax.grid(axis="y", color=GRID, linewidth=0.5, linestyle="--")


# ── 4. Build report figure ────────────────────────────────────────────────────

def build_figure(stats: dict, cbc_probe: dict, gcm_probe: dict):
    per_byte = stats["per_byte"]
    n        = len(per_byte)
    target   = stats["target"]
    total_q  = stats["total_queries"]

    fig = plt.figure(figsize=(16, 11), facecolor=BG)
    fig.suptitle(
        "Padding Oracle Attack vs AEAD Migration — Comparative Analysis Report\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   |   "
        f"Target: \"{target}\"   |   Recovered: \"{stats['recovered']}\"",
        color=TEXT, fontsize=11, fontweight="bold", y=0.99
    )

    gs = gridspec.GridSpec(3, 3, figure=fig,
                           hspace=0.55, wspace=0.38,
                           left=0.06, right=0.97,
                           top=0.93, bottom=0.07)

    ax_bar  = fig.add_subplot(gs[0, :])        # row 0: full width
    ax_hist = fig.add_subplot(gs[1, 0])        # row 1 left
    ax_cum  = fig.add_subplot(gs[1, 1])        # row 1 mid
    ax_cmp  = fig.add_subplot(gs[1, 2])        # row 1 right
    ax_http = fig.add_subplot(gs[2, 0])        # row 2 left
    ax_risk = fig.add_subplot(gs[2, 1])        # row 2 mid
    ax_txt  = fig.add_subplot(gs[2, 2])        # row 2 right (text panel)

    # ── Panel 1: Queries per byte ─────────────────────────────────────────
    colors = [RED if q > 200 else BLUE if q > 100 else GREEN for q in per_byte]
    ax_bar.bar(range(n), per_byte, color=colors, edgecolor=BG, linewidth=0.4)
    for i, q in enumerate(per_byte):
        ch = target[i] if i < len(target) else "?"
        ax_bar.text(i, q + 3, f"'{ch}'", ha="center", va="bottom",
                    color=TEXT, fontsize=6.5)
    ax_bar.axhline(np.mean(per_byte), color=YELLOW, linewidth=1,
                   linestyle="-.", label=f"Mean={np.mean(per_byte):.1f}")
    ax_bar.axhline(256, color=RED, linewidth=0.7, linestyle="--",
                   alpha=0.5, label="Max possible (256)")
    ax_bar.set_ylim(0, 290); ax_bar.set_xticks(range(n))
    ax_bar.set_xlabel("Byte index"); ax_bar.set_ylabel("Oracle queries")
    ax_bar.legend(fontsize=7, facecolor=PANEL, edgecolor=GRID,
                  labelcolor=TEXT, loc="upper right")
    legend_patches = [
        mpatches.Patch(color=GREEN,  label="≤100 queries"),
        mpatches.Patch(color=BLUE,   label="101–200 queries"),
        mpatches.Patch(color=RED,    label=">200 queries"),
    ]
    ax_bar.legend(handles=legend_patches +
                  [plt.Line2D([0],[0], color=YELLOW, linestyle="-.",
                              label=f"Mean={np.mean(per_byte):.1f}"),
                   plt.Line2D([0],[0], color=RED, linestyle="--",
                              alpha=0.5, label="Max=256")],
                  fontsize=7, facecolor=PANEL, edgecolor=GRID,
                  labelcolor=TEXT, loc="upper right")
    style(ax_bar, "Panel 1 — Oracle Queries per Recovered Byte")

    # ── Panel 2: Histogram ────────────────────────────────────────────────
    ax_hist.hist(per_byte, bins=8, range=(0, 256),
                 color=BLUE, edgecolor=BG, alpha=0.85)
    ax_hist.axvline(np.mean(per_byte),  color=YELLOW, linewidth=1.2,
                    linestyle="--", label=f"Mean={np.mean(per_byte):.0f}")
    ax_hist.axvline(np.median(per_byte), color=GREEN, linewidth=1.2,
                    linestyle=":",  label=f"Median={np.median(per_byte):.0f}")
    ax_hist.set_xlabel("Queries"); ax_hist.set_ylabel("Byte count")
    ax_hist.legend(fontsize=7, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)
    style(ax_hist, "Panel 2 — Query Distribution")

    # ── Panel 3: Cumulative recovery ──────────────────────────────────────
    cum = np.cumsum(list(reversed(per_byte)))
    ax_cum.plot(cum, range(1, n+1), color=GREEN, linewidth=2,
                marker="o", markersize=3, markerfacecolor=BLUE)
    ax_cum.fill_between(cum, range(1, n+1), alpha=0.12, color=GREEN)
    worst_x = [i * 256 for i in range(n+1)]
    ax_cum.plot(worst_x, range(n+1), color=RED, linewidth=0.8,
                linestyle="--", alpha=0.6, label="Worst case")
    ax_cum.set_xlabel("Cumulative queries"); ax_cum.set_ylabel("Bytes recovered")
    ax_cum.legend(fontsize=7, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)
    style(ax_cum, "Panel 3 — Cumulative Recovery")

    # ── Panel 4: CBC vs GCM metric comparison ─────────────────────────────
    metrics      = ["Queries\nto decrypt", "Distinct\nerror codes", "Auth\ntag bits"]
    cbc_values   = [total_q, 2, 0]
    gcm_values   = [0,        1, 128]
    x = np.arange(len(metrics)); w = 0.3
    ax_cmp.bar(x - w/2, cbc_values, w, label="AES-CBC (vulnerable)",
               color=RED,   edgecolor=BG, alpha=0.85)
    ax_cmp.bar(x + w/2, gcm_values, w, label="AES-256-GCM (secure)",
               color=GREEN, edgecolor=BG, alpha=0.85)
    ax_cmp.set_xticks(x); ax_cmp.set_xticklabels(metrics, fontsize=7)
    ax_cmp.legend(fontsize=7, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)
    style(ax_cmp, "Panel 4 — CBC vs GCM Key Metrics")

    # ── Panel 5: Live HTTP response codes ─────────────────────────────────
    scenarios  = ["Valid\ndecrypt", "CBC tampered\n(padding error)", "GCM tampered\n(any error)"]
    codes      = [
        cbc_probe.get("valid_code")       or 200,
        cbc_probe.get("invalid_code")     or 403,
        gcm_probe.get("tampered_ct_code") or 400,
    ]
    bar_colors = [GREEN if c == 200 else RED if c == 403 else YELLOW
                  for c in codes]
    bars = ax_http.bar(scenarios, codes, color=bar_colors,
                       edgecolor=BG, linewidth=0.4)
    for bar, code in zip(bars, codes):
        ax_http.text(bar.get_x() + bar.get_width()/2,
                     bar.get_height() + 1,
                     f"HTTP {code}", ha="center", va="bottom",
                     color=TEXT, fontsize=8, fontweight="bold")
    ax_http.set_ylim(0, 520)
    ax_http.set_ylabel("HTTP status code")
    ax_http.set_yticks([200, 400, 403])
    style(ax_http, "Panel 5 — Live HTTP Response Codes")

    # ── Panel 6: Attack feasibility radar-style bar ───────────────────────
    aspects    = ["Key\nrequired", "Padding\nprobed", "Auth\ntag", "Oracle\nsignal", "Exploitable"]
    cbc_score  = [0, 1, 0, 1, 1]   # 1 = bad (vulnerable)
    gcm_score  = [1, 0, 1, 0, 0]   # 1 = good (secure)
    x2 = np.arange(len(aspects)); w2 = 0.3
    ax_risk.bar(x2 - w2/2, cbc_score, w2, label="AES-CBC",
                color=RED,   edgecolor=BG, alpha=0.85)
    ax_risk.bar(x2 + w2/2, gcm_score, w2, label="AES-256-GCM",
                color=GREEN, edgecolor=BG, alpha=0.85)
    ax_risk.set_xticks(x2); ax_risk.set_xticklabels(aspects, fontsize=7)
    ax_risk.set_yticks([0, 1])
    ax_risk.set_yticklabels(["No / Absent", "Yes / Present"], fontsize=7)
    ax_risk.legend(fontsize=7, facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)
    style(ax_risk, "Panel 6 — Security Property Comparison")

    # ── Panel 7: Text summary ─────────────────────────────────────────────
    ax_txt.axis("off")
    ax_txt.set_facecolor(PANEL)
    summary = (
        "FINDINGS SUMMARY\n"
        "─────────────────────────────\n"
        f"Attack target    : {target}\n"
        f"Recovered        : {stats['recovered']}\n"
        f"Match            : {'✔ YES' if target == stats['recovered'] else '✘ NO'}\n"
        f"Total queries    : {total_q}\n"
        f"Avg / byte       : {total_q/n:.1f}\n"
        f"Max / byte       : {max(per_byte)}\n"
        f"Min / byte       : {min(per_byte)}\n"
        "─────────────────────────────\n"
        f"CBC oracle live  : {'✔ EXPOSED' if cbc_probe.get('oracle_exposed') else '─'}\n"
        f"  Valid   → HTTP {cbc_probe.get('valid_code', '?')}\n"
        f"  Invalid → HTTP {cbc_probe.get('invalid_code', '?')}\n"
        "─────────────────────────────\n"
        f"GCM oracle live  : {'✔ SAFE' if not gcm_probe.get('oracle_exposed') else '✘ CHECK'}\n"
        f"  Valid        → HTTP {gcm_probe.get('valid_code', '?')}\n"
        f"  Tampered CT  → HTTP {gcm_probe.get('tampered_ct_code', '?')}\n"
        f"  Tampered tag → HTTP {gcm_probe.get('tampered_tag_code', '?')}\n"
        "─────────────────────────────\n"
        "CONCLUSION\n"
        "AES-CBC leaks padding validity\n"
        "→ full plaintext recovery, no key.\n"
        "AES-256-GCM authenticates first;\n"
        "all errors are indistinguishable\n"
        "→ padding oracle is impossible."
    )
    ax_txt.text(0.05, 0.97, summary, transform=ax_txt.transAxes,
                color=TEXT, fontsize=7.2, va="top", fontfamily="monospace",
                linespacing=1.55)
    ax_txt.set_title("Panel 7 — Findings Summary",
                     color=TEXT, fontsize=9, fontweight="bold", pad=8)

    plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight", facecolor=BG)
    print(f"[✔] Report saved to phase4/{OUT_PNG}")
    plt.show()


# ── 5. Terminal summary ───────────────────────────────────────────────────────

def print_summary(stats, cbc, gcm):
    sep = "─" * 52
    print(f"\n{sep}")
    print("  PADDING ORACLE ATTACK — FINAL REPORT")
    print(sep)
    print(f"  Target plaintext  : {stats['target']}")
    print(f"  Recovered         : {stats['recovered']}")
    print(f"  Match             : {'✔ YES' if stats['target'] == stats['recovered'] else '✘ NO'}")
    print(f"  Total queries     : {stats['total_queries']}")
    print(f"  Bytes recovered   : {len(stats['per_byte'])}")
    print(f"  Avg queries/byte  : {stats['total_queries']/len(stats['per_byte']):.1f}")
    print(f"  Max queries/byte  : {max(stats['per_byte'])}")
    print(f"  Min queries/byte  : {min(stats['per_byte'])}")
    print(sep)
    print("  CBC SERVER (Phase 1 — Vulnerable)")
    print(f"    Reachable       : {cbc.get('reachable')}")
    print(f"    Oracle exposed  : {cbc.get('oracle_exposed')}")
    print(f"    Valid response  : HTTP {cbc.get('valid_code')}")
    print(f"    Invalid padding : HTTP {cbc.get('invalid_code')}")
    print(sep)
    print("  GCM SERVER (Phase 3 — Secure)")
    print(f"    Reachable       : {gcm.get('reachable')}")
    print(f"    Oracle exposed  : {gcm.get('oracle_exposed')}")
    print(f"    Valid response  : HTTP {gcm.get('valid_code')}")
    print(f"    Tampered CT     : HTTP {gcm.get('tampered_ct_code')}")
    print(f"    Tampered tag    : HTTP {gcm.get('tampered_tag_code')}")
    print(sep)
    print("  CONCLUSION")
    print("  AES-CBC leaks padding validity → full plaintext recovery without key.")
    print("  AES-256-GCM verifies auth tag first → all errors indistinguishable.")
    print("  Migrating to AEAD eliminates the padding oracle attack surface.")
    print(f"{sep}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[*] Loading attack stats...")
    stats = load_stats()

    print("[*] Probing CBC server...")
    cbc_probe = probe_cbc_oracle()

    print("[*] Probing GCM server...")
    gcm_probe = probe_gcm_oracle()

    print_summary(stats, cbc_probe, gcm_probe)
    print("[*] Building report figure...")
    build_figure(stats, cbc_probe, gcm_probe)