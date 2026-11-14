#!/usr/bin/env python3
"""
plot_comparison.py  —  Turn the metrics CSVs into comparison graphs for the
Dynamic Host Blocking System performance evaluation (CN Deliverable 2).

Reads two CSV files produced by metrics_client.py:
  - a "protected" run  (SDN controller blocking the attacker)
  - a "baseline" run   (plain switch, no blocking)
and produces:
  1. success_rate.png  — bar chart: legitimate-request success rate, protected vs baseline
  2. latency_over_time.png — line chart: legitimate-request latency during the attack

Usage:
    python3 plot_comparison.py --protected protected_n1.csv --baseline baseline_n1.csv
"""

import argparse
import csv


def load(path):
    t, success, latency = [], [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            t.append(float(row["t_sec"]))
            success.append(int(row["success"]))
            latency.append(float(row["latency_sec"]))
    return t, success, latency


def summarise(name, t, success, latency):
    total = len(success)
    ok = sum(success)
    rate = (100.0 * ok / total) if total else 0.0
    # average latency of successful requests only
    good_lat = [l for s, l in zip(success, latency) if s]
    avg_lat_ms = (1000.0 * sum(good_lat) / len(good_lat)) if good_lat else 0.0
    print(f"{name:10s} requests={total} ok={ok} "
          f"success={rate:.1f}% avg_latency={avg_lat_ms:.1f} ms")
    return rate, avg_lat_ms


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--protected", default="protected_n1.csv")
    p.add_argument("--baseline", default="baseline_n1.csv")
    args = p.parse_args()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pt, ps, pl = load(args.protected)
    bt, bs, bl = load(args.baseline)

    print("=== Summary ===")
    p_rate, p_lat = summarise("protected", pt, ps, pl)
    b_rate, b_lat = summarise("baseline", bt, bs, bl)

    # 1) Success-rate bar chart
    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(["With SDN\n(protected)", "No SDN\n(baseline)"],
                  [p_rate, b_rate],
                  color=["#1e8449", "#c0392b"])
    ax.set_ylabel("Legitimate request success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Legitimate traffic during attack")
    for b, v in zip(bars, [p_rate, b_rate]):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%",
                ha="center", fontweight="bold")
    fig.tight_layout()
    fig.savefig("success_rate.png", dpi=150)

    # 2) Latency over time
    fig2, ax2 = plt.subplots(figsize=(7, 4))
    ax2.plot(pt, [l * 1000 for l in pl], label="With SDN (protected)",
             color="#1e8449", marker="o", markersize=3)
    ax2.plot(bt, [l * 1000 for l in bl], label="No SDN (baseline)",
             color="#c0392b", marker="x", markersize=4)
    ax2.set_xlabel("Time (s)")
    ax2.set_ylabel("Request latency (ms)")
    ax2.set_title("Legitimate request latency during attack")
    ax2.legend()
    fig2.tight_layout()
    fig2.savefig("latency_over_time.png", dpi=150)

    print("Saved: success_rate.png, latency_over_time.png")


if __name__ == "__main__":
    main()
