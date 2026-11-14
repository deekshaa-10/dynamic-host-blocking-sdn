
#!/usr/bin/env python3
"""
Performance comparison graphs for the Dynamic Host Blocking System.

Compares:
1. SDN with dynamic host blocking enabled (protected).
2. SDN without dynamic host blocking (baseline).

Generates:
- success_rate.png
- latency_over_time.png
"""

import argparse
import csv


def load(path):
    t, success, latency = [], [], []

    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            t.append(float(row["t_sec"]))
            success.append(int(row["success"]))
            latency.append(float(row["latency_sec"]))

    return t, success, latency


def summarise(name, t, success, latency):
    total = len(success)
    ok = sum(success)

    rate = (100.0 * ok / total) if total else 0.0

    # Calculate average latency using successful requests only.
    good_lat = [
        l for s, l in zip(success, latency) if s
    ]

    avg_lat_ms = (
        1000.0 * sum(good_lat) / len(good_lat)
        if good_lat else 0.0
    )

    print(
        f"{name:10s} requests={total} ok={ok} "
        f"success={rate:.1f}% "
        f"avg_latency={avg_lat_ms:.1f} ms"
    )

    return rate, avg_lat_ms


def main():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--protected",
        default="protected_n1.csv"
    )

    p.add_argument(
        "--baseline",
        default="baseline_n1.csv"
    )

    args = p.parse_args()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pt, ps, pl = load(args.protected)
    bt, bs, bl = load(args.baseline)

    print("=== Performance Comparison ===")

    p_rate, p_lat = summarise(
        "protected", pt, ps, pl
    )

    b_rate, b_lat = summarise(
        "baseline", bt, bs, bl
    )

    # GRAPH 1: Legitimate request success rate

    fig, ax = plt.subplots(figsize=(6, 4))

    labels = [
        "Blocking enabled",
        "Blocking disabled"
    ]

    bars = ax.bar(
        labels,
        [p_rate, b_rate],
        color=["#1e8449", "#c0392b"]
    )

    ax.set_ylabel("Legitimate request success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Legitimate Traffic During Attack")

    for bar, value in zip(bars, [p_rate, b_rate]):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 2,
            f"{value:.1f}%",
            ha="center",
            fontweight="bold"
        )

    fig.tight_layout()
    fig.savefig("success_rate.png", dpi=150)
    plt.close(fig)

    # GRAPH 2: Latency over time
    # Only successful requests are included.

    protected_t = [
        t for t, s in zip(pt, ps) if s
    ]

    protected_latency = [
        l * 1000 for l, s in zip(pl, ps) if s
    ]

    baseline_t = [
        t for t, s in zip(bt, bs) if s
    ]

    baseline_latency = [
        l * 1000 for l, s in zip(bl, bs) if s
    ]

    fig2, ax2 = plt.subplots(figsize=(7, 4))

    ax2.plot(
        protected_t,
        protected_latency,
        label="Blocking enabled",
        color="#1e8449",
        marker="o",
        markersize=3
    )

    ax2.plot(
        baseline_t,
        baseline_latency,
        label="Blocking disabled",
        color="#c0392b",
        marker="x",
        markersize=4
    )

    ax2.set_xlabel("Time (seconds)")
    ax2.set_ylabel("Successful request latency (ms)")
    ax2.set_title("Legitimate Request Latency During Attack")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    fig2.tight_layout()
    fig2.savefig("latency_over_time.png", dpi=150)
    plt.close(fig2)

    print(
        "Saved: success_rate.png, latency_over_time.png"
    )


if __name__ == "__main__":
    main()
