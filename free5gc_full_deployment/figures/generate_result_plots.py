"""Generates the two result plots added to Chapter 4 of the FYP report.

Data is transcribed directly from the already-published tables in
FYP_Report_main_upgraded.tex (tab:confirmation-rounds, tab:claude-multi-model)
- no new experiment, just a visualisation of existing numbers.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.family"] = "DejaVu Sans"

# --- Figure 1: Dynamic confirmation rate by round (Table 4.1) ---
rounds = ["Round 1", "Round 2", "Round 3", "Round 4", "Round 5"]
confirmed = [1, 2, 1, 4, 5]  # out of 6
total = 6
pct = [c / total * 100 for c in confirmed]

fig, ax = plt.subplots(figsize=(7, 4.2))
bars = ax.bar(rounds, confirmed, color="#4C72B0", width=0.55, label="CVEs dynamically confirmed (of 6)")
ax.set_ylim(0, 6.6)
ax.set_ylabel("CVEs dynamically confirmed (of 6)")
ax.set_xlabel("Verification round")
ax.set_title("Dynamic confirmation rate across five catalogue verification rounds")
for bar, c, p in zip(bars, confirmed, pct):
    ax.annotate(f"{c}/6 ({p:.0f}%)", xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, 4), textcoords="offset points", ha="center", fontsize=9)
ax.legend(loc="upper left", frameon=False)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
fig.tight_layout()
fig.savefig("confirmation_rate_by_round.png", dpi=200)
plt.close(fig)

# --- Figure 2: Cost vs confirmed_fix count, 6 hosted Claude models (Table 4.5) ---
models = ["Haiku 4.5", "Sonnet 4.6", "Sonnet 5", "Opus 4.6", "Opus 4.7", "Opus 4.8"]
cost = [1.81, 4.50, 4.26, 8.04, 5.52, 9.04]
fix_count = [5, 4, 4, 4, 5, 5]  # confirmed_fix out of 6

fig, ax = plt.subplots(figsize=(7, 4.6))
colors = ["#4C72B0" if f == 4 else "#55A868" for f in fix_count]
sc = ax.scatter(cost, fix_count, s=110, c=colors, edgecolors="black", linewidths=0.6, zorder=3)
# Sonnet 4.6 ($4.50) and Sonnet 5 ($4.26) sit close enough on the x-axis that
# the same upper-right offset used for every other point collides; stagger
# these two vertically (one label above its point, one below) instead.
label_offsets = {
    "Sonnet 4.6": (6, 10),
    "Sonnet 5": (-55, -14),
}
for x, y, name in zip(cost, fix_count, models):
    dx, dy = label_offsets.get(name, (6, 6))
    ax.annotate(name, xy=(x, y), xytext=(dx, dy), textcoords="offset points", fontsize=9)
ax.set_xlabel("Total measured cost, 6-CVE run (USD)")
ax.set_ylabel("confirmed_fix count (of 6)")
ax.set_title("Cost vs. patch-screening pass rate, 6 hosted Claude models (36 runs)")
ax.set_ylim(3.5, 5.5)
ax.set_yticks([4, 5])
ax.grid(axis="both", linestyle=":", linewidth=0.6, alpha=0.6, zorder=0)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
# Legend proxy artists
from matplotlib.lines import Line2D
legend_elems = [
    Line2D([0], [0], marker="o", color="w", markerfacecolor="#55A868", markeredgecolor="black", markersize=9, label="5/6 confirmed_fix"),
    Line2D([0], [0], marker="o", color="w", markerfacecolor="#4C72B0", markeredgecolor="black", markersize=9, label="4/6 confirmed_fix"),
]
ax.legend(handles=legend_elems, loc="lower right", frameon=False)
fig.tight_layout()
fig.savefig("cost_vs_pass_rate.png", dpi=200)
plt.close(fig)

print("Both figures written.")
