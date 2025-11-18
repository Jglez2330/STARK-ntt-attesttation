import pandas as pd
import numpy as np
import re

# -------- Helpers to parse time strings -------- #

def parse_time(s):
    """
    Parses strings like '10.023ms', '240.442µs'
    Returns time in milliseconds (float).
    """
    s = s.strip().replace('"', '')
    m = re.match(r"([\d\.]+)\s*(ms|µs)", s)
    if not m:
        raise ValueError(f"Unrecognized time format: {s}")

    value, unit = float(m.group(1)), m.group(2)

    if unit == "ms":
        return value
    elif unit == "µs":
        return value / 1000.0  # convert microseconds → milliseconds
    else:
        raise ValueError(f"Unexpected time unit: {unit}")


# -------- Load CSV -------- #

df = pd.read_csv("starkra.csv")

# Parse times to milliseconds
df["prover_time_ms"] = df["prover_time"].apply(parse_time)
df["verifier_time_ms"] = df["verifier_time"].apply(parse_time)

# Convert proof size to bits
df["proof_bits"] = df["proof_bytes"] * 8

# Group and compute means
grouped = df.groupby("bench").agg({
    "prover_time_ms": "mean",
    "verifier_time_ms": "mean",
    "proof_bits": "mean",
})

# Apply log10 transform
grouped["log10_prover_time_ms"] = np.log10(grouped["prover_time_ms"])
grouped["log10_verifier_time_ms"] = np.log10(grouped["verifier_time_ms"])
grouped["log10_proof_bits"] = np.log10(grouped["proof_bits"])

# Round nicely
grouped = grouped.round(4)

# -------- Generate LaTeX with ZEKRA caption -------- #

latex = ""
latex += "\\begin{table}[h!]\n"
latex += "\\centering\n"
latex += "\\caption{Benchmark results for ZEKRA (STARK RA): log$_{10}$ normalized metrics.}\n"
latex += "\\label{tab:zekra_starkra_log}\n"
latex += "\\begin{tabular}{lccc}\n"
latex += "\\toprule\n"
latex += "bench & $\\log_{10}$(proof gen.) & $\\log_{10}$(proof verif.) & $\\log_{10}$(proof size) \\\\\n"
latex += "      & (ms) & (ms) & (bits) \\\\\n"
latex += "\\midrule\n"

# Add rows
for bench, row in grouped.iterrows():
    latex += (
        f"{bench} & "
        f"{row['log10_prover_time_ms']} & "
        f"{row['log10_verifier_time_ms']} & "
        f"{row['log10_proof_bits']} \\\\\n"
    )

latex += "\\bottomrule\n"
latex += "\\end{tabular}\n"
latex += "\\end{table}\n"

print(latex)

