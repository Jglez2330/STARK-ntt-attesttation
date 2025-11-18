import pandas as pd
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

# Parse times
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

# Final formatting
grouped["prover_time_ms"] = grouped["prover_time_ms"].round(3)
grouped["verifier_time_ms"] = grouped["verifier_time_ms"].round(3)
grouped["proof_bits"] = grouped["proof_bits"].round().astype(int)

# -------- Generate LaTeX with ZEKRA caption -------- #

latex = ""
latex += "\\begin{table}[h!]\n"
latex += "\\centering\n"
latex += "\\caption{Benchmark results for STARKRA: mean proof generation, verification time, and proof size (STARK RA version).}\n"
latex += "\\label{tab:zekra_starkra}\n"
latex += "\\begin{tabular}{lrrr}\n"
latex += "\\toprule\n"
latex += "bench & proof generation (ms) & proof verification (ms) & proof size (bits) \\\\\n"
latex += "\\midrule\n"

# Add rows
for bench, row in grouped.iterrows():
    latex += f"{bench} & {row['prover_time_ms']} & {row['verifier_time_ms']} & {row['proof_bits']} \\\\\n"

latex += "\\bottomrule\n"
latex += "\\end{tabular}\n"
latex += "\\end{table}\n"

print(latex)

