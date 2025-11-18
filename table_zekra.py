import pandas as pd

# Load CSV
df = pd.read_csv("zekra.csv")

# Group by bench and compute means
grouped = df.groupby("bench").agg({
    "prover_time": "mean",
    "verifier_time": "mean",
    "proof_size_bits": "mean"
})

# Convert times to milliseconds
grouped["prover_time_ms"] = grouped["prover_time"] * 1000
grouped["verifier_time_ms"] = grouped["verifier_time"] * 1000

# Format values
grouped["prover_time_ms"] = grouped["prover_time_ms"].round(2)
grouped["verifier_time_ms"] = grouped["verifier_time_ms"].round(4)
grouped["proof_size_bits"] = grouped["proof_size_bits"].astype(int)

# Start building LaTeX
latex = ""
latex += "\\begin{table}[h!]\n"
latex += "\\centering\n"
latex += "\\caption{Benchmark results for ZEKRA: mean proof generation, verification time, and proof size.}\n"
latex += "\\label{tab:zekra_summary}\n"
latex += "\\begin{tabular}{lrrr}\n"
latex += "\\toprule\n"
latex += "bench & proof generation (ms) & proof verification (ms) & proof size (bits) \\\\\n"
latex += "\\midrule\n"

# Add rows
for bench, row in grouped.iterrows():
    latex += f"{bench} & {row['prover_time_ms']} & {row['verifier_time_ms']} & {row['proof_size_bits']} \\\\\n"

latex += "\\bottomrule\n"
latex += "\\end{tabular}\n"
latex += "\\end{table}\n"

print(latex)

