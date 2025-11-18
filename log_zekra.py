import pandas as pd
import numpy as np

# Load CSV (renamed file)
df = pd.read_csv("zekra.csv")

# --- Build log-transformed per-row data for ANOVA --- #
# Original times are in seconds; convert to ms then log10
df_log = pd.DataFrame({
    "bench": df["bench"],
    "prover_time_ms": np.log10(df["prover_time"] * 1000.0),
    "verifier_time_ms": np.log10(df["verifier_time"] * 1000.0),
    "proof_bits": np.log10(df["proof_size_bits"])
})

# Save all log-transformed observations for ANOVA
df_log.to_csv("log_zekra.csv", index=False)

# --- For the LaTeX table: average the log-transformed values per bench --- #
grouped = df_log.groupby("bench").mean().round(4)

# Build LaTeX table
latex = ""
latex += "\\begin{table}[h!]\n"
latex += "\\centering\n"
latex += "\\caption{Benchmark results for ZEKRA (Groth16): log$_{10}$ normalized metrics.}\n"
latex += "\\label{tab:zekra_log}\n"
latex += "\\begin{tabular}{lccc}\n"
latex += "\\toprule\n"
latex += "bench & $\\log_{10}$(proof gen.) & $\\log_{10}$(proof verif.) & $\\log_{10}$(proof size) \\\\\n"
latex += "      & (ms) & (ms) & (bits) \\\\\n"
latex += "\\midrule\n"

for bench, row in grouped.iterrows():
    latex += (
        f"{bench} & "
        f"{row['prover_time_ms']} & "
        f"{row['verifier_time_ms']} & "
        f"{row['proof_bits']} \\\\\n"
    )

latex += "\\bottomrule\n"
latex += "\\end{tabular}\n"
latex += "\\end{table}\n"

print(latex)

