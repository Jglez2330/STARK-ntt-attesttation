import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------------------------------------------
# 1. Load data
# -------------------------------------------------------------------
stark_path = "log_starkra.csv"
zekra_path = "log_zekra.csv"

stark = pd.read_csv(stark_path)
zekra = pd.read_csv(zekra_path)

# -------------------------------------------------------------------
# 2. Normalize system labels
#    Convert any "Groth16" to "ZEKRA"
# -------------------------------------------------------------------
stark["system"] = stark["system"].replace({"Groth16": "ZEKRA"})
zekra["system"] = zekra["system"].replace({"Groth16": "ZEKRA"})

# -------------------------------------------------------------------
# 3. Concatenate
# -------------------------------------------------------------------
data = pd.concat([stark, zekra], ignore_index=True)

# system labels expected now:
systems = ["STARKRA", "ZEKRA"]

print("System labels found:", data["system"].unique())

# -------------------------------------------------------------------
# 4. Helper function: boxplot generator
# -------------------------------------------------------------------
def boxplot_metric(metric, filename, ylabel):
    plt.figure()

    group_data = [
        data.loc[data["system"] == systems[0], metric].dropna(),
        data.loc[data["system"] == systems[1], metric].dropna(),
    ]

    plt.boxplot(group_data, labels=systems)
    plt.ylabel(ylabel)
    plt.title(f"Boxplot of {ylabel} by system")
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    print(f"Saved {filename}")

# -------------------------------------------------------------------
# 5. Generate boxplots for each log10-transformed metric
# -------------------------------------------------------------------

# Prover time
boxplot_metric(
    metric="prover_time_ms",
    filename="box_prover_time_ms.pdf",
    ylabel="log10 proving time (ms)"
)

# Verifier time
boxplot_metric(
    metric="verifier_time_ms",
    filename="box_verifier_time_ms.pdf",
    ylabel="log10 verification time (ms)"
)

# Proof size
boxplot_metric(
    metric="proof_bits",
    filename="box_proof_bits.pdf",
    ylabel="log10 proof size (bits)"
)

print("All boxplots generated.")

