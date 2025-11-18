import pandas as pd
import numpy as np
import re
import statsmodels.api as sm
from statsmodels.formula.api import ols
from scipy.stats import shapiro, levene
import matplotlib.pyplot as plt


# ---------- Helpers ----------

def parse_time_to_ms(s: str) -> float:
    """
    Parse strings like '10.023ms' or '240.442µs' into milliseconds (float).
    Used for STARKRA times.
    """
    s = str(s).strip().replace('"', '')
    m = re.match(r"([\d\.]+)\s*(ms|µs)", s)
    if not m:
        raise ValueError(f"Unrecognized time format: {s}")
    value, unit = float(m.group(1)), m.group(2)
    if unit == "ms":
        return value
    elif unit == "µs":
        return value / 1000.0  # µs -> ms
    else:
        raise ValueError(f"Unexpected time unit: {unit}")


def make_log_zekra(input_file="zekra.csv", output_file="log_zekra.csv") -> pd.DataFrame:
    """
    Load zekra.csv, log10-transform metrics per row, and save to log_zekra.csv.
    Assumes:
      - prover_time, verifier_time are in seconds
      - proof_size_bits is already in bits
    Output columns:
      bench, prover_time_ms, verifier_time_ms, proof_bits, system
    """
    df = pd.read_csv(input_file)

    df_log = pd.DataFrame({
        "bench": df["bench"],
        # convert seconds -> ms, then log10
        "prover_time_ms": np.log10(df["prover_time"] * 1000.0),
        "verifier_time_ms": np.log10(df["verifier_time"] * 1000.0),
        "proof_bits": np.log10(df["proof_size_bits"]),
        "system": "Groth16",
    })

    df_log.to_csv(output_file, index=False)
    print(f"Wrote log-transformed ZEKRA data to {output_file}")
    return df_log


def make_log_starkra(input_file="starkra.csv", output_file="log_starkra.csv") -> pd.DataFrame:
    """
    Load starkra.csv, parse units, log10-transform metrics per row, and save to log_starkra.csv.
    Assumes:
      - prover_time, verifier_time have ms/µs units in strings
      - proof_bytes is given; convert to bits
    Output columns:
      bench, prover_time_ms, verifier_time_ms, proof_bits, system
    """
    df = pd.read_csv(input_file)

    prover_ms = df["prover_time"].apply(parse_time_to_ms)
    verifier_ms = df["verifier_time"].apply(parse_time_to_ms)
    proof_bits = df["proof_bytes"] * 8

    df_log = pd.DataFrame({
        "bench": df["bench"],
        "prover_time_ms": np.log10(prover_ms),
        "verifier_time_ms": np.log10(verifier_ms),
        "proof_bits": np.log10(proof_bits),
        "system": "STARKRA",
    })

    df_log.to_csv(output_file, index=False)
    print(f"Wrote log-transformed STARKRA data to {output_file}")
    return df_log


def build_anova_input(zekra_log: pd.DataFrame,
                      starkra_log: pd.DataFrame,
                      output_file="anova_input.csv") -> pd.DataFrame:
    """
    Merge ZEKRA and STARKRA log data, save combined CSV for ANOVA.
    """
    df = pd.concat([zekra_log, starkra_log], ignore_index=True)
    df.to_csv(output_file, index=False)
    print(f"Wrote merged ANOVA input data to {output_file}")
    return df


# ---------- ANOVA + Assumption Checks ----------

def run_one_way_anova(df: pd.DataFrame, column: str) -> None:
    """
    Run one-way ANOVA on `column` with factor = system (Groth16 vs STARKRA).
    """
    print(f"\n=== One-way ANOVA on {column} (Groth16 vs STARKRA) ===")
    model = ols(f"{column} ~ C(system)", data=df).fit()
    anova_table = sm.stats.anova_lm(model, typ=2)
    print(anova_table)


def check_anova_assumptions(df: pd.DataFrame, column: str) -> None:
    """
    Check ANOVA assumptions for a given metric:
      - Normality of residuals (Shapiro–Wilk)
      - Homogeneity of variances (Levene)
      - Save QQ plot + boxplot to PNG files.
    """
    print(f"\n===== Assumption Checks for ANOVA on {column} =====")

    # Fit model
    model = ols(f"{column} ~ C(system)", data=df).fit()
    residuals = model.resid

    # --- Normality: Shapiro–Wilk test ---
    shapiro_stat, shapiro_p = shapiro(residuals)
    print(f"Shapiro–Wilk test for normality: p = {shapiro_p:.4g}")

    # QQ plot of residuals
    sm.qqplot(residuals, line="45")
    plt.title(f"QQ-plot of residuals: {column}")
    qq_name = f"qqplot_{column}.png"
    plt.savefig(qq_name, bbox_inches="tight")
    plt.close()
    print(f"Saved QQ-plot to {qq_name}")

    # --- Homogeneity of variance: Levene’s test ---
    group_groth = df[df["system"] == "Groth16"][column]
    group_stark = df[df["system"] == "STARKRA"][column]
    lev_stat, lev_p = levene(group_groth, group_stark)
    print(f"Levene’s test for equal variances: p = {lev_p:.4g}")

    # Boxplot by system
    df.boxplot(column=column, by="system")
    plt.title(f"Boxplot: {column} by system")
    plt.suptitle("")
    box_name = f"boxplot_{column}.png"
    plt.savefig(box_name, bbox_inches="tight")
    plt.close()
    print(f"Saved boxplot to {box_name}")

    print("\nInterpretation guide:")
    print("- If Shapiro p > 0.05: residuals are approximately normal.")
    print("- If Levene p > 0.05: variances are approximately equal.")
    print("- With log10 transform and only two groups, ANOVA is quite robust even if these are mildly violated.")


# ---------- Main ----------

def main():
    # 1) Make log-transformed per-row data for both systems
    zekra_log = make_log_zekra(input_file="zekra.csv", output_file="log_zekra.csv")
    starkra_log = make_log_starkra(input_file="starkra.csv", output_file="log_starkra.csv")

    # 2) Merge into a single dataset for ANOVA
    df = build_anova_input(zekra_log, starkra_log, output_file="anova_input.csv")

    # 3) Run one-way ANOVA + assumption checks for each metric
    for col in ["prover_time_ms", "verifier_time_ms", "proof_bits"]:
        run_one_way_anova(df, col)
        check_anova_assumptions(df, col)


if __name__ == "__main__":
    main()

