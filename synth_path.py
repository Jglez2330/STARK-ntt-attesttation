#!/usr/bin/env python3
import argparse
import subprocess
import time
import csv
import re
from pathlib import Path

# -------------------------- Parsing -----------------------------

# We allow units: µs / us / μs, ms, s
TIME_UNITS = ("us", "µs", "μs", "ms", "s")

def parse_time_ms(label: str, text: str):
    """
    Look for e.g. "Prove: 2.283ms" or "Verify: 169.891µs" or "Prove: 0.5s"
    and return the value converted to milliseconds (float) or None.
    """
    # Example regex: r"Prove:\s*([0-9.]+)\s*([uµμ]?s|ms|s)"
    pattern = rf"{label}:\s*([0-9.]+)\s*([uµμ]?s|ms|s)"
    m = re.search(pattern, text)
    if not m:
        return None

    value = float(m.group(1))
    unit = m.group(2)

    # Normalize microsecond representations
    if unit in ("us", "µs", "μs"):
        return value / 1000.0           # µs -> ms
    elif unit == "ms":
        return value                    # already ms
    elif unit == "s":
        return value * 1000.0           # s -> ms
    else:
        return None


PROOF_RE = re.compile(r"Proof:\s*.*\((\d+)\s*bytes\)")


def parse_output(stdout: str):
    """
    Extract:
      - prove_ms (float, ms)
      - verify_ms (float, ms)
      - proof_bits (int)
    from the program stdout.
    """
    prove_ms = parse_time_ms("Prove", stdout)
    verify_ms = parse_time_ms("Verify", stdout)

    proof_bytes = None
    m = PROOF_RE.search(stdout)
    if m:
        proof_bytes = int(m.group(1))

    proof_bits = proof_bytes * 8 if proof_bytes is not None else None
    return prove_ms, verify_ms, proof_bits


# -------------------------- CFG Generation -----------------------------

def build_linear_cfg(n_nodes: int):
    """Build 0 -> 1 -> 2 -> ... -> n-1."""
    adjlist = {i: [] for i in range(n_nodes)}
    for i in range(n_nodes - 1):
        adjlist[i].append(i + 1)
    return adjlist


def write_numified_files(n_nodes: int):
    """Write numified_adjlist + numified_path."""
    adjlist = build_linear_cfg(n_nodes)

    with open("numified_path", "w") as f:
        f.write(f"initial_node=0 final_node={n_nodes - 1}\n")
        for edge_id in range(1, n_nodes):
            f.write(f"jump {edge_id}\n")

    with open("numified_adjlist", "w") as f:
        for src in range(n_nodes):
            for dst in adjlist[src]:
                f.write(f"{src} {dst}\n")


# -------------------------- Execution -----------------------------

def run_starkra(executable: str):
    start = time.perf_counter()
    proc = subprocess.run(
        [executable, "numified_adjlist", "numified_path"],
        text=True,
        capture_output=True
    )
    elapsed = time.perf_counter() - start
    return elapsed, proc.returncode, proc.stdout, proc.stderr


# -------------------------- MAIN -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark starkra over CFGs of size 2^k and log results."
    )

    parser.add_argument("--min_power", type=int, default=4,
                        help="Minimum k for n = 2^k.")
    parser.add_argument("--max_power", type=int, default=10,
                        help="Maximum k for n = 2^k.")
    parser.add_argument("--reps", type=int, default=5,
                        help="Number of runs per k.")
    parser.add_argument("--exec", type=str, default="./starkra",
                        help="Path to starkra executable.")
    parser.add_argument("--csv", type=str, default="starkra_results.csv",
                        help="CSV file to store all results.")
    parser.add_argument("--verbose", action="store_true",
                        help="Print per-run details.")

    args = parser.parse_args()

    csv_path = Path(args.csv)
    new_csv = not csv_path.exists()

    # Open CSV and write header (if new)
    with csv_path.open("a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if new_csv:
            writer.writerow([
                "power_k",
                "n_nodes",
                "run",
                "elapsed_wall_ms",
                "prove_ms",
                "verify_ms",
                "proof_bits",
                "return_code",
            ])

        # Loop over powers of 2
        for k in range(args.min_power, args.max_power + 1):
            n_nodes = 2 ** k

            if args.verbose:
                print(f"\n=== k = {k} (n = {n_nodes}) ===")

            # Generate CFG + path
            write_numified_files(n_nodes)

            # Prepare log directory: logs/synth/k
            logdir = Path(f"logs/synth/{k}")
            logdir.mkdir(parents=True, exist_ok=True)

            for run_i in range(1, args.reps + 1):
                elapsed, rc, stdout, stderr = run_starkra(args.exec)

                # Parse Prove / Verify / Proof size
                prove_ms, verify_ms, proof_bits = parse_output(stdout)

                # Save stdout for this run
                out_file = logdir / f"run_{run_i}"
                with out_file.open("w") as f:
                    f.write(stdout)

                elapsed_ms = elapsed * 1000.0  # wall clock in ms

                # Write one row per run
                writer.writerow([
                    k,
                    n_nodes,
                    run_i,
                    elapsed_ms,
                    prove_ms,
                    verify_ms,
                    proof_bits,
                    rc,
                ])

                if args.verbose:
                    print(
                        f"Run {run_i}: "
                        f"wall={elapsed_ms:.3f} ms, "
                        f"prove={prove_ms}, verify={verify_ms}, "
                        f"proof_bits={proof_bits}, rc={rc}"
                    )


if __name__ == "__main__":
    main()

