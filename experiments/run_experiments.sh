#!/usr/bin/env sh

# --- CONFIGURATION -------------------------------------------------------
RUNS=10          # how many times to run
OUTDIR="runs"    # output folder for logs

# --- YOUR EXPERIMENT COMMAND --------------------------------------------
# Edit this function to call your experiment.
# You can use $RUN (1..N) to vary the behavior if needed.
run_experiment() {
  echo "Running experiment $RUN"
  # Example command:
  ./experiment --trial "$RUN"
}
# ------------------------------------------------------------------------

SUMMARY="$OUTDIR/summary.csv"
echo "run,start_ts,end_ts,status,duration_s,log_path" > "$SUMMARY"

for RUN in $(seq 1 "$RUNS"); do
  LOG="$OUTDIR/logs/run_${RUN}.log"
  echo "=== Run $RUN ==="

  start=$(date +%s)
  start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  if run_experiment >"$LOG" 2>&1; then
    status=0
  else
    status=$?
  fi

  end=$(date +%s)
  end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  dur=$(( end - start ))

  echo "$RUN,$start_iso,$end_iso,$status,$dur,$LOG" >> "$SUMMARY"
done

echo "All runs complete. Summary saved to $SUMMARY"
