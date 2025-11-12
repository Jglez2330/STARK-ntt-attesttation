directories=$(find ../../../../code/complete_runs/ -type d -mindepth 1 -maxdepth 1)
runs=5
# Execute runs times
for dir in $directories; do
    for i in $(seq 1 $runs); do
    echo "$dir/starkra_miden_output_$i.txt"
    # call the ZEKRA erunnner and store the output in a file
    #it also prins the output to the console
    # python3 main.py $dir/numified_adjlist $dir/numified_path > $dir/starkra_output_$i.txt
    ./starkra $dir/numified_path $dir/numified_adjlist ../../src/starkra.masm | tee $dir/starkra_miden_output_$i.txt
    done
    echo
done
