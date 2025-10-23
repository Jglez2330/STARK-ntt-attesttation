
#Get all the directories in embench-iot
directories=$(find ../ZEKRA-STARK/embench-iot-applications/ -type d -mindepth 1 -maxdepth 1)
runs=5
# Execute runs times
for dir in $directories; do
    for i in $(seq 1 $runs); do
    echo "$dir/starkra_output_$i.txt"
    # call the ZEKRA erunnner and store the output in a file
    python3 main.py $dir/numified_adjlist $dir/numified_path > $dir/starkra_output_$i.txt
    done
    echo
done
