
#Get all the directories in embench-iot
directories=$(find ../ZEKRA-STARK/embench-iot-applications/ -type d -mindepth 1 -maxdepth 1)
runs=5
# Execute runs times
for dir in $directories; do
    for i in $(seq 1 $runs); do
    echo "$dir/starkra_output_$i.txt"
    # call the ZEKRA erunnner and store the output in a file
    #it also prins the output to the console
    # python3 main.py $dir/numified_adjlist $dir/numified_path > $dir/starkra_output_$i.txt
    python3 -u main.py $dir/numified_adjlist $dir/numified_path | tee $dir/starkra_output_$i.txt
    done
    echo
done
