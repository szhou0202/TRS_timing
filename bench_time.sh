start=$(date +%s.%N)
./run_benches.sh &
pid=$!

wait $pid

end=$(date +%s.%N)
echo "Elapsed: $(echo "$end - $start" | bc) seconds"
