cd CLSAG
echo "CLSAG" >> ../out.txt
echo "" >> ../out.txt

for i in 1 2; do
    cargo test bench_sign -- --nocapture
    cargo test bench_verify -- --nocapture
    cargo test bench_size -- --nocapture
done 
cargo test bench_sign -- --nocapture >> ../out.txt
cargo test bench_verify -- --nocapture >> ../out.txt
cargo test bench_size -- --nocapture >> ../out.txt

cd ..

cd DualDory 
echo "DualDory" >> ../out.txt
echo "" >> ../out.txt

for i in 1 2; do
    go run bench/main.go
done
go run bench/main.go >> ../out.txt 

cd .. 

cd LRS 
echo "LRS" >> ../out.txt
echo "" >> ../out.txt

for i in 1 2; do 
    go run example.go
done
go run example.go >> ../out.txt

cd .. 

cd Raptor 
echo "Raptor" >> ../out.txt
echo "" >> ../out.txt

for i in 1 2; do
    ./bench.sh
done 
./bench.sh >> ../out.txt

cd .. 

cd TRS 
echo "TRS" >> ../out.txt
echo "" >> ../out.txt

for i in 1 2; do
    cargo test proof_time_bench -- --nocapture
    cargo test verify_time_bench -- --nocapture
    cargo test trace_time_bench -- --nocapture
    cargo test proof_size
done
cargo test proof_time_bench -- --nocapture >> ../out.txt
cargo test verify_time_bench -- --nocapture >> ../out.txt
cargo test trace_time_bench -- --nocapture >> ../out.txt
cargo test proof_size >> ../out.txt

cd ..

cd U2SSO
echo "U2SSO" >> ../out.txt
echo "" >> ../out.txt
cd crypto-snark
echo "snark" >> ../../out.txt
echo "" >> ../../out.txt

for i in 1 2; do 
    npm test
done
npm test >> ../../out.txt
cd ..

cd crypto-dbpoe
echo "dbpoe" >> ../../out.txt
echo "" >> ../../out.txt

for i in 1 2; do 
    ./tests
done
./tests >> ../../out.txt
cd ..
cd ..