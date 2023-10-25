C=`pwd`

set -x
rm -r ./log
mkdir ./log
cd ../../vnetUtils/helper
./addNS ns1
./addNS ns2
./addNS ns3
./addNS ns4
./connectNS ns1 ns2 veth1-2 veth2-1 10.100.1
./connectNS ns2 ns3 veth2-3 veth3-2 10.100.2
./connectNS ns3 ns4 veth3-4 veth4-3 10.100.3

./execNS ns1 ./bypassKernel
./execNS ns2 ./bypassKernel
./execNS ns3 ./bypassKernel
./execNS ns4 ./bypassKernel

./execNS ns1 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns1_action.txt \
1> ../../checkpoints/CP4/log/ns1_cli.log \
2> ../../checkpoints/CP4/log/ns1_trace.log &

./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns2_action.txt \
1> ../../checkpoints/CP4/log/ns2_cli.log \
2> ../../checkpoints/CP4/log/ns2_trace.log &

./execNS ns3 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns3_action.txt \
1> ../../checkpoints/CP4/log/ns3_cli.log \
2> ../../checkpoints/CP4/log/ns3_trace.log &

./execNS ns4 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns4_action.txt \
1> ../../checkpoints/CP4/log/ns4_cli.log \
2> ../../checkpoints/CP4/log/ns4_trace.log &

wait

./delNS ns1
./delNS ns2
./delNS ns3
./delNS ns4

