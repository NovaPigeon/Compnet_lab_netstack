C=`pwd`

set -x
rm -r ./log
mkdir ./log
cd ../../vnetUtils/helper
./addNS ns1
./addNS ns2
./addNS ns3
./addNS ns4
./addNS ns5
./addNS ns6
./connectNS ns1 ns2 veth1-2 veth2-1 10.100.1
./connectNS ns2 ns3 veth2-3 veth3-2 10.100.2
./connectNS ns3 ns4 veth3-4 veth4-3 10.100.3
./connectNS ns2 ns5 veth2-5 veth5-2 10.100.4
./connectNS ns5 ns6 veth5-6 veth6-5 10.100.5
./connectNS ns6 ns3 veth6-3 veth3-6 10.100.6

./execNS ns1 ./bypassKernel
./execNS ns2 ./bypassKernel
./execNS ns3 ./bypassKernel
./execNS ns4 ./bypassKernel
./execNS ns5 ./bypassKernel
./execNS ns6 ./bypassKernel

./execNS ns1 ../../build/tests/ip/host_manager \
../../checkpoints/CP5/action/ns1_action.txt \
1> ../../checkpoints/CP5/log/ns1_cli.log \
2> ../../checkpoints/CP5/log/ns1_trace.log &

./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP5/action/ns2_action.txt \
1> ../../checkpoints/CP5/log/ns2_cli.log \
2> ../../checkpoints/CP5/log/ns2_trace.log &

./execNS ns3 ../../build/tests/ip/host_manager \
../../checkpoints/CP5/action/ns3_action.txt \
1> ../../checkpoints/CP5/log/ns3_cli.log \
2> ../../checkpoints/CP5/log/ns3_trace.log &

./execNS ns4 ../../build/tests/ip/host_manager \
../../checkpoints/CP5/action/ns4_action.txt \
1> ../../checkpoints/CP5/log/ns4_cli.log \
2> ../../checkpoints/CP5/log/ns4_trace.log &

./execNS ns5 ../../build/tests/ip/host_manager \
../../checkpoints/CP5/action/ns5_action.txt \
1> ../../checkpoints/CP5/log/ns5_cli.log \
2> ../../checkpoints/CP5/log/ns5_trace.log &

./execNS ns6 ../../build/tests/ip/host_manager \
../../checkpoints/CP5/action/ns6_action.txt \
1> ../../checkpoints/CP5/log/ns6_cli.log \
2> ../../checkpoints/CP5/log/ns6_trace.log &

wait

./delNS ns1
./delNS ns2
./delNS ns3
./delNS ns4
./delNS ns5
./delNS ns6