C=`pwd`

set -x
rm -r ./log
mkdir ./log
cd ../../vnetUtils/helper
./addNS ns1
./addNS ns2
./addNS ns3
./addNS ns4

./addVethPair veth1-2 veth2-1
./setNS veth1-2 ns1
./setNS veth2-1 ns2
./execNS ns1 ./giveAddr veth1-2 192.24.0.1/19
./execNS ns2 ./giveAddr veth2-1 192.24.0.2/19
./execNS ns1 ./setRoute 192.24.0.0/19 veth1-2
./execNS ns2 ./setRoute 192.24.0.0/19 veth2-1

./addVethPair veth2-3 veth3-2
./setNS veth2-3 ns2
./setNS veth3-2 ns3
./execNS ns2 ./giveAddr veth2-3 192.24.16.1/20
./execNS ns3 ./giveAddr veth3-2 192.24.16.2/20
./execNS ns2 ./setRoute 192.24.16.0/20 veth2-3
./execNS ns3 ./setRoute 192.24.16.0/20 veth3-2

./addVethPair veth2-4 veth4-2
./setNS veth2-4 ns2
./setNS veth4-2 ns4
./execNS ns2 ./giveAddr veth2-4 192.24.8.1/22
./execNS ns4 ./giveAddr veth4-2 192.24.8.2/22
./execNS ns2 ./setRoute 192.24.8.0/22 veth2-4
./execNS ns4 ./setRoute 192.24.8.0/22 veth4-2

./execNS ns1 ./bypassKernel
./execNS ns2 ./bypassKernel
./execNS ns3 ./bypassKernel
./execNS ns4 ./bypassKernel

./execNS ns1 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns1_action.txt \
1> ../../checkpoints/CP6/log/ns1_cli.log \
2> ../../checkpoints/CP6/log/ns1_trace.log &

./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns2_action.txt \
1> ../../checkpoints/CP6/log/ns2_cli.log \
2> ../../checkpoints/CP6/log/ns2_trace.log &

./execNS ns3 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns3_action.txt \
1> ../../checkpoints/CP6/log/ns3_cli.log \
2> ../../checkpoints/CP6/log/ns3_trace.log &

./execNS ns4 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns4_action.txt \
1> ../../checkpoints/CP6/log/ns4_cli.log \
2> ../../checkpoints/CP6/log/ns4_trace.log &

wait

./delNS ns1
./delNS ns2
./delNS ns3
./delNS ns4