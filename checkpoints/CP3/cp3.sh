#!/bin/bash

set -x
rm -r ./log
mkdir ./log
cd ../../vnetUtils/helper
sudo ./addNS ns1
sudo ./addNS ns2
sudo ./connectNS ns1 ns2 veth1-2 veth2-1 10.100.1
sudo ./execNS ns1 sudo ./bypassKernel
sudo ./execNS ns2 sudo ./bypassKernel

sudo ./execNS ns2 tcpdump ip -i veth2-1 -X -vv -c 1 -w ../../checkpoints/CP3/ip_example.pcap &

sudo ./execNS ns1 ../../build/tests/ip/host_manager \
../../checkpoints/CP3/action/ns1_action.txt \
1> ../../checkpoints/CP3/log/ns1_cli.log \
2> ../../checkpoints/CP3/log/ns1_trace.log &

sudo ./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP3/action/ns2_action.txt \
1> ../../checkpoints/CP3/log/ns2_cli.log \
2> ../../checkpoints/CP3/log/ns2_trace.log &

wait

sudo ./delNS ns1
sudo ./delNS ns2

