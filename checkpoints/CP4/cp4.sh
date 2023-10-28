#!/bin/bash

set -x
rm -r ./log
mkdir ./log
cd ../../vnetUtils/helper
sudo ./addNS ns1
sudo ./addNS ns2
sudo ./addNS ns3
sudo ./addNS ns4
sudo ./connectNS ns1 ns2 veth1-2 veth2-1 10.100.1
sudo ./connectNS ns2 ns3 veth2-3 veth3-2 10.100.2
sudo ./connectNS ns3 ns4 veth3-4 veth4-3 10.100.3

sudo ./execNS ns1 sudo ./bypassKernel
sudo ./execNS ns2 sudo ./bypassKernel
sudo ./execNS ns3 sudo ./bypassKernel
sudo ./execNS ns4 sudo ./bypassKernel

sudo ./execNS ns1 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns1_action.txt \
1> ../../checkpoints/CP4/log/ns1_cli.log \
2> ../../checkpoints/CP4/log/ns1_trace.log &

sudo ./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns2_action.txt \
1> ../../checkpoints/CP4/log/ns2_cli.log \
2> ../../checkpoints/CP4/log/ns2_trace.log &

sudo ./execNS ns3 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns3_action.txt \
1> ../../checkpoints/CP4/log/ns3_cli.log \
2> ../../checkpoints/CP4/log/ns3_trace.log &

sudo ./execNS ns4 ../../build/tests/ip/host_manager \
../../checkpoints/CP4/action/ns4_action.txt \
1> ../../checkpoints/CP4/log/ns4_cli.log \
2> ../../checkpoints/CP4/log/ns4_trace.log &

wait

sudo ./delNS ns1
sudo ./delNS ns2
sudo ./delNS ns3
sudo ./delNS ns4

