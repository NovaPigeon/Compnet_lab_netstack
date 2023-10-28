#!/bin/bash

set -x
rm -r ./log
mkdir ./log
cd ../../vnetUtils/helper
sudo ./addNS ns1
sudo ./addNS ns2
sudo ./addNS ns3
sudo ./addNS ns4

sudo ./addVethPair veth1-2 veth2-1
sudo ./setNS veth1-2 ns1
sudo ./setNS veth2-1 ns2
sudo ./execNS ns1 sudo ./giveAddr veth1-2 192.24.0.1/19
sudo ./execNS ns2 sudo ./giveAddr veth2-1 192.24.0.2/19
sudo ./execNS ns1 sudo ./setRoute 192.24.0.0/19 veth1-2
sudo ./execNS ns2 sudo ./setRoute 192.24.0.0/19 veth2-1

sudo ./addVethPair veth2-3 veth3-2
sudo ./setNS veth2-3 ns2
sudo ./setNS veth3-2 ns3
sudo ./execNS ns2 sudo ./giveAddr veth2-3 192.24.16.1/20
sudo ./execNS ns3 sudo ./giveAddr veth3-2 192.24.16.2/20
sudo ./execNS ns2 sudo ./setRoute 192.24.16.0/20 veth2-3
sudo ./execNS ns3 sudo ./setRoute 192.24.16.0/20 veth3-2

sudo ./addVethPair veth2-4 veth4-2
sudo ./setNS veth2-4 ns2
sudo ./setNS veth4-2 ns4
sudo ./execNS ns2 sudo ./giveAddr veth2-4 192.24.8.1/22
sudo ./execNS ns4 sudo ./giveAddr veth4-2 192.24.8.2/22
sudo ./execNS ns2 sudo ./setRoute 192.24.8.0/22 veth2-4
sudo ./execNS ns4 sudo ./setRoute 192.24.8.0/22 veth4-2

sudo ./execNS ns1 sudo ./bypassKernel
sudo ./execNS ns2 sudo ./bypassKernel
sudo ./execNS ns3 sudo ./bypassKernel
sudo ./execNS ns4 sudo ./bypassKernel

sudo ./execNS ns1 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns1_action.txt \
1> ../../checkpoints/CP6/log/ns1_cli.log \
2> ../../checkpoints/CP6/log/ns1_trace.log &

sudo ./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns2_action.txt \
1> ../../checkpoints/CP6/log/ns2_cli.log \
2> ../../checkpoints/CP6/log/ns2_trace.log &

sudo ./execNS ns3 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns3_action.txt \
1> ../../checkpoints/CP6/log/ns3_cli.log \
2> ../../checkpoints/CP6/log/ns3_trace.log &

sudo ./execNS ns4 ../../build/tests/ip/host_manager \
../../checkpoints/CP6/action/ns4_action.txt \
1> ../../checkpoints/CP6/log/ns4_cli.log \
2> ../../checkpoints/CP6/log/ns4_trace.log &

wait

sudo ./delNS ns1
sudo ./delNS ns2
sudo ./delNS ns3
sudo ./delNS ns4