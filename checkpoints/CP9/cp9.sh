#!/bin/bash

set -x
rm -r ./log
mkdir ./log
cd ../../build || exit;cmake .. -DTEST_TCP_DEBUG=on -DTEST_IP_ETHER_DEBUG=off;make;
cd ../vnetUtils/helper || exit
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


sudo ./execNS ns2 ../../build/tests/ip/host_manager \
../../checkpoints/CP9/setup.action \
1>/dev/null \
2>/dev/null &

sudo ./execNS ns3 ../../build/tests/ip/host_manager \
../../checkpoints/CP9/setup.action \
1>/dev/null \
2>/dev/null &

sudo ./execNS ns4 sudo ../../build/tests/tcp/echo_server \
2> ../../checkpoints/CP9/log/server.log &

sudo ./execNS ns1 sudo ../../build/tests/tcp/echo_client 10.100.3.2 \
2> ../../checkpoints/CP9/log/client.log

sudo ./delNS ns1
sudo ./delNS ns2
sudo ./delNS ns3
sudo ./delNS ns4