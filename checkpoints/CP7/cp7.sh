#!/bin/bash

set -x
rm -r ./log
mkdir ./log
cd ../../build || exit;cmake .. -DTEST_TCP_DEBUG=on -DTEST_IP_ETHER_DEBUG=off;make;
cd ../vnetUtils/helper || exit
sudo ./addNS ns1
sudo ./addNS ns2
sudo ./connectNS ns1 ns2 veth1-2 veth2-1 10.100.1

sudo ./execNS ns1 sudo ./bypassKernel
sudo ./execNS ns2 sudo ./bypassKernel

sudo ./execNS ns1 tcpdump -n -c 1 -i veth1-2 -Q out -w ../../checkpoints/CP7/capture.pcap tcp &
sleep 1
#../build/tests/tcp
sudo ./execNS ns2 sudo ../../build/tests/tcp/server \
2> ../../checkpoints/CP7/log/server.log &

sudo ./execNS ns1 sudo ../../build/tests/tcp/client  \
2> ../../checkpoints/CP7/log/client.log &

wait
tcpdump -XX -r ../../checkpoints/CP7/capture.pcap

sudo ./delNS ns1
sudo ./delNS ns2
exit