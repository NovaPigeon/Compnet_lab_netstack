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

sudo ./execNS ns1 sudo tc qdisc add dev veth1-2 root netem loss 20%
sudo ./execNS ns2 sudo tc qdisc add dev veth2-1 root netem loss 20%

sudo ./execNS ns1 tcpdump -n -i veth1-2 -w ../../checkpoints/CP8/capture.pcap tcp &
sleep 1
#../build/tests/tcp
sudo ./execNS ns2 sudo ../../build/tests/tcp/echo_server \
2> ../../checkpoints/CP8/log/server.log &

sudo ./execNS ns1 sudo ../../build/tests/tcp/echo_client 10.100.1.2  \
2> ../../checkpoints/CP8/log/client.log &

wait %2

sudo ./delNS ns1
sudo ./delNS ns2
exit