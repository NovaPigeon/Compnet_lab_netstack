set -x

C=`pwd`
cd ../../build;make
cd ../vnetUtils/examples/
sudo ./makeVNet <example.txt
cd ../helper/
veth0_3=`sudo ./execNS ns0 ifconfig | $C/getEther.py veth0-3`
veth1_2=`sudo ./execNS ns1 ifconfig | $C/getEther.py veth1-2`
veth2_1=`sudo ./execNS ns2 ifconfig | $C/getEther.py veth2-1`
veth2_3=`sudo ./execNS ns2 ifconfig | $C/getEther.py veth2-3`
veth3_0=`sudo ./execNS ns3 ifconfig | $C/getEther.py veth3-0`
veth3_2=`sudo ./execNS ns3 ifconfig | $C/getEther.py veth3-2`
veth3_4=`sudo ./execNS ns3 ifconfig | $C/getEther.py veth3-4`
veth4_3=`sudo ./execNS ns4 ifconfig | $C/getEther.py veth4-3`
sudo ./execNS ns2 ../../build/tests/ethernet/set_receiver veth2-1 10 1>../../checkpoints/CP2/t.log 2>/dev/null &
sudo ./execNS ns1 ../../build/tests/ethernet/test_ethernet veth1-2 $veth2_1 2>/dev/null &
wait
cd ../examples/
sudo ./removeVNet <example.txt
exit
