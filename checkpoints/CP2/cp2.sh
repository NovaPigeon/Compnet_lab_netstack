set -x

C=`pwd`
mkdir ./log
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

sudo ./execNS ns0 ../../build/tests/ethernet/test_ethernet veth0-3 $veth3_0 2>$C/log/ns0.log &
sudo ./execNS ns3 ../../build/tests/ethernet/test_ethernet veth3-0 $veth0_3 veth3-2 $veth2_3 veth3-4 $veth4_3 2>$C/log/ns3.log &
sudo ./execNS ns4 ../../build/tests/ethernet/test_ethernet veth4-3 $veth3_4 2>$C/log/ns4.log &
sudo ./execNS ns2 ../../build/tests/ethernet/test_ethernet veth2-1 $veth1_2 veth2-3 $veth3_2 2>$C/log/ns2.log &
sudo ./execNS ns1 ../../build/tests/ethernet/test_ethernet veth1-2 $veth2_1 2>$C/log/ns1.log &
wait
cd ../examples/
sudo ./removeVNet <example.txt
exit
