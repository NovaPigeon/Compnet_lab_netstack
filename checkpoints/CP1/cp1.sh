cd ../../build
make
set -x
cd ../vnetUtils/examples
sudo ./makeVNet <example.txt
cd ../helper/
sudo ./execNS ns3 ifconfig
sudo ./execNS ns3 ../../build/tests/ethernet/test_device_manager ../../checkpoints/CP1/cp1.txt 2> ../../checkpoints/CP1/cp1_info.log
cd ../examples/
sudo ./removeVNet <example.txt
set +x
exit