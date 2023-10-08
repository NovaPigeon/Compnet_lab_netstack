get_ether_address() {
  set +x
  local device_name="$1"
  local ns="$2"
  local ifconfig_output  

  ifconfig_output=$(sudo ./execNS "$ns" ifconfig "$device_name" 2>/dev/null)

  if [ $? -ne 0 ]; then
    echo "Error: Device '$device_name' not found."
    return 1
  fi
  
  local ether_address=$(echo "$ifconfig_output" | grep -o 'ether [0-9a-fA-F:]*' | awk '{print $2}')

  echo "$ether_address"
  set -x
}

set -x

C=`pwd`
N=100
rm -r log
mkdir log
mkdir log/veth0_3 log/veth3_0 log/veth1_2 log/veth2_1 log/veth2_3 log/veth3_2 log/veth3_4 log/veth4_3
cd ../../build;make
cd ../vnetUtils/examples/
sudo ./makeVNet <example.txt
cd ../helper/

veth0_3=$(get_ether_address "veth0-3" "ns0")
veth1_2=$(get_ether_address "veth1-2" "ns1")
veth2_1=$(get_ether_address "veth2-1" "ns2")
veth2_3=$(get_ether_address "veth2-3" "ns2")
veth3_0=$(get_ether_address "veth3-0" "ns3")
veth3_2=$(get_ether_address "veth3-2" "ns3")
veth3_4=$(get_ether_address "veth3-4" "ns3")
veth4_3=$(get_ether_address "veth4-3" "ns4")

# veth0-3 and veth3-0

sudo ./execNS ns0 \
../../build/tests/ethernet/set_receiver veth0-3 $N \
1>../../checkpoints/CP2/log/veth0_3/veth0-3_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth0_3/veth0-3_receive_info.log &

sudo ./execNS ns3 \
../../build/tests/ethernet/set_receiver veth3-0 $N \
1>../../checkpoints/CP2/log/veth3_0/veth3-0_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth3_0/veth3-0_receive_info.log &

sudo ./execNS ns0 \
../../build/tests/ethernet/set_sender veth0-3 $veth3_0 $N \
1>../../checkpoints/CP2/log/veth0_3/veth0-3_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth0_3/veth0-3_send_info.log &

sudo ./execNS ns3 \
../../build/tests/ethernet/set_sender veth3-0 $veth0_3 $N \
1>../../checkpoints/CP2/log/veth3_0/veth3-0_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth3_0/veth3-0_send_info.log &

# veth1-2 and veth2-1

sudo ./execNS ns2 \
../../build/tests/ethernet/set_receiver veth2-1 $N \
1>../../checkpoints/CP2/log/veth2_1/veth2-1_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth2_1/veth2-1_receive_info.log &

sudo ./execNS ns1 \
../../build/tests/ethernet/set_receiver veth1-2 $N \
1>../../checkpoints/CP2/log/veth1_2/veth1-2_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth1_2/veth1-2_receive_info.log &

sudo ./execNS ns1 \
../../build/tests/ethernet/set_sender veth1-2 $veth2_1 $N \
1>../../checkpoints/CP2/log/veth1_2/veth1-2_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth1_2/veth1-2_send_info.log &

sudo ./execNS ns2 \
../../build/tests/ethernet/set_sender veth2-1 $veth1_2 $N \
1>../../checkpoints/CP2/log/veth2_1/veth2-1_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth2_1/veth2-1_send_info.log &

# veth2-3 and veth3-2

sudo ./execNS ns2 \
../../build/tests/ethernet/set_receiver veth2-3 $N \
1>../../checkpoints/CP2/log/veth2_3/veth2-3_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth2_3/veth2-3_receive_info.log &

sudo ./execNS ns3 \
../../build/tests/ethernet/set_receiver veth3-2 $N \
1>../../checkpoints/CP2/log/veth3_2/veth3-2_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth3_2/veth3-2_receive_info.log &

sudo ./execNS ns3 \
../../build/tests/ethernet/set_sender veth3-2 $veth2_3 $N \
1>../../checkpoints/CP2/log/veth3_2/veth3-2_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth3_2/veth3-2_send_info.log &

sudo ./execNS ns2 \
../../build/tests/ethernet/set_sender veth2-3 $veth3_2 $N \
1>../../checkpoints/CP2/log/veth2_3/veth2-3_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth2_3/veth2-3_send_info.log &

# veth3-4 and veth4-3

sudo ./execNS ns4 \
../../build/tests/ethernet/set_receiver veth4-3 $N \
1>../../checkpoints/CP2/log/veth4_3/veth4-3_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth4_3/veth4-3_receive_info.log &

sudo ./execNS ns3 \
../../build/tests/ethernet/set_receiver veth3-4 $N \
1>../../checkpoints/CP2/log/veth3_4/veth3-4_receive.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth3_4/veth3-4_receive_info.log &

sudo ./execNS ns3 \
../../build/tests/ethernet/set_sender veth3-4 $veth4_3 $N \
1>../../checkpoints/CP2/log/veth3_4/veth3-4_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth3_4/veth3-4_send_info.log &

sudo ./execNS ns4 \
../../build/tests/ethernet/set_sender veth4-3 $veth3_4 $N \
1>../../checkpoints/CP2/log/veth4_3/veth4-3_send.log \
2>/dev/null &
# 2>../../checkpoints/CP2/log/veth4_3/veth4-3_send_info.log &

wait
cd ../examples/
sudo ./removeVNet <example.txt
exit
