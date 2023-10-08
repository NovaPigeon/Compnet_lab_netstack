# 1 Lab 1: Link-layer

## 1.1 Writing Task 1(WT1).

> Open trace.pcap with Wireshark. First set filter to eth.src == 6a:15:0a:ba:9b:7c to only reserve Ethernet frames with source address 6a:15:0a:ba:9b:7c. Find the third frame in the filtered results and answer the following questions.
>
> 1. How many frames are there in the filtered results? (Hint: see the status bar)
> 2. What is the destination address of this Ethernet frame and what makes this address special?
> 3. What is the 71th byte (count from 0) of this frame?

The third frame in the filtered results is:

| No. | Time     | Source  | Destination     | Protocol | Length | Info                                      |
| --- | -------- | ------- | --------------- | -------- | ------ | ----------------------------------------- |
| 12  | 1.068164 | 0.0.0.0 | 255.255.255.255 | DHCP     | 342    | DHCP Discover - Transaction ID 0x13699715 |

1. There are 827 frames in the filtered results.
2. ff:ff:ff:ff:ff:ff, the broadcast address.

   > Frames are addressed to reach every computer on a given LAN segment if they are addressed to MAC address FF:FF:FF:FF:FF:FF. Ethernet frames that contain IP broadcast packages are usually sent to this address.
   > *__by Wikipedia__*
3. 0x15.

## 1.2 Programming Task 1(PT1).

## 1.3 Programming Task 2(PT2).
## 1.4 Checkpoint 1(CP1).
## 1.5 Checkpoint 2(CP2).