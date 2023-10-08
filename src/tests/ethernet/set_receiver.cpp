#include "../../include/device.h"
#include "../../include/type.h"
#include "../../include/callback.h"
#include <mutex>

std::shared_timed_mutex mt_cnt;
DeviceManager m;
Device *dev;
int cnt=0;

int recvFrameCallback_new(const void *frame, int len, dev_id id)
{
    u_char *frame_ = (u_char *)frame;
    u_char src_mac[ETHER_ADDR_LEN];
    u_char dst_mac[ETHER_ADDR_LEN];
    uint64_t check_sum = 0;
    memcpy(dst_mac, frame_, ETHER_ADDR_LEN);
    memcpy(src_mac, frame_ + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    if(memcmp(dst_mac,dev->getDeviceMac(),ETHER_ADDR_LEN)!=0)
        return 0;
    uint16_t ethtype = ntohs(*(uint16_t *)(frame_ + ETHER_ADDR_LEN * 2));
    size_t payload_len = len - ETHER_CRC_LEN - ETHER_HDR_LEN;
    u_char *payload = (u_char *)malloc(payload_len+1);
    memset(payload,0,payload_len+1);
    memcpy(payload, frame_ + ETHER_HDR_LEN, payload_len);
    const char *name = m.getDevice(id)->getDeviceName();
    printf("[INFO] Device %s receive frame %d.\n"
           "src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "pay_load: %s\n"
           "pay_load_len: %ld\n"
           "ethtype: 0x%x\n\n",
           name,cnt,
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
           payload,
           payload_len,
           ethtype);
    free(payload);
    fflush(stdout);
    
    mt_cnt.lock();
    cnt++;
    mt_cnt.unlock();
    return 0;
}
int main(int argc, char **argv)
{
    if(argc!=3)
    {
        printf("[ERROR] usage: %s <dev_name> <recv_num>",argv[0]);
        return -1;
    }
    char *dev_name=argv[1];
    int recv_num=atoi(argv[2]);
    dev_id id=m.addDevice(dev_name);
    if(id==-1)
    {
        printf("[ERROR] %s: The device is invalid", argv[0]);
        return -1;
    }
    dev=m.getDevice(id);
    printf("[INFO] Device %s ready to receive %d frames.\n",dev_name,recv_num);
    dev->setFrameReceiveCallback(recvFrameCallback_new);
    while(true)
    {
        mt_cnt.lock_shared();
        if(cnt==recv_num)
        {
            mt_cnt.unlock_shared();
            dev->stopRecv();
            break;
        }
        mt_cnt.unlock_shared();
    }
    printf("[INFO] Device %s has received %d frames, expect %d frames.\n",dev_name,cnt,recv_num);
    printf("[INFO] Device %s stop receiving frames.\n",dev_name);
    fflush(stdout);
    return 0;
}