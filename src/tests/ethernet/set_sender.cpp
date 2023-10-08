#include "../../include/device.h"
#include "../../include/type.h"
#include "../../include/callback.h"
#include <unistd.h>

#define SEND_WAIT_TIME 30

int cnt=0;
DeviceManager m;
Device *dev;
int MySendFrame(Device *dev,int i,void *dst_mac)
{

}

int main(int argc,char **argv)
{
    if(argc!=4)
    {
        printf("[ERROR] usage: %s <dev_name> <dst_mac> <send_num>", argv[0]);
        return -1;
    }
    char *dev_name = argv[1];
    ether_addr dst_mac;
    if(!ether_aton_r(argv[2],&dst_mac))
    {
        printf("[ERROR] The dst_mac %s is invalid.\n",argv[2]);
        return -1;
    }
    int send_num = atoi(argv[3]);
    dev_id id = m.addDevice(dev_name);
    if (id == -1)
    {
        printf("[ERROR] %s: The device is invalid", argv[0]);
        return -1;
    }
    dev = m.getDevice(id);

    
    return 0;
}