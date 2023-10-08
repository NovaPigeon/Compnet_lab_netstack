#include "../include/device.h"
#include "../include/type.h"
#include "../include/callback.h"
#include <unistd.h>
int main()
{
    DeviceManager *manager=new DeviceManager();
    manager->printAllValidDevice();
    dev_id dev1_id=manager->addDevice("veth3-2");
    manager->findDevice("eth1");
    manager->findDevice("eth0");
    dev_id dev2_id=manager->addDevice("veth3-0");
    Device *dev1=manager->getDevice(dev1_id);
    printf("%d\n",dev1==nullptr);
    printf("%s %d\n",dev1->getDeviceName(),dev1->getDeviceID());
    dev1->stopRecv();
    dev1->setFrameReceiveCallback(nullptr);
    dev1->stopRecv();
    manager->printAllValidDevice();
    return 0;
}