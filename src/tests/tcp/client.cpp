#include "../../include/ARP.h"
#include "../../include/callback.h"
#include "../../include/debug.h"
#include "../../include/device.h"
#include "../../include/IP.h"
#include "../../include/route.h"
#include "../../include/type.h"
#include "../../include/utils.h"
#include "../../include/socket.h"
#include "../../include/TCP.h"

int main()
{
    printf("Set up the Host.\n");
    activateDeviceManager();
    setUpHost();

    printAllAddedDevice();

    int test_fd = __wrap_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr_in;
    addr_in.sin_addr.s_addr = 10 + (100 << 8) + (1 << 16) + (2 << 24);
    addr_in.sin_port = 10000;
    
    __wrap_connect(test_fd, (sockaddr *)(&addr_in), sizeof(addr_in));

    char buf1[3];
    char buf2[3];
    __wrap_read(test_fd, buf1, 3);
    printf("Read %s from server.\n", buf1);

    __wrap_close(test_fd);
    printf("Close client.\n");
    sleep(5);
}