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

    setUpHost();
    //dev_manager->setIPPacketReceiveCallback(IP_recv_callback::recvIPCallback);
    //printf("Set IP receive callback.\n");

    int test_fd = __wrap_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr_in;
    addr_in.sin_addr.s_addr = 10 + (100 << 8) + (1 << 16) + (2 << 24);
    addr_in.sin_port = 10000;
    addr_in.sin_family=AF_INET;
    __wrap_bind(test_fd, (sockaddr *)(&addr_in), sizeof(addr_in));
    __wrap_listen(test_fd, 100);
    int new_sock=__wrap_accept(test_fd, NULL, NULL);
    printf("New conection %d.\n",new_sock);
    printf("Send ABC to client.\n");
    std::string buf = "ABC";
    __wrap_write(new_sock, buf.c_str(), 3);
    __wrap_close(new_sock);
    __wrap_close(test_fd);
    printf("Close server.\n");
    sleep(5);
}