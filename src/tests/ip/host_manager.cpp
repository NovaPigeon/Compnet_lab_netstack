#include "../../include/ARP.h"
#include "../../include/callback.h"
#include "../../include/debug.h"
#include "../../include/device.h"
#include "../../include/IP.h"
#include "../../include/route.h"
#include "../../include/type.h"
#include "../../include/utils.h"
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ifaddrs.h>

// 解析命令行参数并执行命令
void executeCommands(const std::string &filename = "")
{
    std::istream *input;
    std::ifstream fileStream;

    // 如果提供了文件名参数，则使用文件作为输入
    if (!filename.empty())
    {
        fileStream.open(filename);
        if (!fileStream.is_open())
        {
            std::cerr << "[ERROR][host_manager]: Failed to open file " << filename << std::endl;
            return;
        }
        input = &fileStream;
    }
    else
    {
        // 否则，使用标准输入
        input = &std::cin;
    }

    std::string line;
    while (std::getline(*input, line))
    {
        std::cout << "> " << line << std::endl;
        // 分割命令和参数
        std::vector<std::string> tokens;
        size_t pos = 0;
        while ((pos = line.find(' ')) != std::string::npos)
        {
            tokens.push_back(line.substr(0, pos));
            line.erase(0, pos + 1);
        }
        tokens.push_back(line); // 添加最后一个参数
        if (tokens.empty())
        {
            continue; // 忽略空行
        }

        // 解析命令
        const std::string &command = tokens[0];
        if (command == "activateDeviceManager")
        {
            printf("Activate the device manager.\n");
            activateDeviceManager();
        }
        else if(command == "deactivateHost")
        {
            printf("Deactivate the Host.\n");
            deactivateHost();
        }
        else if (command == "addDevice")
        {
            if (tokens.size() != 2)
            {
                std::cerr << "[ERROR][test_device_manager]: addDevice command requires 1 argument (device name)" << std::endl;
                continue;
            }
            activateDeviceManager();
            const char *deviceName = tokens[1].c_str();
            int ret = addDevice(deviceName);
            if (ret == -1)
                std::cerr << "[ERROR][test_device_manager]: addDevice faied" << std::endl;
            else
                std::cout << "Add device " << deviceName << " :ID " << ret << std::endl;
        }
        else if (command == "findDeviceByNmae")
        {
            if (tokens.size() != 2)
            {
                std::cerr << "[ERROR][test_device_manager]: findDeviceByName command requires 1 argument (device name)" << std::endl;
                continue;
            }
            const char *deviceName = tokens[1].c_str();
            Device *device = findDevice(deviceName);
            if (device)
            {
                std::cout << "Found device with name: " << deviceName << ";ID :" << device->getDeviceID() << std::endl;
            }
            else
            {
                std::cout << "Device not found with name: " << deviceName << std::endl;
            }
        }
        else if (command == "findAllAddedDevice")
        {
            printAllAddedDevice();
        }
        else if (command == "findAllValidDevice")
        {
            printAllValidDevice();
        }
        else if (command == "setRecv")
        {
            setIPPacketReceiveCallback(IP_recv_callback::recvIPCallback);
        }
        else if(command=="printARPCache")
        {
            printARPCache();
        }
        else if(command=="printRouteTable")
        {
            printRouteTable(STDOUT_FILENO);
        }
        else if(command=="sleep")
        {
            int time=atoi(tokens[1].c_str());
            printf("Sleep %d seconds.\n",time);
            sleep(time);
        }
        else if (command == "sendFrame")
        {
            if (tokens.size() != 3)
            {
                std::cerr << "[ERROR][test_device_manager]: sendFrame command requires 2 argument (srcDev and dstDev)" << std::endl;
                continue;
            }
            const char *srcDevName = tokens[1].c_str();
            const char *dstDevName = tokens[2].c_str();
            Device *srcDev = findDevice(srcDevName);
            if (srcDev == nullptr)
            {
                std::cerr << "[ERROR][test_device_manager]: sendFrame argument srcDev is invalid." << std::endl;
                continue;
            }
            Device *dstDev = findDevice(dstDevName);
            if (dstDev == nullptr)
            {
                std::cerr << "[ERROR][test_device_manager]: sendFrame argument dstDev is invalid." << std::endl;
                continue;
            }
            const u_char *srcMac = srcDev->getDeviceMac();
            const u_char *dstMac = dstDev->getDeviceMac();
            u_char buf[100];
            for (int i = 0; i < 100; ++i)
                buf[i] = (u_char)i;
            int ret = srcDev->sendFrame(buf, 100, ETHERTYPE_ARP, dstMac);
            if (ret == -1)
            {
                std::cerr << "ERROR: sendFrame ERROR." << std::endl;
                continue;
            }
            printf("Device %s with mac %02x:%02x:%02x:%02x:%02x:%02x and ID %d "
                   "send frame to.\n"
                   "Device %s with mac %02x:%02x:%02x:%02x:%02x:%02x and ID %d.\n",
                   srcDevName,
                   srcMac[0],
                   srcMac[1],
                   srcMac[2],
                   srcMac[3],
                   srcMac[4],
                   srcMac[5],
                   srcDev->getDeviceID(),
                   dstDevName,
                   dstMac[0],
                   dstMac[1],
                   dstMac[2],
                   dstMac[3],
                   dstMac[4],
                   dstMac[5],
                   dstDev->getDeviceID());
        }
        else if (command == "exit")
        {
            exit(0);
            return;
        }
        else if(command=="setUpHost")
        {
            printf("Set up the Host.\n");
            activateDeviceManager();
            setUpHost();

            setIPPacketReceiveCallback(IP_recv_callback::recvIPCallback);
            printf("Set IP receive callback.\n");
            printAllAddedDevice();
            printARPCache();
            printRouteTable(STDOUT_FILENO);
        }
        else if(command=="sendIPPacket")
        {
            std::string ip_src_str=tokens[1];
            std::string ip_dst_str=tokens[2];
            ip_addr_t ip_src;
            inet_aton(ip_src_str.c_str(),&ip_src);
            ip_addr_t ip_dst;
            inet_aton(ip_dst_str.c_str(),&ip_dst);
        
            u_char *pay_load=(u_char *)malloc(ETH_DATA_LEN);
            memset(pay_load,0,ETH_DATA_LEN);
            int pay_load_len = snprintf((char *)pay_load, ETH_DATA_LEN,
                                    "Hello! This is an IP packet from %s to %s.",
                                    ip_src_str.c_str(),
                                    ip_dst_str.c_str());
            printf("Host send an IP packet from %s to %s.\n",ip_src_str.c_str(),
                                    ip_dst_str.c_str());
            sendIPPacket(ip_src,ip_dst,0xfd,pay_load,pay_load_len);
            free(pay_load);
        }
        else
        {
            std::cerr << "[ERROR][test_device_manager]: Unknown command: " << command << std::endl;
        }
        std::cout << "> " << std::endl;
    }
    deactivateHost();
    if (fileStream.is_open())
    {
        fileStream.close();
    }
}

int main(int argc, char *argv[])
{
    
    // 检查是否提供了命令文件名作为命令行参数
    if (argc > 1)
    {
        const std::string filename = argv[1];
        executeCommands(filename);
    }
    else
    {
        // 否则，从标准输入读取命令
        executeCommands();
    }

    return 0;
}