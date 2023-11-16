#include "../include/socket.h"
#include "../include/TCP.h"
#include "../include/device.h"
#include "../include/debug.h"

int __wrap_socket(int domain, int type, int protocol)
{
    if (domain != AF_INET || type != SOCK_STREAM)
    {
        dbg_tcp_printf("[ERROR][socket()] The function not implemented: domain %d, type: %d.\n",domain,type);
        return -1;
    }
    fd_t sockfd = allocSocketfd();
    if (sockfd == -1)
    {
        dbg_tcp_printf("[ERROR][socket()] No available socketfd exists.\n");
        return -1;
    }
    setUpHost();
    TCB *sock = new TCB(domain, type, IPPROTO_TCP, sockfd);
    addSocket(sockfd,sock);

    dbg_tcp_printf("[INFO][socket()] Allocate socket %d.\n",sock->sockfd);
    return sockfd;
}

int __wrap_bind(int socket, const struct sockaddr *address,
                socklen_t address_len)
{
    dbg_tcp_printf("[INFO][bind()]:\n");
    if (((sockaddr_in *)address)->sin_family != AF_INET)
    {
        dbg_tcp_printf("[ERROR][bind()] Address family error: %d.\n",
                   ((sockaddr_in *)address)->sin_family);
        return -1;
    }
    if (address_len != sizeof(struct sockaddr))
    {
        dbg_tcp_printf("[ERROR][bind()] Address len error: %ld and %d.\n",
                   sizeof(struct sockaddr), address_len);
        return -1;
    }
    in_port_t port = ((sockaddr_in *)address)->sin_port;
    ip_addr_t ip;
    ip.s_addr = ((sockaddr_in *)address)->sin_addr.s_addr;

    char ip_str[IP_STR_LEN];
    ip_addr_to_str(ip, ip_str);

    if (ip.s_addr == INADDR_ANY)
    {
        Device *dev_tmp = getDevice(0);
        if (dev_tmp == nullptr)
        {
            dbg_tcp_printf("[ERROR][bind()] The host dosn't have valid device.\n");
            return -1;
        }
        ip.s_addr = dev_tmp->getDeviceIP().s_addr;
    }
    printAllAddedDevice();
    Device *dev = getDeviceByIP(ip);
    if (dev == nullptr)
    {
        dbg_tcp_printf("[ERROR][bind()] Invalid IP address: %s.\n", ip_str);
        return -1;
    }

    in_port_t port_alloc = -1;
    port_alloc = dev->allocPort(port);
    if (port_alloc == -1)
    {
        dbg_tcp_printf("[ERROR][bind()] Invalid Port: %d.\n", port);
        return -1;
    }

    TCB *sock = findSocket(socket);
    if (sock == nullptr)
    {
        dbg_tcp_printf("[ERROR][bind()] Invalid Sockfd: %d.\n", socket);
        return -1;
    }
    if (sock->is_bind == true)
    {
        dbg_tcp_printf("[ERROR][bind()] Socket has been bind: %d.\n", socket);
        return -1;
    }

    sock->is_bind = true;
    sock->local_addr.sin_family = AF_INET;
    sock->local_addr.sin_addr.s_addr = ip.s_addr;
    sock->local_addr.sin_port = port_alloc;

    dbg_tcp_printf("[INFO][bind()] Socket %d binded to (%s: %d).\n",
                  sock->sockfd,
                  ip_str,
                  port_alloc);
    return 0;
}

int __wrap_listen(int socket, int backlog)
{
    dbg_tcp_printf("[INFO][listen()] Socket %d; backlog %d;\n",socket,backlog);
    TCB *sock = findSocket(socket);
    if (sock == nullptr)
    {
        dbg_tcp_printf("[ERROR][listen()] Invalid Sockfd: %d.\n", socket);
        return -1;
    }
    sock->state_mutex.lock();
    if (sock->is_bind == false)
    {
        dbg_tcp_printf("[ERROR][listen()] The socket %d has not been bind.\n", socket);
        sock->state_mutex.unlock();
        return -1;
    }
    if (sock->is_listen == true)
    {
        dbg_tcp_printf("[ERROR][listen()] The socket %d is already listener socket.\n", socket);
        sock->state_mutex.unlock();
        return -1;
    }
    if (sock->state != TCP_STATE::CLOSED)
    {
        dbg_tcp_printf("[ERROR][listen()] The socket %d is not in valid state.\n", socket);
        sock->state_mutex.unlock();
        return -1;
    }
    sock->is_listen = true;
    sock->state_mutex.unlock();
    sock->change_state(TCP_STATE::LISTEN);
    ListenerSocket *listener = new ListenerSocket(socket, sock->local_addr, backlog);
    addListener(listener);
    return 0;
}

int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len)
{
    dbg_tcp_printf("[INFO][connect()]:\n");
    TCB *sock = findSocket(socket);
    if (sock == nullptr)
    {
        dbg_tcp_printf("[ERROR][connect()] The sockfd %d is invalid.\n", socket);
        return -1;
    }
    sock->state_mutex.lock();
    if(sock->is_bind==false)
    {
        sock->local_addr.sin_addr.s_addr=getDevice(0)->getDeviceIP().s_addr;
        sock->local_addr.sin_port=getDevice(0)->allocPort(0);
        sock->is_bind=true;
    }
    if (sock->is_in_listen_queue == true or sock->is_listen == true)
    {   
        dbg_tcp_printf("[ERROR][connect()] The socket %d is listener or in listen queue.\n",sock->sockfd);
        sock->state_mutex.unlock();
        return -1;
    }

    sock->iss = rand() % TCP_MAX_SEQ;
    sock->snd_una = sock->iss;
    sock->snd_nxt = sock->iss + 1;
    sock->remote_addr.sin_addr.s_addr = ((sockaddr_in *)address)->sin_addr.s_addr;
    sock->remote_addr.sin_port = ((sockaddr_in *)address)->sin_port;

    sock->is_set_remote=true;

    char ip_src_str[IP_STR_LEN];
    char ip_dst_str[IP_STR_LEN];
    ip_addr_to_str(sock->local_addr.sin_addr,ip_src_str);
    ip_addr_to_str(sock->remote_addr.sin_addr,ip_dst_str);
    dbg_tcp_printf("[INFO][connect()] The socket %d: (%s:%d, %s:%d).\n",
                    socket,
                    ip_src_str,
                    sock->local_addr.sin_port,
                    ip_dst_str,
                    sock->remote_addr.sin_port);

    dbg_tcp_printf("[INFO][connect()] Socket %d Send <SEQ=ISS(%d)><CTL=SYN>\n",socket,sock->iss);
    sock->sendTCPControlSegment(TCP_SYN_FLAG, sock->iss, 0);
    sock->state_mutex.unlock();
    sock->change_state(TCP_STATE::SYN_SENT);
    
    

    int cnt=1;
    while (true)
    {
        if (sock->state.load() == TCP_STATE::ESTAB)
        {
            dbg_tcp_printf("[INFO][connect()] Connect successfully.\n");
            return 0;
        }
        else
        {
            dbg_tcp_printf("[INFO][connect()] Resend SYN %d: Socket %d send<SEQ=ISS(%d)><CTL=SYN>\n", cnt, socket, sock->iss);
            sock->sendTCPControlSegment(TCP_SYN_FLAG, sock->iss, 0);
        }
        sleep(TCP_HANDSHAKE_RESENT_TIME);
        cnt++;
        if(cnt==20)
            return -1;
    }
    return -1;
}

int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len)
{
    dbg_tcp_printf("[INFO][accept()]:\n");
    TCB *sock = findSocket(socket);
    if (sock == nullptr)
    {
        dbg_tcp_printf("[ERROR][accept()] The sockfd %d is invalid.\n", socket);
        return -1;
    }
    sock->state_mutex.lock();
    if (sock->is_listen == false)
    {
        sock->state_mutex.unlock();
        return -1;
    }

    ListenerSocket *l_sock=getListener(socket);

    TCB *sock_acc = nullptr;
    sock->state_mutex.unlock();
    while (true)
    {
        l_sock->lisen_mutex.lock();
        if (l_sock->listen_queue.empty() == false)
        {
            sock_acc = l_sock->listen_queue[0];
            l_sock->listen_queue.erase(l_sock->listen_queue.begin());
            l_sock->lisen_mutex.unlock();
            break;
        }
        l_sock->lisen_mutex.unlock();
        sleep(TCP_HANDSHAKE_RESENT_TIME);
    }

    sock->state_mutex.lock();
    assert(sock_acc->state == TCP_STATE::LISTEN);
    sock_acc->is_in_listen_queue = false;
    sock_acc->iss = rand() % TCP_MAX_SEQ;
    sock_acc->snd_nxt = sock_acc->iss + 1;
    sock_acc->snd_una = sock_acc->iss;

    char ip_src_str[IP_STR_LEN];
    char ip_dst_str[IP_STR_LEN];
    ip_addr_to_str(sock_acc->local_addr.sin_addr, ip_src_str);
    ip_addr_to_str(sock_acc->remote_addr.sin_addr, ip_dst_str);
    dbg_tcp_printf("[INFO][accept()] Try to accept the socket with: (%s:%d, %s:%d).\n",
                   ip_src_str,
                   sock_acc->local_addr.sin_port,
                   ip_dst_str,
                   sock_acc->remote_addr.sin_port);

    dbg_tcp_printf("[INFO][accept()] Socket %d Send <SEQ=ISS(%d)><ACK=RCV.NXT(%d)><CTL=SYN,ACK>\n", socket, sock_acc->iss,sock_acc->rcv_nxt);
    sock_acc->sendTCPControlSegment(TCP_SYN_FLAG | TCP_ACK_FLAG, sock_acc->iss, sock_acc->rcv_nxt);

    int sock_acc_fd = allocSocketfd();
    sock_acc->sockfd = sock_acc_fd;
    sock_acc->is_bind = true;
    assert(sock_acc_fd >= 3);

    addSocket(sock_acc_fd,sock_acc);

    sock->state_mutex.unlock();
    sock_acc->change_state(TCP_STATE::SYN_RECV);

    while (true)
    {
        if (sock_acc->state.load() == TCP_STATE::ESTAB)
        {
            dbg_tcp_printf("[INFO][accept()] Accept successfully.\n");
            return sock_acc_fd;
        }
        dbg_tcp_printf("[INFO][accept()] Socket %d "
                       "Send <SEQ=ISS(%d)><ACK=RCV.NXT(%d)><CTL=SYN,ACK>\n", 
                       socket, sock_acc->iss, sock_acc->rcv_nxt);
        sock_acc->sendTCPControlSegment(TCP_SYN_FLAG | TCP_ACK_FLAG, sock_acc->iss, sock_acc->rcv_nxt);
        sleep(TCP_HANDSHAKE_RESENT_TIME);
    }
    assert(true);
    return -1;
}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte)
{
    dbg_tcp_printf("[INFO][read()]:\n");
    TCB *sock = findSocket(fildes);
    if (sock == nullptr)
    {
        dbg_tcp_printf("[ERROR][read()] The sockfd %d is invalid.\n", fildes);
        return -1;
    }
    sock->state_mutex.lock();
    if (sock->is_listen == true)
    {
        dbg_tcp_printf("[ERROR][read()] The sockfd %d is listener socket",fildes);
        sock->state_mutex.unlock();
        return -1;
    }
    if (sock->state == TCP_STATE::CLOSED)
    {
        dbg_tcp_printf("[ERROR][read()] Connection does not exist.\n");
        sock->state_mutex.unlock();
        return -1;
    }
    if (sock->state == TCP_STATE::CLOSING or
        sock->state == TCP_STATE::LAST_ACK or
        sock->state == TCP_STATE::TIME_WAIT)
    {
        dbg_tcp_printf("[ERROR][read()] Connection closing.\n");
        sock->state_mutex.unlock();
        return -1;
    }
    if (sock->state == TCP_STATE::LISTEN or
        sock->state == TCP_STATE::SYN_SENT or
        sock->state == TCP_STATE::SYN_RECV)
    {
        sock->state_mutex.unlock();
        while (true)
        {
            if (sock->state.load() == TCP_STATE::ESTAB)
            {
                sock->state_mutex.lock();
                break;
            }
        }
    }
    if (sock->state == TCP_STATE::ESTAB or
        sock->state == TCP_STATE::FINWAIT_1 or
        sock->state == TCP_STATE::FINWAIT_2 or
        sock->state == TCP_STATE::CLOSE_WAIT)
    {
        if (sock->state == TCP_STATE::CLOSE_WAIT)
        {
            if (sock->readbuffed_size.load() == 0)
            {
                dbg_tcp_printf("[ERROR][read()] Connection closing.\n");
                sock->state_mutex.unlock();
                return 0;
            }
        }
        else
        {
            int cnt=0;
            while (true)
            {
                //dbg_tcp_printf("A1.2 %d %d.\n", sock->readbuffed_size.load() , nbyte);
                if (sock->readbuffed_size!=0)
                    break;
                sleep(1);
                cnt++;
                if(cnt==50)
                {
                    sock->state_mutex.unlock();
                    return 0;
                }
            }
        }
        sock->readbuf_mutex.lock();
        nbyte = sock->readbuffed_size.load() < nbyte ? sock->readbuffed_size.load() : nbyte;
        nbyte = nbyte<=TCP_MAX_SEG_LEN?nbyte:TCP_MAX_SEG_LEN;
        //std::sort(sock->read_buffer.begin(),sock->read_buffer.end(),TCPPacketSort);
        int read_byte_cnt = 0;
        int tcp_pkt_cnt = 0;
        for (int i = 0; i < sock->read_buffer.size(); ++i)
        {
            int seg_len = sock->read_buffer[i]->phdr.tcp_len - TCP_HDR_LEN;
            int seg_read_len = nbyte - read_byte_cnt < seg_len ? nbyte - read_byte_cnt : seg_len;
            if (seg_read_len == seg_len)
            {
                tcp_pkt_cnt++;
                memcpy((u_char *)buf + read_byte_cnt, sock->read_buffer[i]->payload, seg_read_len);
            }
            else
            {
                memcpy((u_char *)buf + read_byte_cnt, sock->read_buffer[i]->payload, seg_read_len);
                u_char *new_payload = (u_char *)malloc(seg_len - seg_read_len);
                memcpy(new_payload, sock->read_buffer[i]->payload+seg_read_len, seg_len - seg_read_len);
                free(sock->read_buffer[i]->payload);
                sock->read_buffer[i]->payload = new_payload;
                sock->read_buffer[i]->phdr.tcp_len = TCP_HDR_LEN + seg_len - seg_read_len;
            }
            read_byte_cnt += seg_read_len;
            if (read_byte_cnt >= nbyte)
            {
                break;
            }
        }

        for (int i = 0; i < tcp_pkt_cnt; ++i)
        {
            delete sock->read_buffer[0];
            sock->read_buffer.erase(sock->read_buffer.begin());
        }
        
        sock->readbuffed_size.store(sock->readbuffed_size.load() - read_byte_cnt);
        sock->rcv_wnd += read_byte_cnt;
        assert(sock->rcv_wnd + sock->readbuffed_size == TCP_WINDOW_SIZE);
        sock->readbuf_mutex.unlock();
        dbg_tcp_printf("[INFO][read()] Socket %d read %d bytes, data[0]=%d.\n",sock->sockfd,read_byte_cnt,(int)(*(char *)buf));
        sock->state_mutex.unlock();
        return read_byte_cnt;
    }
    sock->state_mutex.unlock();
    return -1;
}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte)
{
    dbg_tcp_printf("[INFO][write()]: data[0]=%d.\n",(int)(*(char *)buf));
    TCB *sock=findSocket(fildes);
    if(sock==nullptr)
    {
        dbg_tcp_printf("[ERROR][write()] The sockfd %d is invalid.\n", fildes);
        return -1;
    }
    sock->state_mutex.lock();
    if(sock->is_listen or sock->state==TCP_STATE::LISTEN)
    {
        dbg_tcp_printf("[ERROR][write()] The sockfd %d state is LISTEN .\n", fildes);
        sock->state_mutex.unlock();
        return -1;
    }
    if(sock->state==TCP_STATE::CLOSED)
    {
        dbg_tcp_printf("[ERROR][write()] Connection %d does not exist.\n", fildes);
        sock->state_mutex.unlock();
        return -1;
    }
    if(sock->state==TCP_STATE::SYN_SENT or sock->state==TCP_STATE::SYN_RECV)
    {
        sock->state_mutex.unlock();
        while(true)
        {
            if(sock->state==TCP_STATE::ESTAB)
            {
                sock->state_mutex.lock();
                break;
            }
        }
    }
    if(sock->state==TCP_STATE::ESTAB or sock->state==TCP_STATE::CLOSE_WAIT)
    {
            int byte_sent=nbyte<TCP_MAX_SEG_LEN?nbyte:TCP_MAX_SEG_LEN;
            TCPPacket *pkt=new TCPPacket();
            memset(&(pkt->hdr), 0, sizeof(pkt->hdr));
            
            pkt->hdr.ack=1;
            pkt->hdr.th_sport = sock->local_addr.sin_port;
            pkt->hdr.th_dport = sock->remote_addr.sin_port;
            pkt->hdr.th_seq = sock->snd_nxt;
            pkt->hdr.th_ack = sock->rcv_nxt;
            pkt->hdr.th_win = sock->rcv_wnd;
            pkt->hdr.th_off = TCP_HDR_LEN/4;

            ip_addr_t ip_src, ip_dst;
            ip_src.s_addr = sock->local_addr.sin_addr.s_addr;
            ip_dst.s_addr = sock->remote_addr.sin_addr.s_addr;
            pkt->phdr = TCPPseudoHead(ip_src, ip_dst, IPPROTO_TCP, byte_sent+TCP_HDR_LEN);
            pkt->computeTCPCheckSum();

            
            pkt->payload = (u_char *)malloc(byte_sent);
            memcpy(pkt->payload, (u_char *)buf, byte_sent);


            pkt->computeTCPCheckSum();
            pkt->TCPhtons();

            char ip_src_str[IP_STR_LEN];
            char ip_dst_str[IP_STR_LEN];
            ip_addr_to_str(ip_src,ip_src_str);
            ip_addr_to_str(ip_dst,ip_dst_str);
            dbg_tcp_printf("[INFO][write()] Write %d bytes from %s:%d to %s:%d. "
                        "Send <SEQ=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=ACK>\n",
                        byte_sent,
                        ip_src_str,
                        sock->local_addr.sin_port,
                        ip_dst_str,
                        sock->remote_addr.sin_port,
                        sock->snd_nxt,
                        sock->rcv_nxt
                        );
            u_char *pkt_sent=(u_char *)malloc(pkt->phdr.tcp_len);
            memcpy(pkt_sent,&(pkt->hdr),TCP_HDR_LEN);
            memcpy(pkt_sent+TCP_HDR_LEN,pkt->payload,byte_sent);
            sendIPPacket(ip_src,ip_dst,IPPROTO_TCP,pkt_sent,pkt->phdr.tcp_len);
            
            sock->snd_nxt = sock->snd_nxt + byte_sent;
            free(pkt_sent);

            sock->retrans_mutex.lock();
            sock->retransmit_queue.push_back(pkt);
            sock->retrans_mutex.unlock();
        sock->state_mutex.unlock();
        return byte_sent;
    }
    else
    {
        dbg_tcp_printf("[ERROR][write()] The sockfd %d: connection closing.\n", fildes);
        sock->state_mutex.unlock();
        return -1;
    }
    sock->state_mutex.unlock();
    return -1;
}

ssize_t __wrap_close(int fildes)
{
    dbg_tcp_printf("[INFO][close()]:\n");
    TCB *sock=findSocket(fildes);
    if(sock==nullptr)
    {
        dbg_tcp_printf("[ERROR][close()] The sockfd %d is invalid.\n", fildes);
        return -1;
    }
    //sock->state_mutex.lock();
    if(sock->state==TCP_STATE::CLOSED)
    {
        if(sock->is_set_remote==true)
        {
            dbg_tcp_printf("[ERROR][close()] The connection %d does not exist.\n", fildes);
            //sock->state_mutex.unlock();
            return -1;
        }
        else
        {
            //sock->state_mutex.unlock();
            freeSocket(sock);
            dbg_tcp_printf("[INFO][close()] Socket %d close successfully.\n", fildes);
            return 0;
        }
    }

    if(sock->state==TCP_STATE::LISTEN)
    {
        //sock->state_mutex.unlock();
        sock->change_state(TCP_STATE::CLOSED);
        freeSocket(sock);
        dbg_tcp_printf("[INFO][close()] Socket %d close successfully.\n", fildes);
        return 0;
    }
    if(sock->state==TCP_STATE::SYN_SENT)
    {
        //sock->state_mutex.unlock();
        sock->change_state(TCP_STATE::CLOSED);
        sock->clearReadbuffer();
        sock->clearRetransQueue();
        freeSocket(sock);
        dbg_tcp_printf("[INFO][close()] Socket %d close successfully.\n", fildes);
        return 0;
    }
    if(sock->state==TCP_STATE::SYN_RECV)
    {
        //sock->state_mutex.unlock();
        sock->change_state(TCP_STATE::FINWAIT_1);
        dbg_tcp_printf("[INFO][close()] Socket %d send FIN/ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=FIN,ACK>.\n",
                       sock->sockfd,
                       sock->snd_nxt,
                       sock->rcv_nxt);
        sock->sendTCPControlSegment(TCP_FIN_FLAG|TCP_ACK_FLAG,sock->snd_nxt,sock->rcv_nxt);
        sock->snd_nxt=sock->snd_nxt+1;
        
        while(sock->state!=TCP_STATE::CLOSED)
        {
            dbg_tcp_printf("[INFO][close()] Socket %d resend FIN/ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=FIN,ACK>.\n",
                           sock->sockfd,
                           sock->snd_nxt,
                           sock->rcv_nxt);
            sock->sendTCPControlSegment(TCP_FIN_FLAG | TCP_ACK_FLAG, sock->snd_nxt-1, sock->rcv_nxt);
            sleep(TCP_FIN_RESENT_TIME);
        }
        dbg_tcp_printf("[INFO][close()] Socket %d close successfully.\n", fildes);
        return 0;
    }

    if(sock->state==TCP_STATE::ESTAB)
    {
        while(true)
        {
            sock->retrans_mutex.lock_shared();
            if(sock->retransmit_queue.empty())
            {
                sock->retrans_mutex.unlock_shared();
                break;
            }
            sock->retrans_mutex.unlock_shared();
        }
        if(sock->state!=TCP_STATE::ESTAB)
            goto CONTINUE;
        //sock->state_mutex.unlock();
        sock->change_state(TCP_STATE::FINWAIT_1);
        if (sock->state != TCP_STATE::FINWAIT_1)
            goto CONTINUE;
        dbg_tcp_printf("[INFO][close()] Socket %d send FIN/ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=FIN,ACK>.\n",
                       sock->sockfd,
                       sock->snd_nxt,
                       sock->rcv_nxt);
        sock->sendTCPControlSegment(TCP_FIN_FLAG | TCP_ACK_FLAG, sock->snd_nxt, sock->rcv_nxt);
        sock->snd_nxt = sock->snd_nxt + 1;
        while (sock->state != TCP_STATE::CLOSED)
        {
            dbg_tcp_printf("[INFO][close()] Socket %d resend FIN/ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=FIN,ACK>.\n",
                           sock->sockfd,
                           sock->snd_nxt,
                           sock->rcv_nxt);
            sock->sendTCPControlSegment(TCP_FIN_FLAG | TCP_ACK_FLAG, sock->snd_nxt-1, sock->rcv_nxt);
            sleep(TCP_FIN_RESENT_TIME);
        }
        dbg_tcp_printf("[INFO][close()] Socket %d close successfully.\n", fildes);
        return 0;
    }
    CONTINUE:
    if(sock->state==TCP_STATE::CLOSE_WAIT)
    {
        while (true)
        {
            sock->retrans_mutex.lock_shared();
            if (sock->retransmit_queue.empty())
            {
                sock->retrans_mutex.unlock_shared();
                break;
            }
            sock->retrans_mutex.unlock_shared();
        }
        //sock->state_mutex.unlock();
        sock->change_state(TCP_STATE::LAST_ACK);
        dbg_tcp_printf("[INFO][close()] Socket %d send FIN/ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=FIN,ACK>.\n",
                       sock->sockfd,
                       sock->snd_nxt,
                       sock->rcv_nxt);
        sock->sendTCPControlSegment(TCP_FIN_FLAG | TCP_ACK_FLAG, sock->snd_nxt, sock->rcv_nxt);
        sock->snd_nxt = sock->snd_nxt + 1;
        while (sock->state != TCP_STATE::CLOSED)
        {
            dbg_tcp_printf("[INFO][close()] Socket %d resend FIN/ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=FIN,ACK>.\n",
                           sock->sockfd,
                           sock->snd_nxt,
                           sock->rcv_nxt);
            sock->sendTCPControlSegment(TCP_FIN_FLAG | TCP_ACK_FLAG, sock->snd_nxt-1, sock->rcv_nxt);
            sleep(TCP_FIN_RESENT_TIME);
        }
        dbg_tcp_printf("[INFO][close()] Socket %d close successfully.\n",fildes);
        return 0;
    }
    if(sock->state==TCP_STATE::FINWAIT_1 
    or sock->state==TCP_STATE::FINWAIT_2
    or sock->state==TCP_STATE::CLOSING
    or sock->state==TCP_STATE::LAST_ACK
    or sock->state==TCP_STATE::TIME_WAIT)
    {
        dbg_tcp_printf("[ERROR][close()] Connection %d closing.\n",sock->sockfd);
        //sock->state_mutex.unlock();
        return -1;
    }
    
    assert(1);
    //sock->state_mutex.unlock();
    return -1;
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res)
{
    if (hints->ai_family == AF_INET && hints->ai_protocol == IPPROTO_TCP && hints->ai_socktype == SOCK_STREAM)
    {
        return getaddrinfo(node,service,hints,res);
    }
    else
    {
        dbg_tcp_printf("[ERROR][getaddrinfo()] The hints args does not support.\n");
        return -1;
    }
}

void __wrap_freeaddrinfo(struct addrinfo *ai)
{
    struct addrinfo *nxt = nullptr;
    for (auto *p = ai; p; p = nxt)
    {
        nxt = p->ai_next;
        if (p->ai_addr)
            delete p->ai_addr;
        delete p;
    }
    dbg_tcp_printf("[INFO][freeaddrinfo()] Free the addrinfo.\n");
}

int __wrap_setsockopt(int socket, int level, int option_name,
                      const void *option_value, socklen_t option_len)
{
    dbg_tcp_printf("[INFO][setsockopt()] Socket %d set opt.\n",socket);
    TCB *sock=findSocket(socket);
    if(sock==nullptr)
        return setsockopt(socket,level,option_name,option_value,option_len);
    return 0;
}
