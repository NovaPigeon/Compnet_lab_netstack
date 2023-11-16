#include "../include/TCP.h"
#include "../include/device.h"
#include "../include/IP.h"
#include "../include/socket.h"

std::string TCP_STATE_NAME(TCP_STATE state)
{
    switch (state)
    {
    case TCP_STATE::CLOSED:
        return "CLOSED";
    case TCP_STATE::LISTEN:
        return "LISTEN";
    case TCP_STATE::SYN_SENT:
        return "SYN_SENT";
    case TCP_STATE::SYN_RECV:
        return "SYN_RECV";
    case TCP_STATE::ESTAB:
        return "ESTAB";
    case TCP_STATE::FINWAIT_1:
        return "FINWAIT_1";
    case TCP_STATE::FINWAIT_2:
        return "FINWAIT_2";
    case TCP_STATE::CLOSING:
        return "CLOSING";
    case TCP_STATE::TIME_WAIT:
        return "TIME_WAIT";
    case TCP_STATE::CLOSE_WAIT:
        return "CLOSE_WAIT";
    case TCP_STATE::LAST_ACK:
        return "LAST_ACK";
    }
    return "UNKOWN";
}

fd_t DeviceManager::allocSocketfd()
{
    fd_t sockfd = -1;
    this->sockfds_alloc_mutex.lock();
    for (int i = 0; i <= TCP_MAX_SOCK_FD; ++i)
    {
        if (this->sockfd_alloc[i] == false)
        {
            this->sockfd_alloc[i] = true;
            sockfd = i;
            break;
        }
    }
    this->sockfds_alloc_mutex.unlock();
    return sockfd;
}


in_port_t Device::allocPort(in_port_t port)
{
    this->port_mutex.lock();
    in_port_t port_alloc = -1;
    if (port == 0)
    {
        for (int i = TCP_AUTO_MIN_PORT; i <= TCP_MAX_PORT; ++i)
        {
            if (this->port_alloc[i] == false)
            {
                this->port_alloc[i] = true;
                port_alloc = i;
                break;
            }
        }
        if (port_alloc == -1)
            dbg_tcp_printf("[ERROR][Device::allocPort()] Auto allocate port but all ports have been occupied.\n");
    }
    else
    {
        if (this->port_alloc[port] == false)
        {
            this->port_alloc[port] = true;
            port_alloc = port;
        }
        if (port_alloc == -1)
        {
            char ip_str[IP_STR_LEN];
            ip_addr_to_str(this->getDeviceIP(), ip_str);
            dbg_tcp_printf("[ERROR][Device::allocPort()] The port %d of %s has been occupied.\n",
                       port, ip_str);
        }
    }
    this->port_mutex.unlock();
    return port_alloc;
}

int Device::freePort(in_port_t port)
{
    this->port_mutex.lock();
    this->port_alloc[port]=false;
    this->port_mutex.unlock();
    return 0;
}

TCB *DeviceManager::findSocket(fd_t sockfd)
{
    TCB *sock;
    this->sockets_mutex.lock_shared();
    auto it = this->sockets.find(sockfd);
    if (it == this->sockets.end())
    {
        sock = nullptr;
        dbg_tcp_printf("[ERROR][DeviceManager::findSocket()] The sockfd %d invalid.\n", sockfd);
    }
    else
        sock = it->second;
    this->sockets_mutex.unlock_shared();
    return sock;
}
TCB *DeviceManager::findSocket(sockaddr_in *local_addr, sockaddr_in *remote_addr)
{
    this->sockets_mutex.lock_shared();
    for (auto it : this->sockets)
    {
        if (
            it.second->local_addr.sin_addr.s_addr == local_addr->sin_addr.s_addr &&
            it.second->local_addr.sin_port == local_addr->sin_port &&
            it.second->remote_addr.sin_addr.s_addr == remote_addr->sin_addr.s_addr &&
            it.second->remote_addr.sin_port == remote_addr->sin_port)
        {
            this->sockets_mutex.unlock_shared();
            return it.second;
        }
    }
    for (auto it : this->sockets)
    {
        if (it.second->is_listen == true &&
            it.second->local_addr.sin_addr.s_addr == local_addr->sin_addr.s_addr &&
            it.second->local_addr.sin_port == local_addr->sin_port)
        {
            
            ListenerSocket *sock = getListener(it.first);
            
            sock->lisen_mutex.lock_shared();
            for (auto it_ : sock->listen_queue)
            {
                if (
                    it_->local_addr.sin_addr.s_addr == local_addr->sin_addr.s_addr &&
                    it_->local_addr.sin_port == local_addr->sin_port &&
                    it_->remote_addr.sin_addr.s_addr == remote_addr->sin_addr.s_addr &&
                    it_->remote_addr.sin_port == remote_addr->sin_port)
                {
                    sock->lisen_mutex.unlock_shared();
                    this->sockets_mutex.unlock_shared();
                    return it_;
                }
            }
            sock->lisen_mutex.unlock_shared();
            this->sockets_mutex.unlock_shared();
            return it.second;
        }
    }
    this->sockets_mutex.unlock_shared();
    return nullptr;
}

bool DeviceManager::freeSocket(TCB *sock)
{
    if (sock->is_listen)
    {
        sock->change_state(TCP_STATE::CLOSED);
        ListenerSocket *l_sock;

        this->listners_mutex.lock();
        l_sock = this->listeners[sock->sockfd];
        this->listeners.erase(sock->sockfd);
        this->listners_mutex.unlock();

        l_sock->lisen_mutex.lock();
        for (auto iter = l_sock->listen_queue.begin(); iter != l_sock->listen_queue.end();)
        {
            (*iter)->change_state(TCP_STATE::CLOSED);
            delete (*iter);
            iter = l_sock->listen_queue.erase(iter);
        }
        l_sock->lisen_mutex.unlock();

        this->sockets_mutex.lock();
        this->sockets.erase(sock->sockfd);
        this->sockets_mutex.unlock();

        this->sockfds_alloc_mutex.lock();
        this->sockfd_alloc[sock->sockfd]=false;
        this->sockfds_alloc_mutex.unlock();

        Device *dev=this->getDeviceByIP(sock->local_addr.sin_addr);
        dev->freePort(sock->local_addr.sin_port);

        delete sock;
        delete l_sock;
    }
    else if (sock->is_in_listen_queue)
    {
        sock->change_state(TCP_STATE::CLOSED);
        fd_t listen_fd = -1;
        this->sockets_mutex.lock_shared();
        for (auto it : this->sockets)
        {
            if (it.second->is_listen == true &&
                it.second->local_addr.sin_addr.s_addr == sock->local_addr.sin_addr.s_addr &&
                it.second->local_addr.sin_port == sock->local_addr.sin_port)
            {
                listen_fd = it.first;
                break;
            }
        }
        this->sockets_mutex.unlock_shared();

        this->listners_mutex.lock_shared();
        ListenerSocket *l_sock = this->listeners[listen_fd];
        this->listners_mutex.unlock_shared();

        l_sock->lisen_mutex.lock();
        for (auto iter = l_sock->listen_queue.begin(); iter != l_sock->listen_queue.end(); iter++)
        {
            TCB *tcb_tmp = (*iter);
            if (tcb_tmp->remote_addr.sin_addr.s_addr == sock->remote_addr.sin_addr.s_addr &&
                tcb_tmp->remote_addr.sin_port == sock->remote_addr.sin_port)
            {
                l_sock->listen_queue.erase(iter);
            }
        }
        l_sock->lisen_mutex.unlock();
        delete sock;
    }
    else
    {
        this->sockets_mutex.lock();
        sock->change_state(TCP_STATE::CLOSED);
        this->sockets.erase(sock->sockfd);
        this->sockets_mutex.unlock();
        delete sock;
    }
    return true;
}
bool DeviceManager::addLisenedSocket(fd_t listen_fd, TCB *sock)
{
    this->listners_mutex.lock_shared();
    ListenerSocket *l_sock = this->listeners[listen_fd];
    l_sock->lisen_mutex.lock();
    if(l_sock->listen_queue.size()<l_sock->backlog)
        l_sock->listen_queue.push_back(sock);
    else
    {
        dbg_tcp_printf("[ERROR][DeviceManager::addLisenedSocket()] The capacity of listening socket %d has been used up.\n",listen_fd);
        l_sock->lisen_mutex.unlock();
        this->listners_mutex.unlock_shared();
        return false;
    }
    l_sock->lisen_mutex.unlock();
    this->listners_mutex.unlock_shared();
    return true;
}

void TCBUpdate(TCB *sock)
{
    while(true)
    {
        if(sock->close_timer>=0)
        {
            //dbg_tcp_printf("Update CLOSE_TIMER: %d\n",sock->close_timer.load());
            sock->close_timer++;
            if(sock->close_timer==TCP_CLOSE_TIMEOUT)
            {
                dbg_tcp_printf("[INFO] Close socket %d successfully.\n",sock->sockfd);
                sock->change_state(TCP_STATE::CLOSED);
                return;
            }
        }

        sock->retrans_mutex.lock();
        for(int i=0;i<sock->retransmit_queue.size();++i)
        {
            TCPPacket *pkt=sock->retransmit_queue[i];
            pkt->timer++;
            if(pkt->timer==TCP_RETRANS_TIMEOUT)
            {
                pkt->timer=0;
                u_char *buf=(u_char *)malloc(pkt->phdr.tcp_len);
                memcpy(buf,&(pkt->hdr),TCP_HDR_LEN);
                memcpy(buf+TCP_HDR_LEN,pkt->payload,pkt->phdr.tcp_len-TCP_HDR_LEN);
                ip_addr_t ip_src,ip_dst;
                dbg_tcp_printf("[INFO] Retransmitt packet with seq %u.\n",
                                ntohl(pkt->hdr.th_seq));
                sendIPPacket(pkt->phdr.ip_src,pkt->phdr.ip_dst,IPPROTO_TCP,buf,pkt->phdr.tcp_len);
                free(buf);
            }
        }
        sock->retrans_mutex.unlock();
        sleep(1);
    }
}

void TCB::change_state(TCP_STATE state)
{
    //this->state_mutex.lock();
    dbg_tcp_printf("[INFO][TCB::change_state] State of socket change from %s to %s.\n",
                   TCP_STATE_NAME(this->state).c_str(),
                   TCP_STATE_NAME(state).c_str());
    this->pre_state = this->state;
    this->state.store(state);
    //this->state_mutex.unlock();
}

int TCB::ackRetransQueue(tcp_seq_t ack)
{
    dbg_tcp_printf("[INFO][TCB::ackRetransQueue()] Socket %d; ACK %u.\n",this->sockfd,ack);
    this->retrans_mutex.lock();
    std::sort(this->retransmit_queue.begin(),this->retransmit_queue.end(),TCPPacketSort);
    while(true)
    {
        if(this->retransmit_queue.empty())
            break;
        TCPPacket *pkt=this->retransmit_queue[0];
        pkt->TCPntohs();
        if(pkt->hdr.th_seq+pkt->phdr.tcp_len-TCP_HDR_LEN<=ack)
        {
            dbg_tcp_printf("[INFO][TCB::ackRetransQueue()] Remove packet with SEQ %u from retransmitt queue.\n",
                           pkt->hdr.th_seq);
            this->retransmit_queue.erase(this->retransmit_queue.begin());
            delete pkt;
        }
        else
        {
            pkt->TCPhtons();
            break;
        }
    }
    this->retrans_mutex.unlock();
    return 0;

}
int TCB::clearRetransQueue()
{
    dbg_tcp_printf("[INFO][TCB::clearRetainsQueue()]\n");
    this->retrans_mutex.lock();
    while(!this->retransmit_queue.empty())
    {
        TCPPacket *pkt=this->retransmit_queue.back();
        this->retransmit_queue.pop_back();
        delete pkt;
    }
    this->retrans_mutex.unlock();
    return 0;
}
int TCB::clearReadbuffer()
{
    dbg_tcp_printf("[INFO][TCB::clearReadBuffer()]\n");
    this->readbuf_mutex.lock();
    while(!this->read_buffer.empty())
    {
        TCPPacket *pkt=this->read_buffer.back();
        this->read_buffer.pop_back();
        this->readbuffed_size-=pkt->phdr.tcp_len-TCP_HDR_LEN;
        this->rcv_wnd += pkt->phdr.tcp_len - TCP_HDR_LEN;
        delete pkt;
    }
    this->readbuf_mutex.unlock();
    assert(this->rcv_wnd+this->readbuffed_size==TCP_WINDOW_SIZE);
    assert(this->readbuffed_size==0);
    return 0;
}

bool TCB::isReadBufferContain(TCPPacket *pkt)
{
    this->readbuf_mutex.lock_shared();
    for(int i=0;i<this->read_buffer.size();++i)
    {
        if(this->read_buffer[i]->hdr.th_seq==pkt->hdr.th_seq)
        {
            this->readbuf_mutex.unlock_shared();
            return true;
        }
    }
    this->readbuf_mutex.unlock_shared();
    return false;
}

int TCB::sendTCPControlSegment(uint8_t control_flag, tcp_seq_t seq, tcp_seq_t ack)
{
    TCPPacket pkt;
    memset(&(pkt.hdr), 0, sizeof(pkt.hdr));
    pkt.hdr.urg=(control_flag & TCP_URG_FLAG)!=0;
    pkt.hdr.ack = (control_flag & TCP_ACK_FLAG) != 0;
    pkt.hdr.psh = (control_flag & TCP_PSH_FLAG) != 0;
    pkt.hdr.rst = (control_flag & TCP_RST_FLAG) != 0;
    pkt.hdr.syn = (control_flag & TCP_SYN_FLAG) != 0;
    pkt.hdr.fin = (control_flag & TCP_FIN_FLAG) != 0;
    pkt.hdr.th_off=TCP_HDR_LEN/4;
    pkt.hdr.th_sport = this->local_addr.sin_port;
    pkt.hdr.th_dport = this->remote_addr.sin_port;
    pkt.hdr.th_seq = seq;
    pkt.hdr.th_ack = ack;
    pkt.hdr.th_win = this->rcv_wnd;
    if (control_flag & TCP_URG_FLAG)
    {
        this->snd_up = snd_nxt - 1;
        pkt.hdr.th_urp = this->snd_up;
    }
    ip_addr_t ip_src, ip_dst;
    ip_src.s_addr = this->local_addr.sin_addr.s_addr;
    ip_dst.s_addr = this->remote_addr.sin_addr.s_addr;
    pkt.phdr = TCPPseudoHead(ip_src, ip_dst, IPPROTO_TCP, TCP_HDR_LEN);
    pkt.computeTCPCheckSum();
    pkt.TCPhtons();
    sendIPPacket(ip_src, ip_dst, IPPROTO_TCP, &(pkt.hdr), TCP_HDR_LEN);
    return 0;
}

void TCPPacket::TCPntohs()
{
    hdr.th_sport = ntohs(hdr.th_sport);
    hdr.th_dport = ntohs(hdr.th_dport);
    hdr.th_seq = ntohl(hdr.th_seq);
    hdr.th_ack = ntohl(hdr.th_ack);
    hdr.th_win = ntohs(hdr.th_win);
    hdr.th_sum = ntohs(hdr.th_sum);
    hdr.th_urp = ntohs(hdr.th_urp);
}
void TCPPacket::TCPhtons()
{
    hdr.th_sport = htons(hdr.th_sport);
    hdr.th_dport = htons(hdr.th_dport);
    hdr.th_seq = htonl(hdr.th_seq);
    hdr.th_ack = htonl(hdr.th_ack);
    hdr.th_win = htons(hdr.th_win);
    hdr.th_sum = htons(hdr.th_sum);
    hdr.th_urp = htons(hdr.th_urp);
}

uint16_t TCPPacket::computeTCPCheckSum()
{
    hdr.th_sum = 0;
    u_char *data=(u_char *)malloc(TCP_PESUHDR_LEN+TCP_HDR_LEN);
    memcpy(data,&(phdr),TCP_PESUHDR_LEN);
    memcpy(data+TCP_PESUHDR_LEN,&(hdr),TCP_HDR_LEN);
    hdr.th_sum = computeCheckSum(data, TCP_PESUHDR_LEN + TCP_HDR_LEN);
    free(data);
    return hdr.th_sum;
}
bool TCPPacket::checkTCPCheckSum()
{
    u_char *data = (u_char *)malloc(TCP_PESUHDR_LEN + TCP_HDR_LEN);
    memcpy(data, &(phdr), TCP_PESUHDR_LEN);
    memcpy(data + TCP_PESUHDR_LEN, &(hdr), TCP_HDR_LEN);
    uint16_t sum = computeCheckSum(data, TCP_PESUHDR_LEN + TCP_HDR_LEN);
    free(data);
    return (sum == 0);
}

void TCPPacket::printTCPPacket()
{
    char ip_src_str[IP_STR_LEN];
    char ip_dst_str[IP_STR_LEN];
    ip_addr_to_str(this->phdr.ip_src,ip_src_str);
    ip_addr_to_str(this->phdr.ip_dst,ip_dst_str);
    dbg_tcp_printf("[INFO][TCPPacket::printTCPPacket()]\n");
    dbg_tcp_printf("Pesudo Head: \n"
                   "\tSource Address: %s\n"
                   "\tDestination Address: %s\n"
                   "\tPTCL: 0x%x\n"
                   "\tTCP Length: %d\n",
                   ip_src_str,
                   ip_dst_str,
                   this->phdr.proto,
                   this->phdr.tcp_len
                   );
    dbg_tcp_printf("TCP Head: \n"
                   "\tSource Port: %d\n"
                   "\tDestination Port: %d\n"
                   "\tSequence Number: %d\n"
                   "\tAcknowledgment Number: %d\n"
                   "\tURG: %d\n"
                   "\tACK: %d\n"
                   "\tPSH: %d\n"
                   "\tRST: %d\n"
                   "\tSYN: %d\n"
                   "\tFIN: %d\n"
                   "\tWindow: %d\n"
                   "\tChecksum: %d\n"
                   "\tUrgent Pointer: %d\n",
                   this->hdr.th_sport,
                   this->hdr.th_dport,
                   this->hdr.th_seq,
                   this->hdr.th_ack,
                   this->hdr.urg,
                   this->hdr.ack,
                   this->hdr.psh,
                   this->hdr.rst,
                   this->hdr.syn,
                   this->hdr.fin,
                   this->hdr.th_win,
                   this->hdr.th_sum,
                   this->hdr.th_urp);
}

bool TCPPacketSort(const TCPPacket *pkt1, const TCPPacket *pkt2){
    return pkt1->hdr.th_seq<pkt2->hdr.th_seq;
}
bool TCPPacketEqual(const TCPPacket *pkt1, const TCPPacket *pkt2)
{
    return pkt1->hdr.th_seq==pkt2->hdr.th_seq;
}

int handleTCPPacket(Device *dev, void *pkt, int len)
{
    dbg_tcp_printf("[INFO][handleTCPPacket()]\n");
    TCPPacket *tcp_pkt = new TCPPacket();
    IPPacket ip_pkt;
    memcpy(ip_pkt.header, pkt, IPHDR_LEN);
    ip_pkt.IPntohs();
    if (ip_pkt.header->ip_p != IPPROTO_TCP)
    {
        dbg_tcp_printf("[ERROR][handleTCPPacket()] Protocol %d is not TCP.\n",
                   ip_pkt.header->ip_p);
        delete tcp_pkt;
        return -1;
    }
    ip_addr_t ip_src;
    ip_addr_t ip_dst;
    ip_src.s_addr = ip_pkt.header->ip_src.s_addr;
    ip_dst.s_addr = ip_pkt.header->ip_dst.s_addr;
    uint8_t proto = ip_pkt.header->ip_p;
    uint16_t tcp_len = len - IPHDR_LEN;
    tcp_pkt->phdr = TCPPseudoHead(ip_src, ip_dst, proto, tcp_len);
    memcpy(&(tcp_pkt->hdr), (void *)((u_char *)pkt + IPHDR_LEN), TCP_HDR_LEN);
    tcp_pkt->payload = (u_char *)malloc(len - IPHDR_LEN - TCP_HDR_LEN);
    memcpy(tcp_pkt->payload, (u_char *)pkt + IPHDR_LEN + TCP_HDR_LEN, len - IPHDR_LEN - TCP_HDR_LEN);
    tcp_pkt->TCPntohs();
    if (tcp_pkt->checkTCPCheckSum() == false)
    {
        dbg_tcp_printf("[ERROR][handleTCPPacket()] Checksum error.\n");
        delete tcp_pkt;
        return -1;
    }
    tcp_pkt->printTCPPacket();
    sockaddr_in local_addr;
    sockaddr_in remote_addr;
    local_addr.sin_addr.s_addr = ip_dst.s_addr;
    local_addr.sin_port = tcp_pkt->hdr.th_dport;
    remote_addr.sin_addr.s_addr = ip_src.s_addr;
    remote_addr.sin_port = tcp_pkt->hdr.th_sport;
    TCB *sock = findSocket(&local_addr, &remote_addr);
    sock->snd_wnd=tcp_pkt->hdr.th_win;
    if (sock == nullptr)
    {
        dbg_tcp_printf("[ERROR][handleTCPPacket()] The socket doesn't exist.\n");
        delete tcp_pkt;
        return -1;
    }
    dbg_tcp_printf("[INFO][handleTCPPacket()] The socket %d is in state %s.\n",
                   sock->sockfd,
                   TCP_STATE_NAME(sock->state.load()).c_str());
    dbg_tcp_printf("[INFO][handleTCPPacket()]TCB:\n"
                   "\tSND.UNA: %u\n"
                   "\tSND.NXT: %u\n"
                   "\tSND.WND: %u\n"
                   "\tRCV.NXT: %u\n"
                   "\tRCV.WND: %u\n",
                   sock->snd_una,
                   sock->snd_nxt,
                   sock->snd_wnd,
                   sock->rcv_nxt,
                   sock->rcv_wnd);
    
    switch (sock->state.load())
    {
    case TCP_STATE::CLOSED:
    {
        if (tcp_pkt->hdr.ack)
        {
            dbg_tcp_printf("[ERROR][handleTCPPacket()] The socket %d CLOSED, send RST: <SEQ=SEG.ACK(%d)><CTL=RST>.\n",
                           sock->sockfd,tcp_pkt->hdr.th_ack);
            sock->sendTCPControlSegment(TCP_RST_FLAG, tcp_pkt->hdr.th_ack, 0);
        }
        else
        {
            dbg_tcp_printf("[ERROR][handleTCPPacket()] The socket %d CLOSED, send RST: <SEQ=0><ACK=SEG.SEQ+SEG.LEN(%d)><CTL=RST,ACK>.\n",
                           sock->sockfd,tcp_pkt->hdr.th_seq + tcp_pkt->phdr.tcp_len - TCP_HDR_LEN);
            sock->sendTCPControlSegment(TCP_ACK_FLAG | TCP_RST_FLAG, 0, tcp_pkt->hdr.th_seq + tcp_pkt->phdr.tcp_len - TCP_HDR_LEN);
        }
        delete tcp_pkt;
        return -1;
    }
    case TCP_STATE::LISTEN:
    {
        if (sock->is_in_listen_queue)
        {
            delete tcp_pkt;
            return 0;
        }
        if (tcp_pkt->hdr.rst)
        {   
            delete tcp_pkt;
            return 0;
        }
        if (tcp_pkt->hdr.ack)
        {
            dbg_tcp_printf("[ERROR][handleTCPPacket()] The socket %d is in LISTEN state, "
                           "and receiving the ACK is abnormal. \n"
                           "Send <SEQ=SEG.ACK(%d)><CTL=RST>",
                           sock->sockfd,
                           tcp_pkt->hdr.th_ack);
            //sock->sendTCPControlSegment(TCP_RST_FLAG, tcp_pkt->hdr.th_ack, 0);
            delete tcp_pkt;
            return 0;
        }
        if (tcp_pkt->hdr.syn)
        {
            TCB *task = new TCB();
            task->local_addr.sin_addr.s_addr = sock->local_addr.sin_addr.s_addr;
            task->local_addr.sin_port = sock->local_addr.sin_port;
            task->remote_addr.sin_addr.s_addr = tcp_pkt->phdr.ip_src.s_addr;
            task->remote_addr.sin_port = tcp_pkt->hdr.th_sport;
            task->is_in_listen_queue = true;
            task->change_state(TCP_STATE::LISTEN);
            task->rcv_nxt=tcp_pkt->hdr.th_seq+1;
            task->irs=tcp_pkt->hdr.th_seq;
            task->is_set_remote=true;
            addLisenedSocket(sock->sockfd, task);

            dbg_tcp_printf("[INFO][handleTCPPacket()] The listen socket %d receive SYN, "
                           "add a new socket to listen queue.\n",
                           sock->sockfd);
        }
        delete tcp_pkt;
        return 0;
    }
    case TCP_STATE::SYN_SENT:
    {
        bool ack_accept = false;
        if (tcp_pkt->hdr.ack)
        {
            if (tcp_pkt->hdr.th_ack <= sock->iss or tcp_pkt->hdr.th_ack > sock->snd_nxt)
            {
                dbg_tcp_printf("[ERROR][handleTCPPacket()] The packet' ack is unacceptable. "
                               "send RST: <SEQ=SEG.ACK(%d)><CTL=RST>",
                               tcp_pkt->hdr.th_ack);
                sock->sendTCPControlSegment(TCP_RST_FLAG, tcp_pkt->hdr.th_ack, 0);
                delete tcp_pkt;
                return 0;
            }
            if (tcp_pkt->hdr.th_ack >= sock->snd_una and tcp_pkt->hdr.th_ack <= sock->snd_nxt)
                ack_accept = true;
        }
        if (tcp_pkt->hdr.rst)
        {
            if (ack_accept)
            {
                dbg_tcp_printf("[ERROR][handleTCPPacket()] Connection reset.\n");
                freeSocket(sock);
            }
            delete tcp_pkt;
            return 0;
        }
        if (tcp_pkt->hdr.syn)
        {
            sock->rcv_nxt = tcp_pkt->hdr.th_seq + 1;
            sock->irs = tcp_pkt->hdr.th_seq;
            if (tcp_pkt->hdr.ack)
            {
                //assert(sock->snd_una == tcp_pkt->hdr.th_ack);
                sock->snd_una = tcp_pkt->hdr.th_ack;
                sock->ackRetransQueue(tcp_pkt->hdr.th_ack);
            }
            if (sock->snd_una > sock->iss)
            {
                sock->change_state(TCP_STATE::ESTAB);
                dbg_tcp_printf("[INFO][handleTCPPacket()] "
                           "Socket %d send ACK: <SEQ=SND.NXT(%d)><ACK=RCV.NXT(%d)><CTL=ACK>\n",
                           sock->sockfd,sock->snd_nxt, sock->rcv_nxt);
                sock->sendTCPControlSegment(TCP_ACK_FLAG, sock->snd_nxt, sock->rcv_nxt);
            }
            else
            {
                sock->change_state(TCP_STATE::SYN_RECV);
                dbg_tcp_printf("[INFO][handleTCPPacket()] "
                           "Socket %d send ACK: <SEQ=ISS(%d)><ACK=RCV.NXT(%d)><CTL=SYN,ACK>\n",
                           sock->sockfd,sock->iss, sock->rcv_nxt);
                sock->sendTCPControlSegment(TCP_ACK_FLAG | TCP_SYN_FLAG, sock->iss, sock->rcv_nxt);
            }
        }
        delete tcp_pkt;
        return 0;
    }
    }
    /* 检查 ACK_SEQ */
    TCP_STATE state = sock->state.load();
    bool ack_accept;
    tcp_seq_t seg_len = tcp_pkt->phdr.tcp_len - TCP_HDR_LEN;
    tcp_seq_t rcv_wnd = sock->rcv_wnd;
    tcp_seq_t seg_seq = tcp_pkt->hdr.th_seq;
    tcp_seq_t rcv_nxt = sock->rcv_nxt;
    if (seg_len == 0 && rcv_wnd == 0)
    {
        if (seg_seq == rcv_nxt)
            ack_accept = true;
        else
            ack_accept = false;
    }
    if (seg_len == 0 && rcv_wnd > 0)
    {
        if (seg_seq >= rcv_nxt && seg_seq < rcv_nxt + rcv_wnd)
            ack_accept = true;
        else
            ack_accept = false;
    }
    if (seg_len > 0 && rcv_wnd == 0)
        ack_accept = false;

    if (seg_len > 0 && rcv_wnd > 0)
    {
        /* if (seg_seq >= rcv_nxt && seg_seq < rcv_nxt + rcv_wnd or
            seg_seq + seg_len - 1 >= rcv_nxt && seg_seq + seg_len - 1 < rcv_nxt + rcv_wnd)
            ack_accept = true;
        else
            ack_accept = false; */
        if(seg_seq==rcv_nxt)
            ack_accept=true;
        else
            ack_accept=false;
    }
    if (ack_accept == false)
    {
        if(tcp_pkt->hdr.syn)
        {
            delete tcp_pkt;
            return 0;
        }
        dbg_tcp_printf("[INFO][handleTCPPacket()] The segment could not be received. "
                       "Socket %d send <SEQ=SND.NXT(%d)><ACK=RCV.NXT(%d)><CTL=ACK>\n",
                       sock->sockfd,
                       sock->snd_nxt, 
                       rcv_nxt);
        if(seg_seq<rcv_nxt)
            sock->sendTCPControlSegment(TCP_ACK_FLAG, sock->snd_nxt, rcv_nxt);
        delete tcp_pkt;
        return 0;
    }

    /* 检查 RST */
    state = sock->state.load();
    if (tcp_pkt->hdr.rst)
    {
        if (state == TCP_STATE::SYN_RECV)
        {
            if (sock->pre_state == TCP_STATE::LISTEN)
            {
                dbg_tcp_printf("[INFO][handleTCPPacket()] "
                               "The packet set RST and socket's pre-state is LISTEN, "
                               "remove the socket in listen queue.\n"
                               );
                sock->clearRetransQueue();
                freeSocket(sock);
                delete tcp_pkt;
                return 0;
            }
            dbg_tcp_printf("[ERROR][handleTCPPacket()] The packet set RST, Connection refused. ete the TCB.\n");
            sock->clearRetransQueue();
            freeSocket(sock);
            delete tcp_pkt;
            return 0;
        }
        if (state == TCP_STATE::ESTAB or
            state == TCP_STATE::FINWAIT_1 or
            state == TCP_STATE::FINWAIT_2 or
            state == TCP_STATE::CLOSE_WAIT)
        {
            dbg_tcp_printf("[ERROR][handleTCPPacket()] The packet set RST, Connection refused. Delete the TCB.\n");
            sock->is_rst.store(true);
            sock->clearRetransQueue();
            sock->clearReadbuffer();
            freeSocket(sock);
            delete tcp_pkt;
            return 0;
        }
        if (state == TCP_STATE::CLOSING or
            state == TCP_STATE::LAST_ACK or
            state == TCP_STATE::TIME_WAIT)
        {
            dbg_tcp_printf("[ERROR][handleTCPPacket()] The packet set RST, Connection refused. Delete the TCB.\n");
            freeSocket(sock);
            delete tcp_pkt;
            return 0;
        }
    }

    /* 检查 SYN */
    state = sock->state.load();
    if (tcp_pkt->hdr.syn)
    {
        printf("[ERROR][handleTCPPacket()] Connection reset.\n");
        sock->clearRetransQueue();
        sock->clearReadbuffer();
        sock->is_rst.store(true);
        freeSocket(sock);
        delete tcp_pkt;
        return 0;
    }

    /* 检查 ACK 标记 */
    state = sock->state.load();
    tcp_seq_t snd_una = sock->snd_una;
    tcp_seq_t snd_nxt = sock->snd_nxt;
    tcp_seq_t seg_ack = tcp_pkt->hdr.th_ack;
    if (tcp_pkt->hdr.ack)
    {
        sock->ackRetransQueue(seg_ack);
        if (state == TCP_STATE::SYN_RECV)
        {
            if (seg_ack >= snd_una && seg_ack <= snd_nxt)
            {
                sock->change_state(TCP_STATE::ESTAB);
                goto ESTAB;
            }
            else
            {
                dbg_tcp_printf("[ERROR][handleTCPPacket()] The ACK is unacceptable, send RST: <SEQ=SEG.ACK(%d)><CTL=RST>.\n",
                               seg_ack);
                sock->sendTCPControlSegment(TCP_RST_FLAG, seg_ack, 0);
                delete tcp_pkt;
                return 0;
            }
        }
        else if (state == TCP_STATE::ESTAB or state == TCP_STATE::CLOSE_WAIT)
        {
        ESTAB:
            if (seg_ack > snd_una && seg_ack <= snd_nxt)
            {
                sock->snd_una = seg_ack;
                sock->ackRetransQueue(seg_ack);
                if (sock->snd_wl1 < seg_seq or
                    (sock->snd_wl1 = seg_seq and sock->snd_wl2 <= seg_ack))
                {
                    sock->snd_wnd = tcp_pkt->hdr.th_win;
                    sock->snd_wl1 = seg_seq;
                    sock->snd_wl2 = seg_ack;
                }
            }
            else if (seg_ack > snd_nxt)
            {
                dbg_tcp_printf("[ERROR][handleTCPPacket()] Ackowledge the data which was not been sent. Drop it.\n");
                sock->sendTCPControlSegment(TCP_ACK_FLAG, sock->snd_nxt, seg_seq);
                delete tcp_pkt;
                return 0;
            }
            else if(seg_ack<snd_una)
            {

            }
        }
        else if (state == TCP_STATE::FINWAIT_1)
        {
            if (seg_ack == snd_nxt)
            {
                dbg_tcp_printf("[INFO][handleTCPPacket()] The FIN of socket %d has been ACKed.\n",sock->sockfd);
                sock->change_state(TCP_STATE::FINWAIT_2);
            }
        }
        else if (state == TCP_STATE::FINWAIT_2)
        {
            
        }
        else if (state == TCP_STATE::CLOSING)
        {
            if (seg_ack == snd_nxt)
            {
                dbg_tcp_printf("[INFO][handleTCPPacket()] The FIN of socket %d has been ACKed.\n", sock->sockfd);
                sock->change_state(TCP_STATE::TIME_WAIT);
            }
            else
            {   dbg_tcp_printf("[INFO][handleTCPPacket()] The socket %d is CLOSING, drop the packet.\n",sock->sockfd);
                delete tcp_pkt;
                return 0;
            }
        }
        else if (state == TCP_STATE::LAST_ACK)
        {
            if (seg_ack == snd_nxt)
            {
                dbg_tcp_printf("[INFO][handleTCPPacket()] The FIN of socket %d has been ACKed. Close the socket.\n", sock->sockfd);
                sock->change_state(TCP_STATE::CLOSED);
                delete tcp_pkt;
                return 0;
            }
        }
        else if (state == TCP_STATE::TIME_WAIT)
        {
            //FIN: Refresh TIME_WAIT_OUT
            if(tcp_pkt->hdr.fin)
            {
                dbg_tcp_printf("[INFO][[handleTCPPacket()]] Socket %d in TIME_WAIT receives retranmission FIN, "
                               "refresh the CLOSE_TIMER and send ACK: <SEG=SND.NXT(%u)><ACK=RCV.NXT(%u)><CTL=ACK>",
                               sock->sockfd,
                               sock->snd_nxt,
                               sock->rcv_nxt);
                sock->sendTCPControlSegment(TCP_ACK_FLAG,sock->snd_nxt,sock->rcv_nxt);
                sock->close_timer=0;
            }
        }
    }
    else
    {
        dbg_tcp_printf("[INFO][handleTCPPacket()] No ACK flag, drop the packet.\n");
        delete tcp_pkt;
        return 0;
    }

    /* 检查 URG 标志 */
    state = sock->state.load();
    if (tcp_pkt->hdr.urg)
    {
        if (state == TCP_STATE::ESTAB or
            state == TCP_STATE::FINWAIT_1 or
            state == TCP_STATE::FINWAIT_2)
        {
            sock->rcv_up = sock->rcv_up > tcp_pkt->hdr.th_urp ? sock->rcv_up : tcp_pkt->hdr.th_urp;
            printf("Urgent data!.\n");
        }
        else
        {
            dbg_tcp_printf("[ERROR][handleTCPPacket()] This should not occur, "
                           "since a FIN has been received from the remote side. "
                           "Ignore the URG.\n");
            delete tcp_pkt;
            return 0;
        }
    }

    /* 处理用户数据 */
    state = sock->state.load();
    if (state == TCP_STATE::ESTAB or
        state == TCP_STATE::FINWAIT_1 or
        state == TCP_STATE::FINWAIT_2)
    {
        seg_len=tcp_pkt->phdr.tcp_len-TCP_HDR_LEN;
        if(seg_len>0)
        {
            if(!sock->isReadBufferContain(tcp_pkt))
            {

            TCPPacket *pkt_buffered=new TCPPacket(*tcp_pkt);
            sock->readbuf_mutex.lock();
            sock->read_buffer.push_back(pkt_buffered);
            sock->readbuffed_size+=seg_len;
            assert(sock->readbuffed_size<=TCP_WINDOW_SIZE);
            sock->rcv_wnd-=seg_len;
            assert(sock->rcv_wnd+sock->readbuffed_size==TCP_WINDOW_SIZE);
            sock->rcv_nxt=sock->rcv_nxt+seg_len;
            sock->read_buffer.erase(std::unique(sock->read_buffer.begin(), sock->read_buffer.end()), sock->read_buffer.end());
            sock->readbuf_mutex.unlock();
            dbg_tcp_printf("[INFO][handleTCPPacket()] Receive data(%d). Deliver it to read buffer(%d) and"
                           " send ACK: <SEQ=SND.NXT(%d)><ACK=RCV.NXT(%d)><CTL=ACK>\n",
                           seg_len,sock->readbuffed_size.load(),
                           sock->snd_nxt, sock->rcv_nxt);
            }
            sock->sendTCPControlSegment(TCP_ACK_FLAG, snd_nxt, rcv_nxt);
        }
    }
    else
    {
        dbg_tcp_printf("[ERROR][handleTCPPacket()] This should not occur, "
                       "since a FIN has been received from the remote side. "
                       "Ignore the segment text.\n");
        delete tcp_pkt;
        return 0;
    }

    /* 检查 FIN 标志 */
    state = sock->state.load();
    if (tcp_pkt->hdr.fin)
    {
        if (state == TCP_STATE::CLOSED or
            state == TCP_STATE::LISTEN or
            state == TCP_STATE::SYN_SENT)
        {
            dbg_tcp_printf("[INFO][handleTCPPacket()] "
                           "There is no need to process the FIN flag "
                           "as SEG.SEQ cannot be verified for legality. "
                           "Drop the packet.\n");
            delete tcp_pkt;
            return 0;
        }

        sock->rcv_nxt = tcp_pkt->hdr.th_seq + 1;
        dbg_tcp_printf("[INFO][handleTCPPacket()] "
                       "Receive FIN and send ACK of the FIN: "
                       "<SEQ=SND.NXT(%d)><ACK=SEG.SEQ+1(%d)><CTL=ACK>.\n",
                       sock->snd_nxt, sock->rcv_nxt);
        sock->sendTCPControlSegment(TCP_ACK_FLAG, sock->snd_nxt, sock->rcv_nxt);
        if (state == TCP_STATE::SYN_RECV or
            state == TCP_STATE::ESTAB)
        {
            sock->change_state(TCP_STATE::CLOSE_WAIT);
        }
        else if (state == TCP_STATE::FINWAIT_1)
        {
            if (tcp_pkt->hdr.ack and tcp_pkt->hdr.th_ack==sock->rcv_nxt)
            {
                /* start time wait timer, stop other timer */
                sock->close_timer=0;
                sock->clearRetransQueue();
                sock->change_state(TCP_STATE::TIME_WAIT);
            }
            else
            {
                sock->change_state(TCP_STATE::CLOSING);
            }
        }
        else if (state == TCP_STATE::FINWAIT_2)
        {
            sock->change_state(TCP_STATE::TIME_WAIT);
            /* start time wait timer, stop other timer */
            sock->close_timer = 0;
            sock->clearRetransQueue();
            sock->change_state(TCP_STATE::TIME_WAIT);
        }
        else if (state == TCP_STATE::TIME_WAIT)
        {
            /* refresh time wait timer */
            sock->close_timer=0;
        }
    }
    delete tcp_pkt;
    return 0;
}