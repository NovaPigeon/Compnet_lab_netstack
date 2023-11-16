#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H



#include "../include/debug.h"
#include "../include/type.h"

#define TCP_MAX_PORT 65535
#define TCP_AUTO_MIN_PORT 1025
#define TCP_MAX_SOCK_FD 1024
#define TCP_HDR_LEN 20
#define TCP_PESUHDR_LEN 12
#define TCP_WINDOW_SIZE (UINT16_MAX * 8)
#define TCP_MAX_SEQ UINT32_MAX
#define TCP_HANDSHAKE_RESENT_TIME 1
#define TCP_FIN_RESENT_TIME 2
#define TCP_RETRANS_TIMEOUT 5
#define TCP_CLOSE_TIMEOUT 5
#define TCP_MAX_SEG_LEN 1000

#define TCP_URG_FLAG (1<<6)
#define TCP_ACK_FLAG (1<<5)
#define TCP_PSH_FLAG (1<<4)
#define TCP_RST_FLAG (1<<3)
#define TCP_SYN_FLAG (1<<2)
#define TCP_FIN_FLAG 1

enum TCP_STATE
{
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECV,
    ESTAB,
    FINWAIT_1,
    FINWAIT_2,
    CLOSING,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK
};


enum TCP_EVENT
{
  OPEN,
  SEND,
  RECEIVE,
  CLOSE,
  ABORT,
  STATUS,
  SEGMENT_ARRIVES,
  USER_TIMEOUT,
  RETRANSMISSION_TIMEOUT,
  TIME_WAIT_TIMEOUT
};

/*
   +--------+--------+--------+--------+
   |           Source Address          |
   +--------+--------+--------+--------+
   |         Destination Address       |
   +--------+--------+--------+--------+
   |  zero  |  PTCL  |    TCP Length   |
   +--------+--------+--------+--------+
*/
struct TCPPseudoHead
{
    ip_addr_t ip_src;
    ip_addr_t ip_dst;
    uint8_t zeros;
    uint8_t proto;
    uint16_t tcp_len;
    TCPPseudoHead(ip_addr_t ip_src_,ip_addr_t ip_dst_,uint8_t proto_,uint16_t tcp_len_)
    {
      ip_src.s_addr=ip_src_.s_addr;
      ip_dst.s_addr=ip_dst_.s_addr;
      proto=proto_;
      tcp_len=tcp_len_;
      zeros=0;
    }
    TCPPseudoHead(const TCPPseudoHead &phdr)
    {
      this->ip_dst.s_addr=phdr.ip_dst.s_addr;
      this->ip_src.s_addr=phdr.ip_src.s_addr;
      this->zeros=0;
      this->proto=phdr.proto;
      this->tcp_len=phdr.tcp_len;
    }
    TCPPseudoHead(){}

} __attribute__((__packed__));

/*
     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  */
struct TCPPacket
{

  TCPPseudoHead phdr;
  tcphdr hdr;
  u_char *payload;
  std::atomic_int timer;
  void TCPntohs();
  void TCPhtons();
  ~TCPPacket()
  {
    if(payload!=nullptr)
      free(payload);
  }
  uint16_t computeTCPCheckSum();
  bool checkTCPCheckSum();
  TCPPacket(){payload=nullptr;this->timer=0;}
  TCPPacket(const TCPPacket &pkt)
  {
    this->timer=0;
    this->hdr=pkt.hdr;
    this->phdr=pkt.phdr;
    this->payload=(u_char *)malloc(pkt.phdr.tcp_len-TCP_HDR_LEN);
    memcpy(this->payload, pkt.payload, pkt.phdr.tcp_len - TCP_HDR_LEN);
  }
  void printTCPPacket();

};

bool TCPPacketSort(const TCPPacket *pkt1,const TCPPacket *pkt2);
bool TCPPacketEqual(const TCPPacket *pkt1,const TCPPacket *pkt2);

class TCB;
void TCBUpdate(TCB *sock);

class TCB
{

public:
  fd_t sockfd;

  sockaddr_in remote_addr;
  sockaddr_in local_addr;

  std::atomic<TCP_STATE> state;
  TCP_STATE pre_state;
  std::thread *thread_timer;
  std::atomic_int close_timer;

  std::shared_mutex state_mutex;

  std::shared_mutex retrans_mutex;
  std::vector<TCPPacket *> retransmit_queue;
  std::atomic_int readbuffed_size;
  std::shared_mutex readbuf_mutex;
  std::vector<TCPPacket *> read_buffer;

  std::atomic_bool is_rst;

  tcp_seq_t snd_una;
  tcp_seq_t snd_nxt;
  tcp_seq_t snd_wnd;
  tcp_seq_t snd_up;
  tcp_seq_t snd_wl1;
  tcp_seq_t snd_wl2;
  tcp_seq_t iss;

  tcp_seq_t rcv_nxt;
  tcp_seq_t rcv_wnd;
  tcp_seq_t rcv_up;
  tcp_seq_t irs;

  int domain;
  int type;
  int protocol;
  std::atomic_bool is_listen;
  std::atomic_bool is_bind;
  std::atomic_bool is_in_listen_queue;
  std::atomic_bool is_set_remote;

  TCB(int domain_,int type_,int protocol_,fd_t sockfd_):
  domain(domain_),type(type_),protocol(protocol_),sockfd(sockfd_)
  {
    this->state=TCP_STATE::CLOSED;
    this->is_listen=false;
    this->is_bind=false;
    this->pre_state=TCP_STATE::CLOSED;
    this->is_in_listen_queue=false;
    this->snd_wnd=TCP_WINDOW_SIZE;
    this->rcv_wnd=TCP_WINDOW_SIZE;
    this->readbuffed_size.store(0);
    this->is_set_remote=false;
    this->is_rst.store(false);
    close_timer=-1;
    this->thread_timer=new std::thread(TCBUpdate,this);
  }
  TCB()
  {
    this->domain=AF_INET;
    this->type=SOCK_STREAM;
    this->protocol=IPPROTO_TCP;
    this->is_listen=false;
    this->is_bind=false;
    this->state=TCP_STATE::CLOSED;
    this->is_in_listen_queue=false;
    this->snd_wnd=TCP_WINDOW_SIZE;
    this->rcv_wnd=TCP_WINDOW_SIZE;
    this->readbuffed_size.store(0);
    this->is_rst.store(false);
    this->is_set_remote=false;
    close_timer=-1;
    this->thread_timer = new std::thread(TCBUpdate, this);
  }
  void change_state(TCP_STATE state);
  int sendTCPControlSegment(uint8_t control_flag,tcp_seq_t seq,tcp_seq_t ack);
  int ackRetransQueue(tcp_seq_t ack);
  int clearRetransQueue();
  int clearReadbuffer();
  bool isReadBufferContain(TCPPacket *pkt);
};

class ListenerSocket
{
public:
  fd_t sockfd;
  sockaddr_in sock_addr;
  int backlog;
  std::vector<TCB *> listen_queue;
  std::shared_mutex lisen_mutex;
  ListenerSocket(fd_t sockfd_,sockaddr_in sock_addr_,int backlog_):
  sockfd(sockfd_),backlog(backlog_)
  {
    memcpy(&sock_addr,&sock_addr_,sizeof(struct sockaddr_in));
  }
};

std::string TCP_STATE_NAME(TCP_STATE state);

/*                            +---------+ ---------\      active OPEN
                              |  CLOSED |            \    -----------
                              +---------+<---------\   \   create TCB
                                |     ^              \   \  snd SYN
                   passive OPEN |     |   CLOSE        \   \
                   ------------ |     | ----------       \   \
                    create TCB  |     | delete TCB         \   \
                                V     |                      \   \
                              +---------+            CLOSE    |    \
                              |  LISTEN |          ---------- |     |
                              +---------+          delete TCB |     |
                   rcv SYN      |     |     SEND              |     |
                  -----------   |     |    -------            |     V
 +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 |         |<-----------------           ------------------>|         |
 |   SYN   |                    rcv SYN                     |   SYN   |
 |   RCVD  |<-----------------------------------------------|   SENT  |
 |         |                    snd ACK                     |         |
 |         |------------------           -------------------|         |
 +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
   |           --------------   |     |   -----------
   |                  x         |     |     snd ACK
   |                            V     V
   |  CLOSE                   +---------+
   | -------                  |  ESTAB  |
   | snd FIN                  +---------+
   |                   CLOSE    |     |    rcv FIN
   V                  -------   |     |    -------
 +---------+          snd FIN  /       \   snd ACK          +---------+
 |  FIN    |<-----------------           ------------------>|  CLOSE  |
 | WAIT-1  |------------------                              |   WAIT  |
 +---------+          rcv FIN  \                            +---------+
   | rcv ACK of FIN   -------   |                            CLOSE  |
   | --------------   snd ACK   |                           ------- |
   V        x                   V                           snd FIN V
 +---------+                  +---------+                   +---------+
 |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 +---------+                  +---------+                   +---------+
   |                rcv ACK of FIN |                 rcv ACK of FIN |
   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
   |  -------              x       V    ------------        x       V
    \ snd ACK                 +---------+delete TCB         +---------+
     ------------------------>|TIME WAIT|------------------>| CLOSED  |
                              +---------+                   +---------+
 
                      TCP Connection State Diagram */


#endif