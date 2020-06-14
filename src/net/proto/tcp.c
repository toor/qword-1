#include <stdint.h>
#include <stddef.h>
#include <net/socket.h>
#include <net/proto/tcp.h>
#include <net/socket.h>
#include <net/net.h>
#include <net/proto/ether.h>
#include <net/proto/ipv4.h>
#include <lib/cmem.h>
#include <lib/rand.h>
#include <lib/klib.h>

/* tcp_new(): construct a new tcp segment from a raw packet */
void tcp_new(struct socket_descriptor_t *sock, struct packet_t *pkt, int flags,
        const void *tcp_data, size_t data_len) {
    struct ether_hdr *ether = (struct ether_hdr *)pkt->buf;
    ether->type = ETHER_IPV4;

    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(pkt->buf + sizeof(struct ether_hdr));

    /* ignore checksum for now */
    ipv4_hdr->ver = 4;
    ipv4_hdr->head_len = sizeof(struct ipv4_hdr_t) / 4;
    ipv4_hdr->tos = 0; /* TOS/DSCP: we don't need this */
    /* total size of ip datagram: header + tcp header + tcp data */
    ipv4_hdr->total_len = HTONS(sizeof(struct ipv4_hdr_t) + sizeof(struct tcp_hdr_t) + data_len);
    ipv4_hdr->id = NTOHS(sock->ip.ipid); /* TODO these capitals look like wank */
    ipv4_hdr->protocol = PROTO_TCP;
    ipv4_hdr->checksum = 0;
    ipv4_hdr->frag_flag = HTONS(IPV4_HEAD_DF_MASK);
    ipv4_hdr->ttl = 64;
    ipv4_hdr->src = sock->ip.source_ip;
    ipv4_hdr->dst = sock->ip.dest_ip;

    /* tcp header 20 bytes after start of ipv4_hdr header */
    struct tcp_hdr_t *tcp = (struct tcp_hdr_t *)((void *)ipv4_hdr + (ipv4_hdr->head_len * 4));

    tcp->source = sock->ip.source_port;
    tcp->dest = sock->ip.dest_port;

    tcp->seq_num = HTONL(sock->tcp.snd_sq);
    tcp->ack_seq_num = (flags & TCP_ACK) ? HTONL(sock->tcp.recv_sq) : 0;

    /* tcp header is 20 bytes wide */
    tcp->doff = 5;
    tcp->res1 = 0;

    tcp->fin = (flags & TCP_FIN);
    tcp->syn = (flags & TCP_SYN);
    tcp->rst = (flags & TCP_RST);
    tcp->psh = (flags & TCP_PSH);
    tcp->ack = (flags & TCP_ACK);
    tcp->urg = (flags & TCP_URG);
    tcp->ece = (flags & TCP_ECE);
    tcp->cwr = (flags & TCP_CWR);

    tcp->window = HTONS(0x1000);
    tcp->checksum = 0;
    tcp->urg_ptr = 0;

    /* copy data */
    memcpy(tcp->data, tcp_data, data_len);
    pkt->pkt_len = NTOHS(ipv4_hdr->total_len) + sizeof(struct ether_hdr);

    ipv4_checksum(pkt);
    tcp_checksum(pkt);
}

/* send data over tcp connection
 * to send SYN packet, call with data_len = 0, flags set to TCP_SYN */
void tcp_send(struct socket_descriptor_t *sock, const void *data, size_t data_len, int flags) {
    struct packet_t *pkt = pkt_new();

    tcp_new(sock, pkt, flags, data, data_len);
    net_dispatch_pkt(pkt);
    pkt_free(pkt);

    sock->ip.ipid += 1;

    if (flags & TCP_SYN) {
        sock->tcp.snd_sq += 1;
    }

    if  (flags & TCP_FIN) {
        sock->tcp.snd_sq += 1;
    }

    sock->tcp.snd_sq += data_len;
}

/* will be called from connect() - establish a 3-way tcp handshake */
int tcp_connect(struct socket_descriptor_t *sock, const struct sockaddr_in *addr) {
    sock->ip.dest_ip = addr->sin_addr.s_addr;
    sock->ip.dest_port = addr->sin_port;
    sock->state = STATE_OUT;

    sock->tcp.snd_sq = rand32();
    sock->tcp.ack_sq = 0;
    sock->tcp.recv_sq = 0;

    event_t event = 0;
    sock->event = &event;
    sock->socket_lock = new_lock;

    /* actually send the packet */
    tcp_send(sock, NULL, 0, TCP_SYN);
    sock->tcp.state = SYN_SENT;

    /* we must now block until the state is updated by accept() when we receive an ACK from
     * the remote host */
    event_await(&event);

    switch (sock->tcp.state) {
        case ESTABLISHED:
           return 0;
        case CLOSED:
            return -1;
        default:
           kprint(KPRN_WARN,
                   "net: tcp: connection returned socket in tcp state %d\n. Connection failed.",
                   sock->tcp.state);
           return -1;
    }
}
