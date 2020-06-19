#include <stdint.h>
#include <stddef.h>
#include <net/socket.h>
#include <lib/dynarray.h>
#include <lib/list.h>
#include <lib/lock.h>
#include <lib/cmem.h>
#include <lib/klib.h>
#include <net/proto/ipv4.h>
#include <net/proto/tcp.h>
#include <net/proto/udp.h>
#include <net/proto/ether.h>

/* a simple implementation of sockets for handling tcp and udp connections */
/* provides the following functions:
 * int socket_connect(): Allows establishing a connection to a specific remote host
 * int socket_accept(): Accept incoming TCP or UDP connection
 * int socket_listen(): Setup socket to begin listening for incoming connections
 * int socket_bind(): Bind a socket to a certain address
 * int socket_new(): Create a new socket and return an associated file descriptor */

public_dynarray_new(struct socket_descriptor_t, sockets);

static int socket_next(void) {
    int fd = 0;

    struct socket_descriptor_t *sock = dynarray_search(struct socket_descriptor_t, sockets,
            &fd, !elem->valid, 0);

    if (!sock)
        return -1;

    return fd;
}

/* translate fd to the socket descriptor it refers to */
struct socket_descriptor_t *socket_from_fd(int fd) {
    struct socket_descriptor_t *sock = dynarray_getelem(struct socket_descriptor_t,
            sockets, fd);

    if (!sock) {
        return NULL;
    } else if (!sock->valid) {
        return NULL;
    } else {
        return sock;
    }
}

/* construct a new socket and return the corresponding file descriptor */
int socket_new(int domain, int type, int proto) {
    size_t fd = 0;
    /* find first unused element */
    struct socket_descriptor_t *sock = dynarray_search(struct socket_descriptor_t, sockets, &fd,
                                                     !elem->valid, 0);
    if (!sock)
        return -1;
    sock->valid = 1;

    if (domain != AF_INET)
        return -1;

    switch (type) {
        case SOCKET_DGRAM:
            proto = PROTO_UDP;
            break;
        case SOCKET_STREAM:
            proto = PROTO_TCP;
            break;
        default:
            break;
    }

    event_t event = 0;

    sock->domain = domain;
    sock->type = type;
    sock->proto = proto;
    sock->state = STATE_REQ;
    sock->socket_lock = new_lock;
    sock->event = event;

    return fd;
}

/* bind a socket to a given external address. return 0 on success. */
int socket_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);
    /* first, check addr has the right length */
    if (addrlen != sizeof(struct sockaddr_in)) {
        return -1;
    }

    /* construct family-specific address */
    struct sockaddr_in *sockaddr = (struct sockaddr_in *)addr;
    /* validate domain */
    if (sockaddr->sin_family != AF_INET)
        return -1;
    sock->ip.source_ip = sockaddr->sin_addr.s_addr;
    sock->ip.source_port = sockaddr->sin_port;

    sock->state = STATE_BOUND;

    return 0;
}

/* send some data over a socket as either a tcp or udp payload */
int socket_send(int fd, const void *data, size_t data_len, int flags) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (sock->state != STATE_OUT)
        return -1;

    switch (sock->type) {
        case SOCKET_DGRAM:
            udp_send(sock, data, data_len);
        case SOCKET_STREAM:
            tcp_send(sock, data, data_len, flags);
    }

    return 0;
}

/* perform 3-way tcp handshake */
int socket_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;

    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (!sock)
        return -1;

    return tcp_connect(sock, in_addr);
}

/* setup socket to listen for incoming connections */
int socket_listen(int fd, int backlog) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (!sock)
        return -1;

    list_init(&sock->accept_pks);
    sock->state = STATE_LISTENING;
    sock->tcp.state = LISTEN;

    return 0;
}

int socket_accept(int fd, struct sockaddr *addr, socklen_t *len) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (!sock)
        return -1;

    if (sock->type != SOCKET_STREAM)
        return -1;

    spinlock_acquire(&sock->socket_lock);

    struct packet_t *a_pkt;
    /* wait while queue is empty, queue will be filled
     * from net_process_pkt */
    do {
        event_await(&sock->event);
    } while (!list_head(&sock->accept_pks));

    a_pkt = (struct packet_t *)list_pop(&sock->accept_pks);

    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(a_pkt->buf + sizeof(struct ether_hdr));
    struct tcp_hdr_t *tcp_hdr = (struct tcp_hdr_t *)(ipv4_hdr + 4 * ipv4_hdr->head_len);

    /* TODO ensure this is a SYN packet */

    int new_fd = -1;
    /* construct socket to send ACK to */
    struct socket_descriptor_t *ack_sock = dynarray_search(struct socket_descriptor_t,
            sockets, &new_fd, !elem->valid, 0);
    if (!ack_sock)
        return -1;
    ack_sock->valid = 1;

    memcpy(ack_sock, sock, sizeof(struct socket_descriptor_t));
    ack_sock->socket_lock = new_lock;

    /* swap dest and src */
    ack_sock->state = STATE_OUT;
    ack_sock->tcp.state = SYN_RECEIVED;
    ack_sock->ip.dest_ip = ipv4_hdr->src;
    ack_sock->ip.dest_port = tcp_hdr->source;
    ack_sock->tcp.recv_sq = NTOHL(tcp_hdr->seq_num);

    if (!ack_sock->ip.source_ip)
        /* TODO i can't remember where we actually initialise the NIC */
        ack_sock->ip.source_ip = a_pkt->nic->ipv4_addr.raw;

    /* point `addr` to address of peer socket */
    struct sockaddr_in in_addr = {
        .sin_len = AF_INET,
        .sin_port = ack_sock->ip.dest_port,
        .sin_addr = {ack_sock->ip.dest_ip},
    };

    memcpy(addr, &in_addr, sizeof(in_addr));
    *len = sizeof(in_addr);

    tcp_send(ack_sock, NULL, 0, TCP_SYN | TCP_ACK);
    spinlock_release(&sock->socket_lock);

    return new_fd;
}

int socket_close(int fd) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (!sock)
        return -1;

    sock->state = STATE_IDLE;
    sock->valid = 0;

    return 0;
}

ssize_t socket_recvfrom(int fd, void *buf, size_t len, int flags,
        struct sockaddr *sockaddr, socklen_t *addrlen) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);
    if (!sock)
        return -1;

    spinlock_acquire(&sock->socket_lock);

    struct packet_t *r_pkt;
    do {
        event_await(&sock->event);
    } while (!list_head(&sock->udp_dgrams));

    r_pkt = (struct packet_t *)list_pop(&sock->udp_dgrams);

    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr *)(r_pkt->buf + sizeof(struct ether_hdr));
    struct udp_hdr_t *udp_hdr = (struct udp_hdr_t *)(ipv4_hdr + 4 * ipv4_hdr->head_len);
    void *data = udp_hdr->data;
    int udp_data_len = NTOHS(ipv4_hdr->total_len) - sizeof(struct ipv4_hdr_t) - sizeof(struct udp_hdr_t);


    /* point `addr` to address of peer socket */
    struct sockaddr_in *in_addr = (struct sockaddr_in *)sockaddr;

    if (*addrlen < sizeof(*in_addr))
        return -1;

    in_addr->sin_family = AF_INET;
    in_addr->sin_port = udp_hdr->src_port;
    in_addr->sin_addr.s_addr = ipv4_hdr->src;
    *addrlen = (socklen_t)sizeof(in_addr);

    if (len < udp_data_len)
        len = udp_data_len;

    memcpy(buf, data, len);
    spinlock_release(&sock->socket_lock);

    return 0;
}

int socket_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr,
        socklen_t addrlen) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (!sock)
       return -1;

    struct sockaddr_in *in_addr;

    switch (sock->type) {
        case SOCKET_DGRAM:
            in_addr = (struct sockaddr_in *)addr;
            if (addrlen != sizeof(*in_addr))
                return -1;
            udp_sendto(sock, addr, buf, len); /* TODO flags */
            return 0;
        default:
            kprint(KPRN_WARN, "sendto called with socket of type != SOCK_DGRAM. sendto on streams currently unimplemented");
            return -1;
    }
}

/* TODO: implement udp dispatch to socket in the netstack,
 * then can test udp sockets properly. */
