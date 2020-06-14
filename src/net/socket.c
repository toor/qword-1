#include <stdint.h>
#include <stddef.h>
#include <net/socket.h>
#include <lib/dynarray.h>
#include <net/proto/ipv4.h>

/* a simple implementation of sockets for handling tcp and udp connections */
/* provides the follow functions:
 * int socket_connect(): Allows establishing a connection to a specific remote host
 * int socket_accept(): Accept incoming TCP or UDP connection
 * int socket_listen(): Setup socket to begin listening for incoming connections
 * int socket_bind(): Bind a socket to a certain address
 * int socket_new(): Create a new socket and return an associated file descriptor */

public_dynarray_new(struct socket_descriptor_t, sockets);

static int next(void);

/* translate fd to the socket descriptor it refers to */
struct socket_descriptor_t *socket_from_fd(int fd) {
    return dynarray_search(struct socket_descriptor_t, sockets, &fd, elem->valid, 0);
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

    sock->domain = domain;
    sock->type = type;
    sock->proto = proto;
    sock->state = STATE_REQ;
    sock->socket_lock = new_lock;

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

    if (!s)
        return -1;

    return tcp_connect(sock, in_addr);
}

/* setup socket to listen for incoming connections */
int socket_listen(int fd, int backlog) {
    struct socket_descriptor_t *sock = socket_from_fd(fd);

    if (!sock)
        return -1;

    sock->state = STATE_LISTENING;
    sock->tcp.state = LISTEN;

    return 0;
}
