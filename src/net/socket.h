#ifndef __SOCKET_H__
#define __SOCKET_H__

#include <stdint.h>
#include <stddef.h>
#include <lib/dynarray.h>
#include <lib/lock.h>
#include <lib/event.h>
#include <net/net.h>
#include <lib/list.h>

#define PF_INET 2
#define AF_INET PF_INET

enum socket_type {
    SOCKET_RAW = 0,
    SOCKET_STREAM, /* tcp */
    SOCKET_DGRAM, /* udp */
};

enum socket_state {
    STATE_REQ = 0, /* socket created but not yet bound */
    STATE_BOUND, /* socket bound to remote address */
    STATE_OUT,
    STATE_LISTENING,
    STATE_IDLE,
};

enum tcp_state {
    SYN_SENT,
    ESTABLISHED,
    CLOSED,
    LISTEN,
    SYN_RECEIVED,
};

/* structure that describes all the key info about a socket */
struct socket_descriptor_t {
    /* whether socket has been associated with a remote server */
    /* FIXME: change this to `used` ? */
    int valid;

    int domain; /* TODO: make this a generic socket api  @aurelian */
    int type;
    int proto; /* tcp or udp */
    enum socket_state state;

    struct {
        uint16_t ipid;
        uint32_t source_ip;
        uint16_t source_port;
        uint32_t dest_ip;
        uint16_t dest_port;
    } ip;

    struct {
        uint32_t snd_sq;
        uint32_t ack_sq;
        uint32_t recv_sq;
        uint16_t win_sz;
        enum tcp_state state;
    } tcp;

    lock_t socket_lock;
    event_t event;

    /* list of tcp packets to be accepted */
    // TODO how does one create dynarrays in structs ? is it possible ?
    // no it isn't
    
    list_t accept_pks;
    list_t udp_dgrams;

    /* TODO construct queues for udp datagrams, tcp accept() packets, packets to be ack'd, etc. */
    /* should probably figure out how these will be programmed first */
};

typedef struct {
    uint32_t s_addr;
} in_addr;

/* maybe typedefs ? */
/* https://linux.die.net/man/7/ip */
struct sockaddr_in {
    uint8_t sin_len;
    uint8_t sin_family;
    uint16_t sin_port;
    in_addr sin_addr;
    char sin_zero[8];
};

struct sockaddr {
    uint8_t sa_len;
    uint8_t sa_family;
    char sa_data[14];
};
typedef int socklen_t;

struct socket_descriptor_t *socket_from_fd(int fd);
int socket_new(int, int, int);
int socket_bind(int, const struct sockaddr *, socklen_t);
int socket_listen(int, int);
int socket_accept(int, struct sockaddr *, socklen_t *);
int socket_connect(int, const struct sockaddr *, socklen_t);

int socket_send(int, const void *, size_t, int);
int socket_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t socket_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);

public_dynarray_prototype(struct socket_descriptor_t, sockets);

#endif
