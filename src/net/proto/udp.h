#ifndef __NET__PROTO__UDP_H__
#define __NET__PROTO__UDP_H__

#include <stdint.h>
#include <net/net.h>
#include <net/socket.h>

struct udp_hdr_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    char *data;
} __attribute__((packed));

/* construct a new packet to send over UDP */
void udp_new(struct socket_descriptor_t *, struct packet_t *, const void *, size_t);
/* send some data over udp */
void udp_send(struct socket_descriptor_t *, const void *, size_t);

#endif //__NET_PROTO__UDP_H__
