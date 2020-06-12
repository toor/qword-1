#include <stdint.h>
#include <stddef.h>
#include <net/net.h>
#include <net/proto/udp.h>
#include <net/proto/ipv4.h>
#include <net/proto/ether.h>
#include <net/socket.h>
#include <lib/cmem.h>

void udp_new(struct socket_descriptor_t *sock, struct packet_t *pkt, const void *data, size_t data_len) {
    struct ether_hdr *ether = (struct ether_hdr *)pkt->buf;
    ether->type = ETHER_IPV4;

    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(pkt->buf + sizeof(struct ether_hdr));

    ipv4_hdr->ver = 4;

    ipv4_hdr->ver = 4;
    ipv4_hdr->head_len = sizeof(struct ipv4_hdr_t) / 4;
    ipv4_hdr->tos = 0;
    /* total size of ip datagram: header + tcp header + tcp data */
    ipv4_hdr->total_len = HTONS(sizeof(struct ipv4_hdr_t) + sizeof(struct udp_hdr_t) + data_len);
    ipv4_hdr->id = NTOHS(sock->ip.ipid); /* TODO these capitals look like wank */
    ipv4_hdr->protocol = PROTO_UDP;
    ipv4_hdr->frag_flag = HTONS(IPV4_HEAD_DF_MASK);
    ipv4_hdr->ttl = 64;
    ipv4_hdr->src = sock->ip.source_ip;
    ipv4_hdr->dst = sock->ip.dest_ip;

    struct udp_hdr_t *udp = (struct udp_hdr_t *)((void *)ipv4_hdr + ipv4_hdr->head_len * 4);
    udp->dst_port = HTONS(sock->ip.dest_port);
    udp->src_port = HTONS(sock->ip.source_port);
    udp->length = HTONS(data_len + sizeof(struct udp_hdr_t));
    udp->checksum = 0;

    /* copy payload */
    memcpy(udp->data, data, data_len);

    pkt->pkt_len = NTOHS(ipv4_hdr->total_len) + sizeof(struct ether_hdr);

    ipv4_checksum(pkt);
    udp_checksum(pkt);
}

void udp_send(struct socket_descriptor_t *sock, const void *data, size_t len) {
    struct packet_t *pkt = pkt_new();

    udp_new(sock, pkt, data, len);
    net_dispatch_pkt(pkt);
    pkt_free(pkt);

    sock->ip.ipid += 1;
}
