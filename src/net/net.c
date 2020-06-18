#include <stdint.h>
#include <stddef.h>
#include <net/net.h>
#include <net/proto/ether.h>
#include <net/proto/ipv4.h>
#include <net/proto/arp.h>
#include <net/proto/udp.h>
#include <net/proto/tcp.h>
#include <sys/panic.h>
#include <lib/cmem.h>
#include <lib/klib.h>

public_dynarray_new(struct nic_t *, nics);

static struct nic_t *default_nic;

struct packet_t *pkt_new(void) {
    struct packet_t *pkt = kalloc(sizeof(struct packet_t) + 1536); /* ETH_MTU */
    pkt->buf = kalloc(1536u);
    pkt->pkt_len = -1;
    pkt->nic = NULL;

    return pkt;
}

void pkt_free(struct packet_t *pkt) {
    /* check if payload exists */
    if (pkt->buf)
        kfree(pkt->buf);
    kfree((void *)pkt);
}

int addr_to_raw(char *addr) {
    int a1, a2, a3, a4;

    a1 = 256 * 256 * 256 * addr[0];
    a2 = 256 * 256 * addr[1];
    a3 = 256 * addr[2];
    a4 = addr[3];

    return a1 + a2 + a3 + a4;
}

char *raw_to_addr(int raw) {
    char a, b, c, d;

    /* format: a.b.c.d */
    d = raw;
    c = (raw / 256);
    b = (raw / 65536);
    a = (raw / 16777216);

    char *addr = kalloc(4 * sizeof(char));
    addr[0] = (a % 256);
    addr[1] = (b % 256);
    addr[2] = (c % 256);
    addr[3] = (d % 256);

    return addr;
}

void net_add_nic(struct nic_t *nic) {
    char buffer[2 * 6 + 10] = {0};

    nic->subnet = 16;
    nic->ipv4_addr.addr[0] = 169u;
    nic->ipv4_addr.addr[1] = 254u;
    nic->ipv4_addr.addr[2] = 123;
    nic->ipv4_addr.addr[3] = 123;

    dynarray_add(struct nic_t *, nics, &nic);
}

void ipv4_checksum(struct packet_t *pkt) {
    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(pkt->buf + sizeof(struct ether_hdr));

    uint16_t *words = (uint16_t *)ipv4_hdr;
    uint32_t sum32 = 0;

    /* iterate over all words in header */
    for (size_t i = 0; i < ipv4_hdr->head_len * 2; i++)
        sum32 += words[i];

    /* take one's complement */
    uint16_t checksum = (sum32 & 0xffff) + (sum32 >> 16);
    ipv4_hdr->checksum = checksum;
}

struct udp_pseudohdr_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t resv0;
    uint8_t proto;
    uint16_t udp_len;
};

void udp_checksum(struct packet_t *pkt) {
    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(pkt->buf + sizeof(struct ether_hdr));
    struct udp_hdr_t *udp = (struct udp_hdr_t *)((void *)ipv4_hdr + ipv4_hdr->head_len * 4);

    int len = NTOHS(ipv4_hdr->total_len);
    int udp_len = len - sizeof(struct ipv4_hdr_t);

    struct udp_pseudohdr_t p_udp = {
        .src_ip = ipv4_hdr->src,
        .dst_ip = ipv4_hdr->dst,
        .resv0 = 0,
        .proto = PROTO_UDP,
        .udp_len = udp_len,
    };

    uint32_t sum32 = 0;
    uint16_t *p_words = (uint16_t *)&p_udp;

    for (size_t i = 0; i < sizeof(p_words) / 2; i++)
        sum32 += p_words[i];

    uint16_t *u_words = (uint16_t *)udp;

    for (size_t i = 0; i < udp_len / 2; i++)
        sum32 += u_words[i];

    /* account for case where carry-out bit is produced */
    if (udp_len % 2) {
        uint16_t l = ((uint8_t *)ipv4_hdr)[len - 1];
        sum32 += l;
    }

    while (sum32 >> 16)
        sum32 = (sum32 & 0xffff) + (sum32 >> 16);

    udp->checksum = ~(uint16_t)sum32;
}

struct tcp_pseudohdr_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t resv0;
    uint16_t proto;
    uint16_t tcp_len;
};

void tcp_checksum(struct packet_t *pkt) {
    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(pkt->buf + sizeof(struct ether_hdr));
    struct tcp_hdr_t *tcp = (struct tcp_hdr_t *)((void *)ipv4_hdr + ipv4_hdr->head_len * 4);

    int len = NTOHS(ipv4_hdr->total_len);
    int tcp_len = len - sizeof(struct ipv4_hdr_t);

    struct tcp_pseudohdr_t p_tcp = {
        .src_ip = ipv4_hdr->src,
        .dst_ip = ipv4_hdr->dst,
        .resv0 = 0,
        .proto = PROTO_TCP,
        .tcp_len = tcp_len,
    };

    uint32_t sum32 = 0;
    uint16_t *p_words = (uint16_t *)&p_tcp;

    for (size_t i = 0; i < sizeof(p_words) / 2; i++)
        sum32 += p_words[i];

    uint16_t *t_words = (uint16_t *)tcp;

    for (size_t i = 0; i < tcp_len / 2; i++)
        sum32 += t_words[i];

    /* account for case where carry-out bit is produced */
    if (tcp_len % 2) {
        uint16_t l = ((uint8_t *)ipv4_hdr)[len - 1];
        sum32 += l;
    }

    while (sum32 >> 16)
        sum32 = (sum32 & 0xffff) + (sum32 >> 16);

    tcp->checksum = ~(uint16_t)sum32;
}

/* route address to host: update `nic` with
 * the nic corresponding to the right netaddr  */
int net_best_nic(ipv4_addr_t addr, struct nic_t **nic) {
    panic_unless(nic);
    *nic = NULL;

    spinlock_acquire(&nics_lock);

    for (size_t i = 0; i < nics_i; i++) {
        struct nic_t *_nic = nics[i]->data;
        uint32_t mask = ((1 << _nic->subnet) - 1);
        if ((_nic->ipv4_addr.raw & mask) == (addr.raw & mask)) {
            *nic = _nic;
            spinlock_release(&nics_lock);
            return 0;
        }
    }

    spinlock_release(&nics_lock);
    return -1;
}

int net_query_mac(ipv4_addr_t addr, mac_addr_t *mac) {
    struct nic_t *nic = NULL;

    if (!net_best_nic(addr, &nic)) {
        return arp_query_ipv4(nic, addr, mac);
    } else {
        if (!default_nic)
            return -1;

        return net_query_mac(default_nic->ipv4_gateway, mac);
    }
}

/* net_dispatch_pkt(): send an ipv4 packet */
int net_dispatch_pkt(struct packet_t *pkt) {
    struct ether_hdr *ether = (struct ether_hdr *)pkt->buf;
    if (HTONS(ether->type) != ETHER_IPV4)
        return -1;

    struct ipv4_hdr_t *ipv4_hdr = (struct ipv4_hdr_t *)(pkt->buf + sizeof(struct ether_hdr));

    struct nic_t *nic = NULL;
    ipv4_addr_t addr;
    addr.raw = ipv4_hdr->dst;

    /* route the packet */
    if (!net_best_nic(addr, &nic)) {
        /* route found */
        mac_addr_t mac = {0};
        /* search for the correct mac address */
        arp_query_ipv4(nic, addr, &mac);

        mac_addr_t mac_zero = {
            .raw = {0}
        };

        if (!MAC_EQUAL(&mac, &mac_zero)) {
            struct ether_hdr *ether_hdr = (struct ether_hdr *)pkt->buf;
            ether_hdr->src = nic->mac_addr;
            ether_hdr->dst = mac;
            ether_hdr->type = ETHER_IPV4;

            return nic->calls.send_packet(nic->internal_fd, pkt->buf, pkt->pkt_len);
        }

        return -1;
    }
}

void net_process_pkt(struct packet_t *pkt) {
    struct ether_hdr *eth_hdr = (struct ether_hdr *)(pkt->buf);

    switch (eth_hdr->type) {
        case ETHER_IPV4:
            net_process_ip(pkt);
        case ETHER_ARP:
            net_process_arp(pkt);
    }
}

void net_process_ip(struct packet_t *pkt) {}
void net_process_arp(struct packet_t *pkt) {}
