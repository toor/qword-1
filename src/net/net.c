#include <stdint.h>
#include <stddef.h>
#include <net/net.h>
#include <net/proto/ether.h>
#include <net/proto/ipv4.h>
#include <net/proto/arp.h>
#include <sys/panic.h>
#include <lib/cmem.h>
#include <lib/klib.h>

public_dynarray_new(struct nic_t *, nics);

static struct nic_t *default_nic;

struct packet_t *pkt_new(void) {
    struct packet_t *pkt = kalloc(sizeof(struct packet_t) + 1536); /* ETH_MTU */
    pkt->pkt_len = -1;
    pkt->nic = NULL;

    return pkt;
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
    /* TODO: check that this is an ip packet */
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
