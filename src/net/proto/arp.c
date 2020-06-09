#include <lib/time.h>
#include <lib/event.h>
#include <net/net.h>
#include <net/netstack.h>
#include <lib/klib.h>
#include <lib/errno.h>
#include "arp.h"

/* TODO this naming is stupid, why have 3 structs instead of just one */
struct ipv4_arp_packet_t {
    struct arp_hdr_t hdr;
    struct arp_ipv4_t ipv4;
} __attribute__((packed));

// 4 hour timeout by default
#define ARP_TIMEOUT (60 * 4)

struct arp_entry_t {
    uint64_t timestamp;
    mac_addr_t phys;
    ipv4_addr_t ip;
};

dynarray_new(struct arp_entry_t, arp_cache);

struct arp_request_t {
    ipv4_addr_t ip;
    event_t* event;
};

dynarray_new(struct arp_request_t, arp_requests);

/* check if ipv4 addr already in cache */
static int is_in_cache(ipv4_addr_t addr) {
    size_t i = 0;
    void *res = dynarray_search(struct arp_entry_t, arp_cache, &i,
            IPV4_EQUAL(elem->ip, addr), 0);

    if (res) {
        dynarray_unref(arp_cache, i);
        return 1;
    } else {
        return 0;
    }
}

static int send_arp_request(struct nic_t *nic, ipv4_addr_t addr, mac_addr_t *mac) {
    event_t event = 0;
    struct arp_request_t request = {
        .event = &event,
        .ip = addr
    };

    dynarray_add(struct arp_request_t, arp_requests, &request);

    struct packet_t *pkt = pkt_new();

    struct ether_hdr *ether_hdr = (struct ether_hdr *)pkt->buf;
    ether_hdr->src = nic->mac_addr;
    ether_hdr->dst = (mac_addr_t){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    ether_hdr->type = ETHER_ARP;

    /* according to rfc 826, payload consists of arp packet.
     * construct this payload */
    struct ipv4_arp_packet_t *arp_request = (struct ipv4_arp_packet_t *)(
            pkt->buf + sizeof(struct ether_hdr));
    arp_request->hdr.opcode = ARP_OPCODE_REQUEST;
    arp_request->hdr.proto_addr_len = sizeof(ipv4_addr_t);
    arp_request->hdr.hw_addr_len = sizeof(mac_addr_t);
    arp_request->hdr.hw_type = ARP_HW_ETHER;
    arp_request->hdr.proto_type = ARP_PROTO_IPV4;

    arp_request->ipv4.sender_ip = nic->ipv4_addr;
    arp_request->ipv4.sender_mac = nic->mac_addr;
    arp_request->ipv4.target_ip = addr;
    arp_request->ipv4.target_mac = (mac_addr_t){ {0} };

    pkt->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_arp_packet_t);

    int ret = nic->calls.send_packet(nic->internal_fd, pkt->buf, pkt->pkt_len);

    // wait for the result
    event_await(&event);
    arp_query_ipv4(nic, addr, mac);

    return 0;
}

/* this doesn't really work well with redesigned network architecture */
void arp_process_packet(struct packet_t *pkt) {
    return;
}

int arp_query_ipv4(struct nic_t *nic, ipv4_addr_t addr, mac_addr_t *mac) {
    // first check in the cache if we have the ip
    int i = 0;
    struct arp_entry_t *entry = dynarray_search(struct arp_entry_t, arp_cache, &i, IPV4_EQUAL(elem->ip, addr), 0);

    if (entry) {
        // check the timeout on the entry
        if (unix_epoch - entry->timestamp > ARP_TIMEOUT) {
            dynarray_unref(arp_cache, i);
            dynarray_remove(arp_cache, i);
        }

        // we have it
        *mac = entry->phys;
        dynarray_unref(arp_cache, i);
        return 0;
    }

    /* TODO handle multiple requests at the same time - we need a single request */
    /* could use queue of requests, where send_arp_request is some worker or other */

    // we don't have it, let's request it
    return send_arp_request(nic, addr, mac);
}
