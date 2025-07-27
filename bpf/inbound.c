#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

// struct bpf_map_def {
//     unsigned int type;
//     unsigned int key_size;
//     unsigned int value_size;
//     unsigned int max_entries;
//     unsigned int map_flags;
//     unsigned int inner_map_idx;
//     unsigned int numa_node;
// };

struct rule_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 icmp_type;
    __u32 src_ip_mask;
    __u32 dst_ip_mask;
};

struct rule_value {
    __u8 action; // 0: DROP, 1: ACCEPT
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} inbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} inbound_default_policy SEC(".maps");

// Crée une clé pour faire une lookup dans la map
static __always_inline void create_lookup_key(struct rule_key *key,
                                              __u32 src_ip, __u32 dst_ip,
                                              __u16 src_port, __u16 dst_port,
                                              __u8 protocol, __u8 icmp_type) {
    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->protocol = protocol;
    key->icmp_type = icmp_type;
    key->src_ip_mask = 0xffffffff;
    key->dst_ip_mask = 0xffffffff;
}

SEC("xdp")
int xdp_firewall_inbound(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    __u16 src_port = 0, dst_port = 0;
    __u8 icmp_type = 0;

    struct rule_key lookup_key = {};
    struct rule_value *value;
    __u32 default_key = 0;
    __u8 *default_action;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        src_port = __constant_ntohs(tcp->source);
        dst_port = __constant_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        src_port = __constant_ntohs(udp->source);
        dst_port = __constant_ntohs(udp->dest);
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + ip->ihl * 4;
        if ((void *)icmp + sizeof(*icmp) > data_end)
            return XDP_PASS;
        icmp_type = icmp->type;
    }

    // 1. Exact match
    create_lookup_key(&lookup_key, src_ip, dst_ip, src_port, dst_port, protocol, icmp_type);
    value = bpf_map_lookup_elem(&inbound_rules, &lookup_key);
    if (value)
        return value->action ? XDP_PASS : XDP_DROP;

    // 2. Source any
    create_lookup_key(&lookup_key, 0, dst_ip, src_port, dst_port, protocol, icmp_type);
    value = bpf_map_lookup_elem(&inbound_rules, &lookup_key);
    if (value)
        return value->action ? XDP_PASS : XDP_DROP;

    // 3. Destination any
    create_lookup_key(&lookup_key, src_ip, 0, src_port, dst_port, protocol, icmp_type);
    value = bpf_map_lookup_elem(&inbound_rules, &lookup_key);
    if (value)
        return value->action ? XDP_PASS : XDP_DROP;

    // 4. IPs any
    create_lookup_key(&lookup_key, 0, 0, src_port, dst_port, protocol, icmp_type);
    value = bpf_map_lookup_elem(&inbound_rules, &lookup_key);
    if (value)
        return value->action ? XDP_PASS : XDP_DROP;

    // 5. ICMP: fallback to wildcard icmp_type = 0
    if (protocol == IPPROTO_ICMP) {
    return XDP_PASS;
}

    // 6. TCP/UDP: ports any
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        create_lookup_key(&lookup_key, 0, 0, 0, dst_port, protocol, 0);
        value = bpf_map_lookup_elem(&inbound_rules, &lookup_key);
        if (value)
            return value->action ? XDP_PASS : XDP_DROP;

        create_lookup_key(&lookup_key, 0, 0, 0, 0, protocol, 0);
        value = bpf_map_lookup_elem(&inbound_rules, &lookup_key);
        if (value)
            return value->action ? XDP_PASS : XDP_DROP;
    }

    // Default policy
    default_action = bpf_map_lookup_elem(&inbound_default_policy, &default_key);
    if (default_action && *default_action == 1)
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
