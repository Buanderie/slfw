#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h> // Added for IPPROTO_*


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

struct bpf_map_def SEC("maps") outbound_rules = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 1000,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct rule_value),
};

struct bpf_map_def SEC("maps") outbound_default_policy = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 1,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
};

SEC("tc")
int tc_firewall_outbound(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    struct rule_key key = {};
    struct rule_value *value;
    __u32 default_key = 0;
    __u8 *default_action;

    // Check Ethernet header
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Check IP header
    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    key.src_ip_mask = 0xffffffff;
    key.dst_ip_mask = 0xffffffff;

    // Handle protocols
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;
        key.src_port = __constant_ntohs(tcp->source);
        key.dst_port = __constant_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)udp + sizeof(*udp) > data_end)
            return TC_ACT_OK;
        key.src_port = __constant_ntohs(udp->source);
        key.dst_port = __constant_ntohs(udp->dest);
    } else if (ip->protocol == IPPROTO_ICMP) {
        icmp = (void *)ip + (ip->ihl * 4);
        if ((void *)icmp + sizeof(*icmp) > data_end)
            return TC_ACT_OK;
        key.icmp_type = icmp->type;
    }

    // Check rules
    value = bpf_map_lookup_elem(&outbound_rules, &key);
    if (value) {
        if (value->action == 1)
            return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    // Try with "any" IP (0.0.0.0/0)
    key.src_ip = 0;
    key.dst_ip = 0;
    key.src_ip_mask = 0;
    key.dst_ip_mask = 0;
    value = bpf_map_lookup_elem(&outbound_rules, &key);
    if (value) {
        if (value->action == 1)
            return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    // Apply default policy
    default_action = bpf_map_lookup_elem(&outbound_default_policy, &default_key);
    if (default_action && *default_action == 1)
        return TC_ACT_OK;
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";