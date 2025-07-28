#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct rule_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 src_ip_mask;
    __u32 dst_ip_mask;
};

struct rule_value {
    __u8 action;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
    __uint(max_entries, 256);
} outbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} outbound_default_policy SEC(".maps");

// Use "tc" section for TC hooks
SEC("tc")
int tc_firewall_outbound(struct __sk_buff *skb) {
    // void *data_end = (void *)(long)skb->data_end;
    // void *data = (void *)(long)skb->data;

    // struct ethhdr *eth = data;
    // if ((void *)eth + sizeof(*eth) > data_end)
    //     return TC_ACT_OK;

    // if (eth->h_proto != __constant_htons(ETH_P_IP))
    //     return TC_ACT_OK;

    // struct iphdr *ip = data + sizeof(*eth);
    // if ((void *)ip + sizeof(*ip) > data_end)
    //     return TC_ACT_OK;

    // __u32 src_ip = ip->saddr;
    // __u32 dst_ip = ip->daddr;
    // __u8 protocol = ip->protocol;
    // __u16 src_port = 0, dst_port = 0;

    // // Calculate IP header length in bytes
    // __u32 ip_hdr_len = ip->ihl * 4;
    // void *l4hdr = (void *)ip + ip_hdr_len;

    // // Bounds check before accessing TCP/UDP header
    // if (protocol == IPPROTO_TCP) {
    //     if (l4hdr + sizeof(struct tcphdr) > data_end)
    //         return TC_ACT_OK;
    //     struct tcphdr *tcp = l4hdr;
    //     src_port = __constant_ntohs(tcp->source);
    //     dst_port = __constant_ntohs(tcp->dest);
    // } else if (protocol == IPPROTO_UDP) {
    //     if (l4hdr + sizeof(struct udphdr) > data_end)
    //         return TC_ACT_OK;
    //     struct udphdr *udp = l4hdr;
    //     src_port = __constant_ntohs(udp->source);
    //     dst_port = __constant_ntohs(udp->dest);
    // }

    // struct rule_key lookup_key = {
    //     .src_ip = src_ip,
    //     .dst_ip = dst_ip,
    //     .src_port = src_port,
    //     .dst_port = dst_port,
    //     .protocol = protocol,
    //     .src_ip_mask = 0xffffffff,
    //     .dst_ip_mask = 0xffffffff,
    // };

    // struct rule_value *value = bpf_map_lookup_elem(&outbound_rules, &lookup_key);
    // if (value) {
    //     return value->action ? TC_ACT_OK : TC_ACT_SHOT;
    // }

    // Default: accept
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";