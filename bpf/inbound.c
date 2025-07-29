#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#include "filter.h"

struct rule_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 src_ip_mask;
    __u32 dst_ip_mask;
};

struct rule_value {
    __u8 action; // 0: DROP, 1: ACCEPT
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, firewall_rule_t);
} inbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} inbound_default_policy SEC(".maps");

SEC("xdp")
int xdp_firewall_inbound(struct xdp_md *ctx) {

    bpf_printk("XDP SBOOB program loaded and running\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";