#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "filter.h"

#define MAX_RULES 16

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, firewall_rule_t);
    __uint(max_entries, MAX_RULES);
} inbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} inbound_default_policy SEC(".maps");

static inline firewall_rule_t *check_rule(__u32 rule_idx) {
    firewall_rule_t *rule = bpf_map_lookup_elem(&inbound_rules, &rule_idx);
    if (!rule || rule->used == 0) {
        // bpf_printk("UNK RULE idx=%d\n", rule_idx);
        return NULL;
    }
    // bpf_printk("FOUND RULE idx=%d used=%d IP=%u\n", rule_idx, rule->used, rule->ip);
    return rule;
}

SEC("xdp")
int xdp_firewall_inbound(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ensure Ethernet header is present
    if (data + sizeof(struct ethhdr) > data_end) {
        bpf_printk("Invalid Ethernet header\n");
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    // Explicitly check for h_proto access
    if ((void *)&eth->h_proto + sizeof(__u16) > data_end) {
        bpf_printk("Cannot access eth->h_proto\n");
        return XDP_PASS;
    }

    // Check for IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_printk("Non-IPv4 packet\n");
        return XDP_PASS;
    }

    // Ensure minimum IP header is present
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        bpf_printk("Invalid IP header\n");
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    // Verify IP header length
    if (ip->ihl < 5) {
        bpf_printk("Invalid IP ihl=%d\n", ip->ihl);
        return XDP_PASS;
    }

    // Calculate transport header offset
    __u32 ip_header_len = ip->ihl * 4;
    void *transport_header = (void *)ip + ip_header_len;

    __u16 dst_port = 0;
    // Parse TCP/UDP header for ports
    if (ip->protocol == IPPROTO_TCP) {
        if (transport_header + sizeof(struct tcphdr) > data_end) {
            // bpf_printk("Invalid TCP header\n");
            return XDP_PASS;
        }
        struct tcphdr *tcp = transport_header;
        dst_port = __constant_ntohs(tcp->source);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (transport_header + sizeof(struct udphdr) > data_end) {
            // bpf_printk("Invalid UDP header\n");
            return XDP_PASS;
        }
        struct udphdr *udp = transport_header;
        dst_port = __constant_ntohs(udp->source);
    } else if (ip->protocol != IPPROTO_ICMP) {
        // bpf_printk("Unsupported protocol=%d\n", ip->protocol);
        return XDP_PASS;
    }

    // Iterate over rules
    for (__u32 i = 0; i < MAX_RULES; i++) {
        firewall_rule_t *rule = check_rule(i);
        if (!rule) {
            continue;
        }

        // Check if rule is enabled
        if (!rule->enabled) {
            continue;
        }

        // Match protocol (0 means any protocol)
        if (rule->protocol != 0 && rule->protocol != ip->protocol) {
            continue;
        }

        // Match source IP (0 means any IP)
        if (rule->ip != 0) {
            __u32 src_ip = __constant_ntohl(ip->saddr);
            if ((src_ip & rule->netmask) != (rule->ip & rule->netmask)) {
                continue;
            }
        }

        // Match destination port for TCP/UDP (no port check for ICMP)
        if (ip->protocol != IPPROTO_ICMP) {
            if (rule->has_port_range) {
                __u16 start = rule->port_info.port_range.start;
                __u16 end = rule->port_info.port_range.end;
                if (dst_port < start || dst_port > end) {
                    continue;
                }
            } else {
                if (rule->port_info.port != 0 && rule->port_info.port != dst_port) {
                    continue;
                }
            }
        }

        // Rule matches, apply action
        // bpf_printk("[IN] MATCH RULE [ %s ] idx=%d action=%d\n", rule->rule_name, i, rule->action);
        if (rule->action == POLICY_ACCEPT) {
            return XDP_PASS;
        }
        return XDP_DROP;
    }

    // Apply default policy
    __u32 key = 0;
    __u8 default_action = POLICY_DROP;
    __u8 *policy = bpf_map_lookup_elem(&inbound_default_policy, &key);
    if (policy) {
        default_action = *policy;
    }
    // bpf_printk("APPLY DEFAULT POLICY action=%d\n", default_action);
    if (default_action == POLICY_ACCEPT) {
        return XDP_PASS;
    }
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";