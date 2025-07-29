#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "filter.h"

#define MAX_RULES 512

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, firewall_rule_t);
    __uint(max_entries, MAX_RULES);
} outbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} outbound_default_policy SEC(".maps");

static inline firewall_rule_t *check_rule(__u32 rule_idx) {
    firewall_rule_t *rule = bpf_map_lookup_elem(&outbound_rules, &rule_idx);
    if (!rule || rule->used == 0) {
        // bpf_printk("UNK RULE idx=%d\n", rule_idx);
        return NULL;
    }
    // bpf_printk("FOUND RULE idx=%d used=%d IP=%u\n", rule_idx, rule->used, rule->ip);
    return rule;
}

SEC("tc")
int tc_firewall_outbound(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_OK; // Malformed packet
    }

    // Check for IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return TC_ACT_OK; // Non-IPv4, pass
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return TC_ACT_OK; // Malformed packet
    }

    __u16 src_port = 0;
    // Parse TCP/UDP header for ports
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(*tcp) > data_end) {
            return TC_ACT_OK;
        }
        src_port = __constant_ntohs(tcp->source);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)udp + sizeof(*udp) > data_end) {
            return TC_ACT_OK;
        }
        src_port = __constant_ntohs(udp->source);
    } else if (ip->protocol != IPPROTO_ICMP) {
        return TC_ACT_OK; // Unknown protocol, pass
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
            __u32 src_ip = __constant_ntohl(ip->daddr);
            if ((src_ip & rule->netmask) != (rule->ip & rule->netmask)) {
                continue;
            }
        }

        // Match port for TCP/UDP (no port check for ICMP)
        if (ip->protocol != IPPROTO_ICMP) {
            if (rule->has_port_range) {
                // Check port range
                __u16 start = rule->port_info.port_range.start;
                __u16 end = rule->port_info.port_range.end;
                if (src_port < start || src_port > end) {
                    continue;
                }
            } else {
                // Check single port (0 means any port)
                if (rule->port_info.port != 0 && rule->port_info.port != src_port) {
                    continue;
                }
            }
        }

        // Rule matches, apply action
        bpf_printk("[OUT] MATCH RULE [ %s ] idx=%d action=%d\n", rule->rule_name, i, rule->action);
        if (rule->action == POLICY_ACCEPT) {
            return TC_ACT_OK;
        }
        return TC_ACT_SHOT;
    }

    // Apply default policy
    __u32 key = 0;
    __u8 default_action = POLICY_DROP; // Default to DROP
    __u8 *policy = bpf_map_lookup_elem(&outbound_default_policy, &key);
    if (policy) {
        default_action = *policy;
    }
    // bpf_printk("APPLY DEFAULT POLICY action=%d\n", default_action);
    if (default_action == POLICY_ACCEPT) {
        return TC_ACT_OK;
    }
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";