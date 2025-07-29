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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, firewall_rule_t);
    __uint(max_entries, 1024);
} outbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1);
} outbound_default_policy SEC(".maps");

// Helper to parse IP string (e.g., "192.168.1.1" or "192.168.1.0/24")
static inline int parse_ip_str(const char *ip_str, __u32 *ip_addr, __u32 *mask) {
    __u32 addr = 0;
    __u32 bits = 32;
    int i, j = 0;
    int num = 0;

    // Simple parsing for "xxx.xxx.xxx.xxx" or "xxx.xxx.xxx.xxx/yy"
    for (i = 0; i < 46 && ip_str[i]; i++) {
        if (ip_str[i] >= '0' && ip_str[i] <= '9') {
            num = num * 10 + (ip_str[i] - '0');
        } else if (ip_str[i] == '.' && j < 3) {
            addr = (addr << 8) | (num & 0xff);
            num = 0;
            j++;
        } else if (ip_str[i] == '/') {
            addr = (addr << 8) | (num & 0xff);
            num = 0;
            i++;
            for (; i < 46 && ip_str[i]; i++) {
                num = num * 10 + (ip_str[i] - '0');
            }
            bits = num;
            break;
        }
    }
    if (j == 3 && !ip_str[i]) {
        addr = (addr << 8) | (num & 0xff);
    }

    *ip_addr = addr;
    *mask = ~((1ULL << (32 - bits)) - 1);
    return ip_str[0] == 'a' && ip_str[1] == 'n' && ip_str[2] == 'y' ? 0 : 1; // 0 for "any"
}

// Helper to match IP against rule's IP
// static inline int match_ip(__u32 pkt_ip, const char *rule_ip) {
//     if (rule_ip[0] == 'a' && rule_ip[1] == 'n' && rule_ip[2] == 'y') {
//         return 1; // Match any IP
//     }
//     __u32 rule_addr, mask;
//     if (parse_ip_str(rule_ip, &rule_addr, &mask) == 0) {
//         return 1; // "any"
//     }
//     return (pkt_ip & mask) == (rule_addr & mask);
// }

// Helper to match protocol
static inline int match_protocol(__u8 pkt_proto, const char *rule_proto) {
    if (rule_proto[0] == 'a' && rule_proto[1] == 'n' && rule_proto[2] == 'y') {
        return 1; // Match any protocol
    }
    if (pkt_proto == IPPROTO_TCP && rule_proto[0] == 't' && rule_proto[1] == 'c' && rule_proto[2] == 'p') {
        return 1;
    }
    if (pkt_proto == IPPROTO_UDP && rule_proto[0] == 'u' && rule_proto[1] == 'd' && rule_proto[2] == 'p') {
        return 1;
    }
    if (pkt_proto == IPPROTO_ICMP && rule_proto[0] == 'i' && rule_proto[1] == 'c' && rule_proto[2] == 'm' && rule_proto[3] == 'p') {
        return 1;
    }
    return 0;
}

// Helper to match port (or skip for ICMP)
static inline int match_port(__u16 pkt_port, firewall_rule_t *rule) {
    if (rule->protocol[0] == 'i' && rule->protocol[1] == 'c' && rule->protocol[2] == 'm' && rule->protocol[3] == 'p') {
        return 1; // ICMP has no ports, always match
    }
    if (rule->has_port_range) {
        int start = rule->port_info.port_range.start;
        int end = rule->port_info.port_range.end;
        return pkt_port >= start && pkt_port <= end;
    }
    return pkt_port == rule->port_info.port || rule->port_info.port == 0;
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
        return TC_ACT_OK; // Non-IPv4, pass to default policy
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return TC_ACT_OK;
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
        return TC_ACT_OK; // Unknown protocol, pass to default policy
    }

    // Iterate over rules
    for (__u32 i = 0; i < 1024; i++) {
        firewall_rule_t *rule;
        rule = bpf_map_lookup_elem(&outbound_rules, &i);
        if (!rule) {
            continue; // Skip empty or invalid slots
        }

        // Match protocol, source IP, and source port
        if (match_protocol(ip->protocol, rule->protocol) &&
            // match_ip(__constant_ntohl(ip->saddr), rule->ip) &&
            match_port(src_port, rule)) {
            // if (rule.action[0] == 'a' && rule.action[1] == 'l' && rule.action[2] == 'l' && rule.action[3] == 'o' && rule.action[4] == 'w') {
            //     return TC_ACT_OK; // Allow
            // } else {
            //     return TC_ACT_SHOT; // Block
            // }
            return TC_ACT_OK;
        }
    }

    // Apply default policy
    // __u32 key = 0;
    // __u8 default_action = POLICY_DROP; // Default to DROP
    // bpf_map_lookup_elem(&outbound_default_policy, &key, &default_action);
    // if (default_action == POLICY_ACCEPT) {
    //     return TC_ACT_OK;
    // }
    // return TC_ACT_SHOT;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";