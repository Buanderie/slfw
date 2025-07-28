#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

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
    __uint(max_entries, 32);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} outbound_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} outbound_default_policy SEC(".maps");

static __always_inline void create_lookup_key(struct rule_key *key,
                                            __u32 src_ip, __u32 dst_ip,
                                            __u16 src_port, __u16 dst_port,
                                            __u8 protocol) {
    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->protocol = protocol;
    key->src_ip_mask = 0x0;
    key->dst_ip_mask = 0xffffffff;  // 0xffffffff for TCP
                                    // 0x0 for ICMP
}

// static __always_inline int check_rule_combinations(struct rule_key *key,
//                                                  __u32 src_ip, __u32 dst_ip,
//                                                  __u16 src_port, __u16 dst_port,
//                                                  __u8 protocol,
//                                                  struct rule_value **value) {
//     __u8 max_fields = (protocol == IPPROTO_ICMP) ? 2 : 4;
//     __u32 max_combinations = 1 << max_fields; // 2^4 = 16 for TCP/UDP, 2^2 = 4 for ICMP
//     __u8 src_ip_spec, dst_ip_spec, src_port_spec, dst_port_spec;

//     for (__u32 i = 0; i < max_combinations; i++) {
//         src_ip_spec = (i & (1 << 0)) ? 1 : 0;
//         dst_ip_spec = (i & (1 << 1)) ? 1 : 0;
//         src_port_spec = (protocol == IPPROTO_ICMP || !(i & (1 << 2))) ? 0 : 1;
//         dst_port_spec = (protocol == IPPROTO_ICMP || !(i & (1 << 3))) ? 0 : 1;

//         create_lookup_key(key,
//                          src_ip_spec ? src_ip : 0,
//                          dst_ip_spec ? dst_ip : 0,
//                          src_port_spec ? src_port : 0,
//                          dst_port_spec ? dst_port : 0,
//                          protocol);

//         bpf_printk("[TC_OUT] IP check %d: %lu/%lu\n", i,
//                    src_ip_spec ? src_ip : 0, dst_ip_spec ? dst_ip : 0);
//         bpf_printk("[TC_OUT] PORT check %d: %d/%d\n", i,
//                    src_port_spec ? src_port : 0, dst_port_spec ? dst_port : 0);
//         *value = bpf_map_lookup_elem(&outbound_rules, key);
//         if (*value) {
//             bpf_printk("[TC_OUT] stop_i=%d action=%d\n",i,(*value)->action);
//             return 1;
//         }
//     }
//     return 0; // No rule found
// }

// static __always_inline void print_outbound_rules() {
//     struct rule_key key = {}, next_key = {};
//     struct rule_value *value;

//     while (bpf_map_get_next_key(&outbound_rules, &key, &next_key) == 0) {
//         value = bpf_map_lookup_elem(&outbound_rules, &next_key);
//         if (value) {
//             bpf_printk("RULE: src=%x dst=%x\n",
//                        next_key.src_ip, next_key.dst_ip);
//             bpf_printk("RULE: sport=%u dport=%u\n",
//                        __bpf_ntohs(next_key.src_port),
//                        __bpf_ntohs(next_key.dst_port));
//             bpf_printk("RULE: proto=%u action=%u\n",
//                        next_key.protocol, value->action);
//         }
//         key = next_key;
//     }
// }

static __always_inline int check_outbound_rules(__u32 dst_ip, __u16 src_port, __u8 protocol) {

    struct rule_key lookup_key = {};
    struct rule_value *value;
    __u32 default_key = 0;
    __u8 *default_action;

    // 1. Exact match
    bpf_printk("EXACT\n");
    create_lookup_key(&lookup_key, 0, dst_ip, src_port, 0, protocol);
    value = bpf_map_lookup_elem(&outbound_rules, &lookup_key);
    if (value) {
        bpf_printk("value_0 %d\n", value->action);
        return value->action;
    }

    // 2. Source port any
    bpf_printk("ANY PORT\n");
    create_lookup_key(&lookup_key, 0, dst_ip, 0, 0, protocol);
    value = bpf_map_lookup_elem(&outbound_rules, &lookup_key);
    if (value) {
        bpf_printk("value_1 %d\n", value->action);
        return value->action;
    }

    // 3. Destination address any
    bpf_printk("ANY ADDRESS\n");
    create_lookup_key(&lookup_key, 0, 0, src_port, 0, protocol);
    value = bpf_map_lookup_elem(&outbound_rules, &lookup_key);
    if (value) {
        bpf_printk("value_2 %d\n", value->action);
        return value->action;
    }

    // 4. ANY ANY
    bpf_printk("ANY ANY\n");
    create_lookup_key(&lookup_key, 0, 0, 0, 0, protocol);
    value = bpf_map_lookup_elem(&outbound_rules, &lookup_key);
    if (value) {
        bpf_printk("value_3 %d\n", value->action);
        return value->action;
    }

    return 0;
}

SEC("tc")
int tc_firewall_outbound(struct __sk_buff *skb) {

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        bpf_printk("[TC_OUT] invalid eth header");
        return TC_ACT_OK;
    }

    // if (eth->h_proto != __constant_htons(ETH_P_IP)) {
    //     bpf_printk("[TC_OUT] non-IP packet");
    //     return TC_ACT_OK;
    // }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        bpf_printk("[TC_OUT] invalid IP header");
        return TC_ACT_OK;
    }

    __u32 src_ip = __constant_ntohl(ip->saddr); // Convert to host byte order
    __u32 dst_ip = __constant_ntohl(ip->daddr); // Convert to host byte order
    __u8 protocol = ip->protocol;
    __u16 src_port = 0, dst_port = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)tcp + sizeof(*tcp) > data_end) {
            bpf_printk("[TC_OUT] invalid TCP header");
            return TC_ACT_OK;
        }
        src_port = __constant_ntohs(tcp->source);
        dst_port = __constant_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)udp + sizeof(*udp) > data_end) {
            bpf_printk("[TC_OUT] invalid UDP header");
            return TC_ACT_OK;
        }
        src_port = __constant_ntohs(udp->source);
        dst_port = __constant_ntohs(udp->dest);
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + ip->ihl * 4;
        if ((void *)icmp + sizeof(*icmp) > data_end) {
            bpf_printk("[TC_OUT] invalid ICMP header");
            return TC_ACT_OK;
        }
    } else {
        bpf_printk("[TC_OUT] unknown proto=%d", protocol);
        return TC_ACT_OK;
    }

    // Log packet details
    bpf_printk("[TC_OUT] protocol=%d DST=%ul\n", protocol, dst_ip);
    // bpf_printk("[TC_OUT] src=%u:%d\n", src_ip, src_port);
    // bpf_printk("[TC_OUT] dst=%u:%d\n", dst_ip, dst_port);
    // bpf_printk("[TC_OUT] checking rules\n");

    // struct rule_key lookup_key = {};
    // struct rule_value *value;
    __u32 default_key = 0;
    __u8 *default_action;

    // Check rules
    // if (check_rule_combinations(&lookup_key, src_ip, dst_ip, src_port, dst_port, 6, &value)) {
    //     return value->action ? TC_ACT_OK : TC_ACT_SHOT;
    // }

    if (protocol == IPPROTO_ICMP) {
        bpf_printk("CHECK ICMP - PROTO=%d DST=%ul\n", protocol, dst_ip);
        struct rule_key lookup_key = {};
        struct rule_value *value;
        __u32 default_key = 0;
        __u8 *default_action;

        // 4. ANY ANY
        bpf_printk("ANY ANY\n");
        create_lookup_key(&lookup_key, 0, dst_ip, 0, 0, protocol);
        value = bpf_map_lookup_elem(&outbound_rules, &lookup_key);
        if (value) {
            bpf_printk("value_ICMP !!!!! %d\n", value->action);
            return value->action ? TC_ACT_OK : TC_ACT_SHOT;;
        }
    }

    bpf_printk("[TC_OUT] PRE-CHECK\n");
    int mret = check_outbound_rules(dst_ip, src_port, IPPROTO_TCP);
    if(mret)
    {
        bpf_printk("[TC_OUT] MATCHED TCP\n");
        return mret ? TC_ACT_OK : TC_ACT_SHOT;
    }

    mret = check_outbound_rules(dst_ip, src_port, IPPROTO_UDP);
    if(mret)
    {
        bpf_printk("[TC_OUT] MATCHED UDP\n");
        return mret ? TC_ACT_OK : TC_ACT_SHOT;
    }

    bpf_printk("[TC_OUT] POST-CHECK\n");

    // Default policy
    default_action = bpf_map_lookup_elem(&outbound_default_policy, &default_key);
    __u8 action = (default_action && *default_action == 1) ? 1 : 0;
    bpf_printk("[TC_OUT] action=%c default", action ? 'A' : 'D');
    return action ? TC_ACT_OK : TC_ACT_SHOT;
    // return TC_ACT_OK;

}

char _license[] SEC("license") = "GPL";