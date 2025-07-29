#ifndef __FILTER_H__
#define __FILTER_H__

// Policy values for default policy maps
#define POLICY_ACCEPT 1
#define POLICY_DROP   0

// Structure to represent a port range (e.g., for HTTP/HTTPS)
struct PortRange {
    __u16 start;  // Start of port range (e.g., 80)
    __u16 end;    // End of port range (e.g., 443)
} typedef port_range_t;

// Structure to represent a single firewall rule
struct {
    char rule_name[128];        // Rule name (e.g., "block_ssh_inbound")
    __u8 action;            // Action: "ALLOW" => 1 or "DROP" => 0
    __u16 protocol;          // Protocol: IPPROTO_UDP IPPROTO_TCP IPPROTO_ICMP etc.
    __u32 ip;                // IP in 32 bit (0 => ANY)
    __u32 netmask;            // For CIDR ranges
    __u8 has_port_range;         // Flag: 1 if port_range is used, 0 if port or none
    union {
        __u16 port;               // Single port (e.g., 22 for SSH)
        port_range_t port_range;   // Port range (e.g., 80-443)
    } port_info;
    __u8 used;
    __u8 enabled;
} typedef firewall_rule_t;

#endif