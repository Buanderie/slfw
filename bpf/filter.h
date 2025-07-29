#ifndef __FILTER_H__
#define __FILTER_H__

// Policy values for default policy maps
#define POLICY_ACCEPT 1
#define POLICY_DROP   0

// Structure to represent a port range (e.g., for HTTP/HTTPS)
struct PortRange {
    int start;  // Start of port range (e.g., 80)
    int end;    // End of port range (e.g., 443)
} typedef port_range_t;

// Structure to represent a single firewall rule
struct {
    char rule_name[128];        // Rule name (e.g., "block_ssh_inbound")
    char action[16];            // Action: "allow" or "block"
    char protocol[16];          // Protocol: "tcp", "udp", "icmp", or "any"
    char ip[46];                // IP in CIDR notation (e.g., "192.168.1.0/24") or "any"
    int has_port_range;         // Flag: 1 if port_range is used, 0 if port or none
    union {
        int port;               // Single port (e.g., 22 for SSH)
        port_range_t port_range;   // Port range (e.g., 80-443)
    } port_info;
    char description[256];      // Description of the rule
} typedef firewall_rule_t;

#endif