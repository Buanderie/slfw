# slfw

## Overview
This project implements a high-performance, auditable firewall for Linux environments using **eBPF (extended Berkeley Packet Filter)**. It leverages **XDP (eXpress Data Path)** for ingress filtering and **TC (Traffic Control)** for egress filtering, bypassing Docker’s problematic iptables NAT rules. Built with **Cilium’s eBPF library** in a portable **GoLang application**, the firewall uses a **YAML configuration file** and a **binary diff-based audit process** to ensure runtime rules match the intended policy. This solution provides superior security, performance, and auditability compared to traditional iptables-based firewalls.

## Features
- **XDP Ingress Filtering**: Blocks incoming packets at the network driver level for maximum performance and early threat mitigation.
- **TC Egress Filtering**: Controls container-originated outbound traffic with fine-grained rules.
- **Cilium/eBPF Integration**: Uses Cilium’s robust eBPF library for reliable program and map management.
- **GoLang Binary**: Portable, single-binary deployment across platforms for easy distribution.
- **YAML Configuration**: Human-readable, version-controllable rule definitions.
- **Binary Diff Audits**: Verifies runtime eBPF map rules against YAML config to ensure policy integrity.
- **Docker Compatibility**: Operates at the interface level to avoid conflicts with Docker’s iptables NAT rules.

## Technical Justification
Docker’s heavy reliance on iptables for NAT (e.g., port mapping, masquerading) creates challenges for traditional firewalls:
- **iptables Limitations**:
  - Docker dynamically modifies iptables rules (e.g., DOCKER chain), overwriting custom filters.
  - Parsing `iptables -S` is error-prone due to NAT clutter, making audits unreliable.
  - L3/L4 focus lacks container-aware context, limiting granularity.
  - Netfilter hooks introduce performance overhead, increasing DoS risks.
- **eBPF Advantages**:
  - **Security**: XDP/TC filtering at the interface level bypasses Docker’s NAT, ensuring consistent rule enforcement. Container-aware rules (via Cilium) enhance granularity.
  - **Auditability**: eBPF maps provide structured, queryable rule storage. Binary diff audits compare map contents to YAML-derived rules, guaranteeing policy alignment.
  - **Performance**: XDP processes ingress packets at the driver level, and TC handles egress efficiently, minimizing latency and DoS exposure.
  - **Flexibility**: Dynamic rule updates without traffic disruption and portable GoLang deployment simplify management.

## Why eBPF Over iptables?
This eBPF firewall is more secure and auditable than iptables in Docker environments because:
1. **No NAT Conflicts**: XDP/TC operate before Docker’s NAT stack, preventing rule overrides.
2. **Reliable Audits**: Binary diff of eBPF maps against YAML config is precise and programmatic, unlike iptables’ messy text output.
3. **Container Awareness**: Supports container-specific rules, surpassing iptables’ L3/L4 limitations.
4. **Performance**: XDP/TC’s low-latency processing reduces attack surface compared to iptables’ Netfilter hooks.

## Security Considerations
- **Implementation**: Custom eBPF programs and audit logic require rigorous testing to prevent bugs or bypasses.
- **Privileges**: The GoLang app requires CAP_BPF/CAP_NET_ADMIN; secure deployment is critical to prevent tampering.
- **Dependencies**: Regular updates to Cilium/eBPF, GoLang, and the Linux kernel mitigate potential vulnerabilities.

## Getting Started
1. **Build Dependencies**:
   - GoLang (v1.18+)
   - Make
   - LLVM
   - Clang
   - libc6-dev-i386
   - libbpf-dev
   - linux-headers-generic
2. **Runtime Dependencies**:
   - Linux kernel with eBPF support (v4.15+ for XDP, v4.19+ for TC clsact)
3. **Build**:
   ```bash
   make
   ```
4. **Configure**:
   - Edit a YAML configuration file to define rules (e.g., src_ip, dst_port, action).
5. **Run**:
    * Attach to an interface (no rules loaded)
   ```bash
   sudo ./ebpf-firewall -i eth0 attach
   ```

   * Attach and load a configuration to an interface
   ```bash
   sudo ./ebpf-firewall -i eth0 load -c config.yaml
   xxx@xxx:$ sudo ./firewall -i eth0 load -c test_config.yaml
    Using existing pinned eBPF objects at /sys/fs/bpf/slfw_eth0
    Set inbound default policy to DROP
    Set outbound default policy to DROP
    Loading 3 rules for interface eth0...
    ✓ Added block_specific_ip_inbound rule at index 0
    ✓ Added block_specific_ip_inbound rule at index 1
    ✓ Added block_specific_ip_inbound rule at index 2
    Loading 6 rules for interface eth0...
    ✓ Added allow_dns_udp_outbound rule at index 0
    ✓ Added allow_dns_tcp_outbound rule at index 1
    ✓ Added allow_doh_outbound rule at index 2
    ✓ Added allow_dot_outbound rule at index 3
    ✓ Added allow_icmp_outbound rule at index 4
    ✓ Added block_specific_port_range_outbound rule at index 5
    Firewall rules applied to interface eth0
   ```

   * Detach firewall from an interface
   ```bash
   sudo ./ebpf-firewall -i eth0 detach
   ```

* Print rules enforced on an interface
   ```bash
   xxx@xxx:$ sudo ./firewall -i eth0 print
    Inbound Rules:
    Rule block_specific_ip_inbound: icmp any n/a:ALLOW
    Rule block_specific_ip_inbound: udp any 53:ALLOW
    Rule block_specific_ip_inbound: tcp any 53:BLOCK

    Outbound Rules:
    Rule allow_dns_udp_outbound: udp any 53:ALLOW
    Rule allow_dns_tcp_outbound: tcp any 53:ALLOW
    Rule allow_doh_outbound: tcp any 443:ALLOW
    Rule allow_dot_outbound: tcp any 853:ALLOW
    Rule allow_icmp_outbound: icmp any n/a:ALLOW
    Rule block_specific_port_range_outbound: tcp 10.0.0.0/16 1000-2000:BLOCK
   ```
6. Detach firewall from an interface
     ```bash
     xxx@xxx:$ sudo ./firewall -i eth0 detach
    Detached XDP program from eth0
    Successfully detached eBPF programs and removed pinned objects from eth0
     ```

7. **Audit**:
   - Run the audit command to verify map rules against config:
     ```bash
     sudo ./firewall -i eth0 audit -c config.yaml
     ```

## Example YAML Config
```yaml
inbound_policy: "DROP"
inbound:
  - rule_name: "block_specific_ip_inbound"
    action: "allow"
    protocol: "icmp"
    ip: "any"
    description: "Block all inbound traffic from 203.0.113.5"
  - rule_name: "block_specific_ip_inbound"
    action: "allow"
    protocol: "udp"
    ip: "any"
    port: 53
    description: "Block all inbound traffic from 203.0.113.5"
  - rule_name: "block_specific_ip_inbound"
    action: "block"
    protocol: "tcp"
    ip: "any"
    port: 53
    description: "Block all inbound traffic from 203.0.113.5"

outbound_policy: "DROP"
outbound:
  - rule_name: "allow_icmp_outbound"
    action: "allow"
    protocol: "icmp"
    ip: "any"
    description: "Allow outbound ICMP traffic"
  - rule_name: "block_specific_port_range_outbound"
    action: "block"
    protocol: "tcp"
    ip: "10.0.0.0/16"
    port_range:
      start: 1000
      end: 2000
    description: "Block outbound TCP traffic to 10.0.0.0/16 on ports 1000-2000"
```

## Future Improvements
- Add observability with eBPF ring buffer logging for dropped packets.
- Add stats for dropped packets
- Add bandwidth control (global + per-rule ?)

## License
MIT License