package main

import (
	"fmt"
	"os"
	"firewall/cmd"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package fwebpf -output-dir fwebpf -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" InboundBPF ./bpf/inbound.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package fwebpf -output-dir fwebpf -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" OutboundBPF ./bpf/outbound.c
//go:generate ./generate_version.sh

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}