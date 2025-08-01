# Makefile for eBPF firewall
.PHONY: all clean generate

all: secure-linux-firewall

bpf_programs: bpf/inbound.c bpf/outbound.c
	go generate 

secure-linux-firewall: bpf_programs main.go
	CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -o secure-linux-firewall

clean:
	rm -f secure-linux-firewall
	rm -rf bpf_firewall_bpf*
	rm -rf *_bpfe*
	rm -rf fwebpf/*_bpfe*
