# Makefile for eBPF firewall
.PHONY: all clean generate

all: generate firewall

generate:
	go generate 

firewall: main.go
	go build -o firewall

clean:
	rm -f firewall
	rm -rf bpf_firewall_bpf*