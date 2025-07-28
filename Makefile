# Makefile for eBPF firewall
.PHONY: all clean generate

all: generate firewall

generate:
	go generate 

firewall: main.go
	CGO_ENABLED=0 go build -o firewall

clean:
	rm -f firewall
	rm -rf bpf_firewall_bpf*