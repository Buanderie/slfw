FROM golang:latest

RUN apt -y update
RUN apt -y install llvm clang libc6-dev-i386 libbpf-dev
RUN apt -y install linux-headers-generic
