XDP_SRC=src/kg_xdp_prog.c
XDP_OUT=bin/kg_xdp_prog.o
XDP_SEC=xdp

NET_INTERFACE=enp0s3

CC=clang
CFLAGS=-O2 -target bpf -g -c

.PHONY: all build server attach detach clean

all: build attach

build: $(XDP_OUT) server

$(XDP_OUT): $(XDP_SRC)
	$(CC) $(CFLAGS) $< -o $@
	

server:
	clang test/server.c -o bin/server.exe

attach:
	ip link set dev $(NET_INTERFACE) xdp obj $(XDP_OUT) sec $(XDP_SEC)

detach:
	ip link set dev $(NET_INTERFACE) xdp off

clean:
	rm -rf bin/**


