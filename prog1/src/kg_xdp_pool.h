#ifndef __KG_XDP_POOL_H
#define __KG_XDP_POOL_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include <string.h>
#include <memory.h>

#define TIME_RESET_WAITING_CONNECTION 10000
#define TIME_RESET_WAITING_CONNECTION_ALL 15000
#define MAX_WAITING_CONNECTIONS 10
#define INVALID_KEY_INDEX (MAX_WAITING_CONNECTIONS + 1)

enum kg_pool_error
{
    POOL_ERROR_NONE = 0,
    POOL_ERROR_INVALID_HEADERS = 1,
    POOL_ERROR_MULTIPLE_SYN_PERKEY_NOT_PERMITED = 2,
    POOL_ERROR_CONNECTION_MAP_FULL
};

typedef __u64 tcp_key;

tcp_key make_tcp_key(struct iphdr *iph, struct tcphdr *tcph);
__u32 find_tcp_key_index(tcp_key key);
__u32 get_empty_keymap_idx();

struct tcphdr *verify_tcp_key(tcp_key __key);
__u64 verify_elapsed_time();
__u64 verify_perkey_elapsed_time(tcp_key __key);

enum kg_pool_error waiting_conn_pool_add(tcp_key __key, struct tcphdr *tcph);
int waiting_conn_pool_remove(tcp_key __key);
int waiting_conn_pool_clean();

int verify_syn_packet(struct tcphdr *tcph);

#endif