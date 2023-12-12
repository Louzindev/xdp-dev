#include "kg_xdp_pool.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, tcp_key);
    __type(value, struct tcphdr);
    __uint(max_entries, MAX_WAITING_CONNECTIONS);
} waiting_conn_pool SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, tcp_key);
    __uint(max_entries, MAX_WAITING_CONNECTIONS);
} waiting_conn_keymap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, tcp_key);
    __type(value, __u64);
    __uint(max_entries, MAX_WAITING_CONNECTIONS);
} per_waiting_conn_elapsed_time SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} elapsed_time SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = NULL;
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;

    eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        const char fmt[] = "Invalid ETH Header size. Dropping packet...\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return XDP_DROP;
    }

    if (eth->h_proto != htons(ETH_P_IPV6))
    {
        iph = (data + sizeof(struct ethhdr));
        if (iph + 1 > (struct iphdr *)data_end)
        {
            const char fmt[] = "Invalid IP Header size. Dropping packet...\n";
            bpf_trace_printk(fmt, sizeof(fmt));
            return XDP_DROP;
        }
    }
    else
    {
        return XDP_PASS;
    }

    if ((iph && iph->protocol != IPPROTO_TCP))
    {
        return XDP_PASS;
    }

    tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
    if (tcph + 1 > (struct tcphdr *)data_end)
    {
        const char fmt[] = "Invalid TCP Header size. Dropping packet...\n";
        bpf_trace_printk(fmt, sizeof(fmt));
        return XDP_DROP;
    }

    tcp_key key = make_tcp_key(iph, tcph);

    if (verify_syn_packet(tcph))
    {
        const char fmt[] = "New SYN packet.\n";
        bpf_trace_printk(fmt, sizeof(fmt));

        enum kg_pool_error err = waiting_conn_pool_add(key, tcph);
        if (err == POOL_ERROR_NONE)
        {
            const char fmt[] = "Successfully added new Connection to waiting connection pool.\n";
            bpf_trace_printk(fmt, sizeof(fmt));
            if (key != 0)
            {
                const char fmt[] = "TCP Key: %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), key);
            }
            const char fmt2[] = "TCP Header ip = %u, source = %d, dest = %d.\n";
            bpf_trace_printk(fmt2, sizeof(fmt2), iph->saddr, tcph->source, tcph->dest);
            return XDP_PASS;
        }
        else if (err == POOL_ERROR_MULTIPLE_SYN_PERKEY_NOT_PERMITED)
        {
            const char fmt[] = "Error: POOL_ERROR_MULTIPLE_SYN_PERKEY_NOT_PERMITED, dropping packet...\n";
            bpf_trace_printk(fmt, sizeof(fmt));
            if (verify_perkey_elapsed_time(key) > TIME_RESET_WAITING_CONNECTION)
            {
                const char fmt[] = "Timeout: TIME_RESET_WAITING_CONNECTION, removing one connection from connection pool...\n";
                bpf_trace_printk(fmt, sizeof(fmt));
                waiting_conn_pool_remove(key);
            }

            return XDP_PASS;
        }
        else if (err == POOL_ERROR_CONNECTION_MAP_FULL)
        {
            const char fmt[] = "Error: POOL_ERROR_CONNECTION_MAP_FULL, dropping packet...\n";
            bpf_trace_printk(fmt, sizeof(fmt));

            if (verify_elapsed_time() > TIME_RESET_WAITING_CONNECTION_ALL)
            {
                const char fmt[] = "Timeout: TIME_RESET_WAITING_CONNECTION_ALL, cleaning connection pool...\n";
                bpf_trace_printk(fmt, sizeof(fmt));
                waiting_conn_pool_clean();
            }
        }
    }

    if (verify_tcp_key(key) != NULL)
    {
        const char fmt[] = "TCP Key verified!, removing connection from waiting connection pool...\n";
        bpf_trace_printk(fmt, sizeof(fmt));

        waiting_conn_pool_remove(key);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u64 make_tcp_key(struct iphdr *iph, struct tcphdr *tcph)
{
    if (iph != NULL && tcph != NULL)
    {
        __u32 src_ip = iph->saddr;
        __u16 src_port = tcph->source;
        __u16 dest_port = tcph->dest;
        __u64 key = ((__u64)src_ip << 32) | ((__u64)src_port << 16) | (__u64)dest_port;
        return key;
    }

    return 0;
}

__u32 find_tcp_key_index(tcp_key key)
{
    for (int i = 0; i < MAX_WAITING_CONNECTIONS; i++)
    {
        __u32 m_key = i;
        tcp_key *k = bpf_map_lookup_elem(&waiting_conn_keymap, &m_key);
        if (k != 0)
        {
            if (*k == key)
            {
                return m_key;
            }
        }
    }
    return INVALID_KEY_INDEX;
}

__u32 get_empty_keymap_idx()
{
    for (int i = 0; i < MAX_WAITING_CONNECTIONS; i++)
    {
        __u32 m_key = i;
        tcp_key *k = bpf_map_lookup_elem(&waiting_conn_keymap, &m_key);
        if (k && *k == 0)
        {
            return m_key;
        }
    }
    return INVALID_KEY_INDEX;
}

struct tcphdr *verify_tcp_key(tcp_key __key)
{
    tcp_key key = __key;
    if (key != 0)
    {
        struct tcphdr *tcphdr = (struct tcphdr *)bpf_map_lookup_elem(&waiting_conn_pool, &key);
        return tcphdr;
    }
    else
    {
        return NULL;
    }
}

enum kg_pool_error waiting_conn_pool_add(tcp_key __key, struct tcphdr *tcph)
{
    tcp_key key = __key;

    if (verify_tcp_key(key) != NULL)
    {
        return POOL_ERROR_MULTIPLE_SYN_PERKEY_NOT_PERMITED;
    }
    int result = bpf_map_update_elem(&waiting_conn_pool, &key, tcph, BPF_NOEXIST);
    if (result == 0)
    {
        __u32 key_index = get_empty_keymap_idx();
        if (key_index != INVALID_KEY_INDEX)
        {
            bpf_map_update_elem(&waiting_conn_keymap, &key_index, &key, BPF_ANY);
            __u64 time_ns = bpf_ktime_get_ns();
            bpf_map_update_elem(&per_waiting_conn_elapsed_time, &key, &time_ns, BPF_NOEXIST);
        }

        return POOL_ERROR_NONE;
    }
    else
    {
        return POOL_ERROR_CONNECTION_MAP_FULL;
    }
}

int waiting_conn_pool_remove(tcp_key __key)
{
    tcp_key key = __key;

    if (key == 0)
    {
        return 0;
    }

    int result = bpf_map_delete_elem(&waiting_conn_pool, &key);
    if (result == 0)
    {
        __u32 key_index = find_tcp_key_index(key);
        if (key_index != INVALID_KEY_INDEX)
        {
            bpf_map_delete_elem(&waiting_conn_keymap, &key_index);
            bpf_map_delete_elem(&per_waiting_conn_elapsed_time, &key);
        }
        return 1;
    }
    else
    {
        return 0;
    }
}

int waiting_conn_pool_clean()
{
    for (__u32 i = 0; i < MAX_WAITING_CONNECTIONS; i++)
    {
        __u32 m_key = i;
        tcp_key *tcp_key = bpf_map_lookup_elem(&waiting_conn_keymap, &m_key);
        if (tcp_key != 0)
        {
            bpf_map_delete_elem(&waiting_conn_pool, tcp_key);
            bpf_map_delete_elem(&waiting_conn_keymap, &m_key);
            bpf_map_delete_elem(&per_waiting_conn_elapsed_time, tcp_key);
        }
    }
    return 1;
}

int verify_syn_packet(struct tcphdr *tcph)
{
    if (tcph->syn == 1)
    {
        return 1;
    }
    return 0;
}

__u64 verify_elapsed_time()
{
    __u32 key = 0;
    __u64 init_value = bpf_ktime_get_ns();
    __u64 *value = bpf_map_lookup_elem(&elapsed_time, &key);
    if (value == NULL)
    {
        bpf_map_update_elem(&elapsed_time, &key, &init_value, BPF_ANY);
        return 0;
    }
    else
    {
        __u64 current_time = bpf_ktime_get_ns();
        __u64 elapsed_time_ns = current_time - *value;
        __u64 elapsed_time_ms = elapsed_time_ns / 1000000;
        bpf_map_update_elem(&elapsed_time, &key, &init_value, BPF_ANY);
        return elapsed_time_ms;
    }
}

__u64 verify_perkey_elapsed_time(tcp_key __key)
{
    tcp_key key = __key;

    if (key == 0)
    {
        return 0;
    }

    __u64 *value = bpf_map_lookup_elem(&per_waiting_conn_elapsed_time, &key);
    if (value && *value != 0)
    {
        __u64 init_value = bpf_ktime_get_ns();
        __u64 current_time = bpf_ktime_get_ns();
        __u64 elapsed_time_ns = current_time - *value;
        __u64 elapsed_time_ms = elapsed_time_ns / 1000000;
        bpf_map_update_elem(&elapsed_time, &key, &init_value, BPF_ANY);
        return elapsed_time_ms;
    }

    return 0;
}