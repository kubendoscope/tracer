#include "common.h"

#ifndef __MAPS_H__
#define __MAPS_H__

#define MAX_DATA_SIZE_OPENSSL 1024 * 17
#define TASK_COMM_LEN 16

struct address_info {
    __be32 family;
    __be32 saddr4;   
    __be32 daddr4;
    __u8 saddr6[16];  
    __u8 daddr6[16]; 
    __be16 sport;
    __be16 dport;
};

struct go_tls_event {
    u64 order_index; // Used to maintain the order of events
    u64 goid;
    u64 ts_ns;
    u32 fd;
    u32 pid;
    u32 tid;
    struct address_info address_info;
    s32 data_len;
    u8 event_type;
    char comm[TASK_COMM_LEN];
    char data[MAX_DATA_SIZE_OPENSSL];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 33554432); // 16MB ring buffer size, adjust as needed
// } events SEC(".maps");

// PID in eBPF means the thread id, tgid in eBPF means the process id or the thread group id.

// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __type(key, u64);
//     __type(value, struct go_tls_event);
//     __uint(max_entries, 4000);
// } gotls_event_output SEC(".maps");


// key is tgid bitwise or'ed with goroutineid 
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct go_tls_event);
    __uint(max_entries, 1 << 14);
} gotls_write_context SEC(".maps");

// key is tgid bitwise or'ed with goroutineid 
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct go_tls_event);
    __uint(max_entries, 1 << 14);
} gotls_read_context SEC(".maps");

// key is bpf_get_current_pid_tgid , so basically tgid bitwise or'ed with thread id (pid).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u32);
    __uint(max_entries, 1 << 14);
} gotls_write_pid_fd_map SEC(".maps");

// key is tgid bitwise or'ed with fd
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct address_info);
    __uint(max_entries, 1 << 14);
} gotls_write_pidfd_addrinfo_map SEC(".maps");

// key is bpf_get_current_pid_tgid , so basically tgid bitwise or'ed with thread id (pid).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u32);
    __uint(max_entries, 1 << 14);
} gotls_read_pid_fd_map SEC(".maps");

// key is tgid bitwise or'ed with fd
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct address_info);
    __uint(max_entries, 1 << 14);
} gotls_read_pidfd_addrinfo_map SEC(".maps");

// Special maps

// key is goid
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1 << 14);
} gotls_conn_address_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct go_tls_event);
    __uint(max_entries, 1);
} gte_context_gen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} global_order_counter SEC(".maps");

#endif