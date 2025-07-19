#include "include/common.h"

#include "include/maps.h"


#define GOTLS_EVENT_TYPE_WRITE 1

#define GOTLS_EVENT_TYPE_READ  2


// TLS record types from Go's tls package

#define recordTypeApplicationData 23


const __s32 invalid_fd = -1;


static __always_inline u64 next_order_index() {
    u32 key = 0;
    u64 *counter = bpf_map_lookup_elem(&global_order_counter, &key);
    if (!counter) return 0;

    // Use this workaround: create local temp and fetch *before* increment
    u64 current = *counter;
    __sync_fetch_and_add(counter, 1);
    return current;
}



struct go_interface {

    __s64 type;

    void* ptr;

};


static __always_inline struct go_tls_event *get_gotls_event(void* context, u8 event_type, u64 goroutine_id, u64 order_index) {

    u32 zero = 0;

    struct go_tls_event *event = bpf_map_lookup_elem(&gte_context_gen, &zero);

    if (!event) return 0;


    u64 pid_tgid = bpf_get_current_pid_tgid();

    u64 pid = pid_tgid >> 32;

    u64 id = (pid << 32) | goroutine_id;

    event->order_index = order_index;

    event->goid  = id;

    event->ts_ns = bpf_ktime_get_ns();

    event->pid   = pid;

    event->tid   = (__u32)pid_tgid;

    event->event_type = event_type;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_map_update_elem(context, &id, event, BPF_ANY);

    return bpf_map_lookup_elem(context, &id);

}


static __always_inline int get_fd_from_conn(struct pt_regs *ctx, bool is_register_abi, __u32 *fd) {

    struct go_interface conn;

    void* addr = (void *)go_get_argument(ctx, is_register_abi, 1);

    if (bpf_probe_read(&conn, sizeof(conn), addr) != 0) return -1;


    void* net_conn_struct_ptr;

    if (bpf_probe_read(&net_conn_struct_ptr, sizeof(net_conn_struct_ptr), conn.ptr) != 0) return -1;

    if (bpf_probe_read(fd, sizeof(*fd), net_conn_struct_ptr + 0x10) != 0) return -1;


    return 0;

}


static __always_inline int gotls_read(struct pt_regs *ctx, bool is_register_abi, u64 counter) {

    u64 goid = GOROUTINE(ctx);
    struct go_tls_event *event = get_gotls_event(&gotls_read_context, GOTLS_EVENT_TYPE_READ, goid, counter);

    if (!event) return 0;


    u32 fd = invalid_fd;

    if (get_fd_from_conn(ctx, is_register_abi, &fd) < 0) return 0;

    u64 ptr = (u64)go_get_argument(ctx, is_register_abi, 1);

    bpf_printk("gotls_read: goid=%llu, fd=%u, ptr=0x%llx", goid, fd, ptr);
    bpf_map_update_elem(&gotls_conn_address_map, &goid, &ptr, BPF_ANY);

    event->fd = fd;

    return 0;

}


static __always_inline int gotls_write(struct pt_regs *ctx, bool is_register_abi, u64 counter) {

    s32 record_type, len;

    const char *str;

    void *record_type_ptr = (void *)go_get_argument(ctx, is_register_abi, 2);

    void *len_ptr = (void *)go_get_argument(ctx, is_register_abi, 4);

   

    bpf_probe_read_kernel(&record_type, sizeof(record_type), &record_type_ptr);

    bpf_probe_read_kernel(&len, sizeof(len), &len_ptr);

   

    if (len == 0 || record_type != recordTypeApplicationData) return 0;


    str = (const char *)go_get_argument(ctx, is_register_abi, 3);

    struct go_tls_event *event = get_gotls_event(&gotls_write_context, GOTLS_EVENT_TYPE_WRITE, GOROUTINE(ctx), counter);
    if (!event) return 0;

    len = len & 0xFFFF;
    event->data_len = len;

    if (bpf_probe_read_user(&event->data, sizeof(event->data), str) < 0) return 0;

    u32 fd = invalid_fd;
    if (get_fd_from_conn(ctx, is_register_abi, &fd) < 0) return 0;
    event->fd = fd;

    if (len < 200) {
        bpf_printk("gotls_write captured data: %s", &event->data);
    }

    return 0;
}


static __always_inline int process_event_with_address_info(struct pt_regs *ctx, struct go_tls_event *event, u64 id, u64 pid, void* addr_map) {

    u64 key = (pid << 32) | event->fd;

    struct address_info* addr_info = bpf_map_lookup_elem(addr_map, &key);


    if (!addr_info) return -1;


    event->address_info.family = addr_info->family;

    event->address_info.dport = addr_info->dport;

    event->address_info.sport = addr_info->sport;


    if (addr_info->family == AF_INET) {

        event->address_info.saddr4 = addr_info->saddr4;

        event->address_info.daddr4 = addr_info->daddr4;

    } else if (addr_info->family == AF_INET6) {

        __builtin_memcpy(event->address_info.saddr6, addr_info->saddr6, sizeof(addr_info->saddr6));

        __builtin_memcpy(event->address_info.daddr6, addr_info->daddr6, sizeof(addr_info->daddr6));

    } else {

        return -1;

    }
    // Still update the context map (if you're using it elsewhere)
    // bpf_map_update_elem(&gotls_event_output, &id, event, BPF_ANY);

    return 0;
}



static __always_inline int gotls_write_ret(struct pt_regs *ctx, bool is_register_abi) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    u64 goroutine_id = GOROUTINE(ctx);
    u64 id = (pid << 32) | goroutine_id;

    bpf_printk("gotls_write_ret_register called");

    struct go_tls_event *event = bpf_map_lookup_elem(&gotls_write_context, &id);
    if (!event) return -1;

    int ret = process_event_with_address_info(ctx, event, id, pid, &gotls_write_pidfd_addrinfo_map);
    if (ret < 0){
        bpf_map_delete_elem(&gotls_write_context, &id);
        return ret;
    };

    // bpf_ringbuf_output(&events, event, sizeof(*event), 0);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_printk("gotls_event captured: goid %llu, fd %u, data_len %d", event->goid, event->fd, event->data_len);

    bpf_map_delete_elem(&gotls_write_context, &id);
    return 0;
}


// static __always_inline int gotls_read_ret(struct pt_regs *ctx, bool is_register_abi) {
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     u64 pid = pid_tgid >> 32;
//     u64 goroutine_id = GOROUTINE(ctx);
//     u64 id = (pid << 32) | goroutine_id;

//     bpf_printk("gotls_read_ret_register called");

//     struct go_tls_event *event = bpf_map_lookup_elem(&gotls_read_context, &id);
//     if (!event) return -1;
//     s32 ret_len;
//     const char *str = (void *)go_get_argument(ctx, false, 2);
//     void *ret_len_ptr = (void *)go_get_argument(ctx, is_register_abi, is_register_abi ? 1 : 5);
//     bpf_probe_read_kernel(&ret_len, sizeof(ret_len), &ret_len_ptr);
//     if (!str || ret_len <= 0) return 0;
//     event->data_len = ret_len;
//     if (bpf_probe_read_user(&event->data, sizeof(event->data), str) < 0) return 0;
//     int ret = process_event_with_address_info(ctx, event, id, pid, &gotls_read_pidfd_addrinfo_map);
//     if (ret < 0) return ret;

//     // bpf_ringbuf_output(&events, event, sizeof(*event), 0);
//         bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

//     bpf_printk("gotls_event captured: goid %llu, fd %u, data_len %d", event->goid, event->fd, event->data_len);

//     bpf_map_delete_elem(&gotls_read_context, &id);
//     return 0;
// }

// static __always_inline int gotls_read_ret(struct pt_regs *ctx, bool is_register_abi) {
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     u64 pid = pid_tgid >> 32;
//     u64 goroutine_id = GOROUTINE(ctx);
//     u64 id = (pid << 32) | goroutine_id;

//     bpf_printk("gotls_read_ret_register called");

//     struct go_tls_event *event = bpf_map_lookup_elem(&gotls_read_context, &id);
//     if (!event) return -1;
//     s32 record_len;

//     u64* conn_ptr = bpf_map_lookup_elem(&gotls_conn_address_map, &event->goid);
//     if (conn_ptr == NULL) {
//         bpf_printk("gotls_read_ret_register: no address info for goid %llu", event->goid);
//         return -1;
//     }
//     u64 conn = *conn_ptr;
//     void *record_len_ptr = (void *)(uintptr_t)(conn + 0x2e0);
//     void *data_ptr_addr  = (void *)(uintptr_t)(conn + 0x2d8);

    
//     if(bpf_probe_read_user(&record_len, sizeof(record_len), record_len_ptr) < 0) {
//         bpf_printk("gotls_read_ret_register: failed to read record length for goid %llu", event->goid);
//         return -1;
//     }
//     if (record_len <= 0) {
//         bpf_printk("gotls_read_ret_register: invalid record length %d for goid %llu", record_len, event->goid);
//         return -1;
//     }

//     int safe_len = record_len;
//     if (safe_len > sizeof(event->data)) {
//         bpf_printk("record_len too large: %d, truncating to: %d", record_len, sizeof(event->data));
//         safe_len = sizeof(event->data);
//     }
//     event->data_len = safe_len;

//     void* data_ptr;
//     if (bpf_probe_read_user(&data_ptr, sizeof(data_ptr), data_ptr_addr) < 0) {
//         bpf_printk("gotls_read_ret_register: failed to read data pointer for goid %llu", event->goid);
//         return -1;
//     }
//     if(data_ptr == NULL) {
//         bpf_printk("gotls_read_ret_register: data pointer is NULL for goid %llu", event->goid);
//         return -1;
//     }
//     event->data_len = safe_len;;
    
//     if (bpf_probe_read_user(&event->data, safe_len, data_ptr) < 0) return 0;

//     int ret = process_event_with_address_info(ctx, event, id, pid, &gotls_read_pidfd_addrinfo_map);
//     if (ret < 0) return ret;

//     // bpf_ringbuf_output(&events, event, sizeof(*event), 0);
//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

//     bpf_printk("gotls_event captured: goid %llu, fd %u, data_len %d", event->goid, event->fd, event->data_len);

//     bpf_map_delete_elem(&gotls_read_context, &id);
//     return 0;
// }

static __always_inline int gotls_read_ret(struct pt_regs *ctx, bool is_register_abi) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    u64 goid = GOROUTINE(ctx);
    u64 id = (pid << 32) | goid;

    bpf_printk("gotls_read_ret: pid=%llu, goid=%llu", pid, goid);

    struct go_tls_event *event = bpf_map_lookup_elem(&gotls_read_context, &id);
    if (!event) {
        bpf_printk("gotls_read_ret: no event context for id=%llu", id);
        return -1;
    }

    u64 *conn_ptr = bpf_map_lookup_elem(&gotls_conn_address_map, &goid);
    if (!conn_ptr) {
        bpf_printk("gotls_read_ret: no conn_ptr for goid=%llu", goid);
        return -1;
    }

    u64 conn = *conn_ptr;
    bpf_printk("gotls_read_ret: conn address for goid=%llu is 0x%llx", goid, conn);

    // Read record_len
    s32 record_len = 0;
    u64 record_len_addr = conn + 0x2e0;
    int r1 = bpf_probe_read_user(&record_len, sizeof(record_len), (void *)(unsigned long)record_len_addr);
    if (r1 < 0 || record_len <= 0) {
        bpf_printk("gotls_read_ret: failed to read record_len or invalid: r1=%d, len=%d", r1, record_len);
        return -1;
    }

    // Clamp and mask record_len to unsigned safe_len
    u32 safe_len = (__u32)record_len & 0xFFFF;
    if (safe_len > sizeof(event->data)) {
        bpf_printk("gotls_read_ret: record_len too large: %u > %u, clamping", safe_len, sizeof(event->data));
        safe_len = sizeof(event->data);
    }

    // Read data_ptr (as u64, not void *)
    u64 data_ptr_val = 0;
    u64 data_ptr_addr = conn + 0x2d8;
    int r2 = bpf_probe_read_user(&data_ptr_val, sizeof(data_ptr_val), (void *)(unsigned long)data_ptr_addr);
    if (r2 < 0 || data_ptr_val == 0) {
        bpf_printk("gotls_read_ret: failed to read data_ptr or NULL: r2=%d, ptr=0x%llx", r2, data_ptr_val);
        return -1;
    }

    // Use safe_len in probe read user — make sure it's unsigned and <= max
    if (safe_len > sizeof(event->data)) {
        bpf_printk("gotls_read_ret: safe_len (%u) exceeds buffer size, aborting", safe_len);
        return -1;
    }
    int r3 = bpf_probe_read_user(&event->data, safe_len, (void *)(unsigned long)data_ptr_val);
    if (r3 < 0) {
        bpf_printk("gotls_read_ret: failed to read data: r3=%d, len=%u", r3, safe_len);
        return 0;
    }


    event->data_len = safe_len;
    event->goid = goid;

    int ret = process_event_with_address_info(ctx, event, id, pid, &gotls_read_pidfd_addrinfo_map);
    if (ret < 0) {
        bpf_printk("gotls_read_ret: process_event_with_address_info failed for goid=%llu", goid);
        return ret;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&gotls_read_context, &id);

    bpf_printk("gotls_read_ret: success goid=%llu, len=%u", goid, event->data_len);
    return 0;
}





// --- UPROBE SECTIONS ---
SEC("uprobe/gotls_write_register")
int gotls_write_register(struct pt_regs *ctx) {
    return gotls_write(ctx, true, next_order_index());
}


SEC("uprobe/gotls_write_stack")
int gotls_write_stack(struct pt_regs *ctx) {
    return gotls_write(ctx, false, next_order_index());
}


SEC("uprobe/gotls_write_ret_register")
int gotls_write_ret_register(struct pt_regs *ctx) {
    return gotls_write_ret(ctx, true);
}


SEC("uprobe/gotls_write_ret_stack")
int gotls_write_ret_stack(struct pt_regs *ctx) {
    return gotls_write_ret(ctx, false);
}


SEC("uprobe/gotls_read_register")
int gotls_read_register(struct pt_regs *ctx) {
    return gotls_read(ctx, true, next_order_index());
}


SEC("uprobe/gotls_read_stack")
int gotls_read_stack(struct pt_regs *ctx) {
    return gotls_read(ctx, false, next_order_index());
}


SEC("uprobe/gotls_read_ret_register")
int gotls_read_ret_register(struct pt_regs *ctx) {
    return gotls_read_ret(ctx, true);
}


SEC("uprobe/gotls_read_ret_stack")
int gotls_read_ret_stack(struct pt_regs *ctx) {
    return gotls_read_ret(ctx, false);
} 