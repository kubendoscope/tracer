#include "include/common.h"
#include "include/maps.h"

struct sys_enter_read_write_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 fd;
	__u64* buf;
	__u64 count;
};

struct sys_exit_read_write_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 ret;
};

struct sys_enter_recvfrom_sendto_ctx {
	__u64 __unused_syscall_header;
	__u32 __unused_syscall_nr;

	__u64 fd;      // at offset 16, size 4 (signed)
	void* buf;     // at offset 24, size 8 (unsigned)
	__u64 count;   // at offset 32, size 8 (unsigned)
	__u32 flags;   // at offset 40, size 4 (signed)
	void* addr;    // at offset 48, size 8 (unsigned)
	void* addrlen; // at offset 56, size 8 (unsigned)
};

static __always_inline int fd_update_read_write(struct sys_enter_read_write_ctx * ctx, u64 fd, void* map_pid_fd){
	u64 id = bpf_get_current_pid_tgid();
    
    long err = bpf_map_update_elem(map_pid_fd, &id, &fd, BPF_ANY);

	if (err != 0) {
		//log_error(ctx, LOG_ERROR_PUTTING_FILE_DESCRIPTOR, id, err, origin_code);
		return err;
	}

    return 0;
}

static __always_inline int fd_update_recv_send(struct sys_enter_recvfrom_sendto_ctx * ctx, u64 fd, void* map_pid_fd){
	u64 id = bpf_get_current_pid_tgid();
    
    long err = bpf_map_update_elem(map_pid_fd, &id, &fd, BPF_ANY);

	if (err != 0) {
		//log_error(ctx, LOG_ERROR_PUTTING_FILE_DESCRIPTOR, id, err, origin_code);
		return err;
	}

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
void sys_enter_read(struct sys_enter_read_write_ctx* ctx) {
	fd_update_read_write(ctx, ctx->fd, &gotls_read_pid_fd_map);
}

SEC("tracepoint/syscalls/sys_enter_write")
void sys_enter_write(struct sys_enter_read_write_ctx* ctx) {
	fd_update_read_write(ctx, ctx->fd, &gotls_write_pid_fd_map);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
void sys_enter_recvfrom(struct sys_enter_recvfrom_sendto_ctx* ctx) {
	fd_update_recv_send(ctx, ctx->fd, &gotls_read_pid_fd_map);
}


SEC("tracepoint/syscalls/sys_enter_sendto")
void sys_enter_sendto(struct sys_enter_recvfrom_sendto_ctx* ctx) {
	fd_update_recv_send(ctx, ctx->fd, &gotls_write_pid_fd_map);
}
//TODO: sys_exit_recvfrom and sys_exit_sendto


SEC("tracepoint/syscalls/sys_exit_read")
void sys_exit_read(struct sys_exit_read_write_ctx* ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	// Delete from go map. The value is not used after exiting this syscall.
	// Keep value in openssl map.
	bpf_map_delete_elem(&gotls_read_pid_fd_map, &id);
}

SEC("tracepoint/syscalls/sys_exit_write")
void sys_exit_write(struct sys_exit_read_write_ctx* ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	// Delete from go map. The value is not used after exiting this syscall.
	// Keep value in openssl map.
	bpf_map_delete_elem(&gotls_write_pid_fd_map, &id);
}