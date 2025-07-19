#include "include/common.h"
#include "include/maps.h"

#define TLS_DIRECTION_SEND 1
#define TLS_DIRECTION_READ 2

static __always_inline int tcp_kprobes_get_address_pair_from_ctx(struct pt_regs* ctx, __u64 id, struct address_info* address_info_ptr) {
    long err;
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    __u16 family_short;

    err = bpf_probe_read_kernel(&family_short, sizeof(family_short), (void*)&sk->__sk_common.skc_family);
    if (err != 0) {
        //log_error(ctx, LOG_ERROR_READING_SOCKET_FAMILY, id, err, 0l);
        return -1;
    }

    address_info_ptr->family = (__be32)family_short;

    if (address_info_ptr->family  == AF_INET) {
        // Extract IPv4 addresses
        err = bpf_probe_read_kernel(&address_info_ptr->saddr4, sizeof(address_info_ptr->saddr4), (void*)&sk->__sk_common.skc_rcv_saddr);
        if (err != 0) {
            //log_error(ctx, LOG_ERROR_READING_SOCKET_SADDR, id, err, 0l);
            return -1;
        }
        err = bpf_probe_read_kernel(&address_info_ptr->daddr4, sizeof(address_info_ptr->daddr4), (void*)&sk->__sk_common.skc_daddr);
        if (err != 0) {
            //log_error(ctx, LOG_ERROR_READING_SOCKET_DADDR, id, err, 0l);
            return -1;
        }
    } else if (address_info_ptr->family  == AF_INET6) {
        // Extract IPv6 addresses
        err = bpf_probe_read_kernel(address_info_ptr->saddr6, sizeof(address_info_ptr->saddr6), (void*)&sk->__sk_common.skc_v6_rcv_saddr);
        if (err != 0) {
            //log_error(ctx, LOG_ERROR_READING_SOCKET_SADDR, id, err, 0l);
            return -1;
        }
        err = bpf_probe_read_kernel(address_info_ptr->daddr6, sizeof(address_info_ptr->daddr6), (void*)&sk->__sk_common.skc_v6_daddr);
        if (err != 0) {
            //log_error(ctx, LOG_ERROR_READING_SOCKET_DADDR, id, err, 0l);
            return -1;
        }
    } else {
		//log_error(ctx, LOG_ERROR_UNKNOWN_FAMILY, id, address_info_ptr->family , 0l);
        return -1; 
    }

    err = bpf_probe_read_kernel(&address_info_ptr->dport, sizeof(address_info_ptr->dport), (void*)&sk->__sk_common.skc_dport);
    if (err != 0) {
        //log_error(ctx, LOG_ERROR_READING_SOCKET_DPORT, id, err, 0l);
        return -1;
    }
    err = bpf_probe_read_kernel(&address_info_ptr->sport, sizeof(address_info_ptr->sport), (void*)&sk->__sk_common.skc_num);
    if (err != 0) {
        //log_error(ctx, LOG_ERROR_READING_SOCKET_SPORT, id, err, 0l);
        return -1;
    }
    address_info_ptr->sport = bpf_htons(address_info_ptr->sport);

	return 0;
}

static __always_inline int tcp_kprobe(struct pt_regs * ctx, void* tcp_pid_fd_map, void* tcp_pidfd_addrinfo_map, u8 direction){
    long err;
	u64 id = bpf_get_current_pid_tgid();

    u32 zero = 0;
    struct go_tls_event *event = bpf_map_lookup_elem(&gte_context_gen, &zero);

    if (!event) {
        return 0;
    }

    if((id >> 32) != (event->pid)){
        // bpf_printk("tcp_kprobe not same process");
        return -1;
    }
    // else{
    //     bpf_printk("tcp_kprobe id >> 32 is %llu and event->pid is %llu", id, event->pid);
    // }

    struct address_info address_info = {};
    err = tcp_kprobes_get_address_pair_from_ctx(ctx, id, &address_info);
	if (err != 0) {
        bpf_printk("tcp_kprobe Error: %d", err);
		return err;
	}

    // if(address_info.saddr6[14] == 100 && address_info.saddr6[15] == 1){
    if(address_info.family == AF_INET6){
        // bpf_printk("tcp_kprobe source addr (v6) ended in %d.%d.%d.%d", address_info.saddr6[12], address_info.saddr6[13], address_info.saddr6[14], address_info.saddr6[15]);
        if(direction == TLS_DIRECTION_SEND){
            bpf_printk("tcp_kprobe source addr (v6) ended in %pI4, port %d, dst %pI4", address_info.saddr6+12, bpf_ntohs(address_info.sport), address_info.daddr6+12);
        }else if(direction == TLS_DIRECTION_READ){
            int count = PT_REGS_PARM2(ctx);
            bpf_printk("tcp_kprobe source addr (v6) ended in %pI4, port %d, %d bytes read.", address_info.daddr6+12, bpf_ntohs(address_info.dport), count);
        }
    }else{
        // bpf_printk("tcp_kprobe source addr (v4) ended in %d.%d.%d.%d", (address_info.saddr4 >> 24) & 0xFF, (address_info.saddr4 >> 16) & 0xFF, (address_info.saddr4 >> 8) & 0xFF, address_info.saddr4 & 0xFF);
        if(direction == TLS_DIRECTION_SEND){
            bpf_printk("tcp_kprobe source addr (v6) ended in %pI4, port %d, dst %pI4", address_info.saddr4, bpf_ntohs(address_info.sport), address_info.daddr4);
        }else if(direction == TLS_DIRECTION_READ){
            int count = PT_REGS_PARM2(ctx);
            bpf_printk("tcp_kprobe source addr (v4) ended in %pI4 , port %d, %d bytes read.", address_info.daddr4, bpf_ntohs(address_info.dport), count);
        }
    }
        
    // }

    u32* fd_ptr;
    fd_ptr = bpf_map_lookup_elem(tcp_pid_fd_map, &id);
    if (fd_ptr == NULL) {
        bpf_printk("tcp_kprobe connection wasn't found in pid_fd_map");
        // Connection was not created by a Go program or by openssl lib
        return -1;
    }
    
    u32 fd = *fd_ptr;
    u64 pid = id >> 32;
	u64 key = (u64)pid << 32 | fd;

    bpf_printk("tcp_kprobe writing address info for event with id %llu, fd %llu", key, fd);

	err = bpf_map_update_elem(tcp_pidfd_addrinfo_map, &key, &address_info, BPF_ANY);
	if (err != 0) {
		//log_error(ctx, LOG_ERROR_PUTTING_GO_USER_KERNEL_CONTEXT, id, fd, err);
		return err;
	}

    return 0;
};

SEC("kprobe/tcp_sendmsg")
void BPF_KPROBE(tcp_sendmsg) {
	__u64 id = bpf_get_current_pid_tgid();
	tcp_kprobe(ctx, &gotls_write_pid_fd_map, &gotls_write_pidfd_addrinfo_map, TLS_DIRECTION_SEND);
}

SEC("kprobe/tcp_cleanup_rbuf")
void BPF_KPROBE(tcp_cleanup_rbuf) {
	__u64 id = bpf_get_current_pid_tgid();
	tcp_kprobe(ctx, &gotls_read_pid_fd_map, &gotls_read_pidfd_addrinfo_map, TLS_DIRECTION_READ);
}