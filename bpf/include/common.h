#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "go_argument.h"

#define AF_UNSPEC 0	/* Unspecified */
#define AF_INET	2	/* IPv4 Protocol */
#define AF_INET6 10	/* IPv6 Protocol */

#endif