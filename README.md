# tracer

`tracer` is an eBPF-based network payload tracer for Kubernetes control-plane traffic.  
It attaches to `kube-apiserver`, captures Go TLS read/write payloads and socket metadata, and streams events to a gRPC hub while also logging them locally.

## What it does

- Locates the running `kube-apiserver` process automatically (from `/proc` or `/host/proc` when containerized).
- Attaches Go TLS uprobes/uretprobes to:
  - `crypto/tls.(*Conn).writeRecordLocked`
  - `crypto/tls.(*Conn).readRecordOrCCS`
- Attaches kernel probes to correlate process FD activity and socket address data:
  - `kprobe/tcp_sendmsg`
  - `kprobe/tcp_cleanup_rbuf`
  - `tracepoint/syscalls/sys_enter_{read,write,recvfrom,sendto}`
  - `tracepoint/syscalls/sys_exit_{read,write}`
- Emits enriched events containing process IDs, goroutine-derived IDs, direction/type, payload bytes, and source/destination IP:port.
- Streams events via gRPC `TrafficCollector/StreamEvents` to a hub server.

## High-level flow

1. Discover `kube-apiserver` executable path.
2. Load compiled eBPF objects (`bpf2go` generated).
3. Attach Go TLS uprobes and TCP/syscall probes.
4. Read events from a perf buffer.
5. Decode and print events in userspace.
6. Forward events to the hub over gRPC if reachable.

## Requirements

- Linux with eBPF support (BTF/CO-RE capable kernel recommended).
- Go `1.23`.
- `clang-17` (used by `go generate`).
- `libbpf` headers/dev package.
- Capstone `4.0.1` (used for symbol/return-offset discovery in `get_offsets.go`).
- Privileges to load eBPF programs and attach probes (`root` or equivalent capabilities).

The repository includes `install-libcapstone.sh` for Capstone installation.

## Build

```bash
go mod tidy
go generate .
go build -ldflags "-w -s" -o tracer
```

Notes:

- `go generate` runs:
  - `go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-17 -target amd64 -tags linux uprobe bpf/uprobe.c`
- The current generation target is `amd64`.

## Run

```bash
sudo ./tracer -hub_host <hub-host-or-ip> -hub_port 50051
```

Flags:

- `-hub_host` (default: `localhost`)
- `-hub_port` (default: `50051`)

If gRPC connection fails, tracer continues running and logs events locally.

## Event schema and gRPC service

Protobuf is defined in `proto/traffic-mon.proto`.

- Service: `traffic.TrafficCollector`
- RPC: `StreamEvents(stream GoTlsEvent) returns (StreamResponse)`

Each `GoTlsEvent` includes:

- `goid`, `pid`, `tid`, `fd`
- timestamp (`ts_ns`)
- `event_type`
- process command (`comm`)
- node hostname (`node`)
- payload bytes (`data`) and length (`data_len`)
- address info (`family`, IPv4/IPv6 src/dst, ports)

## Running in Kubernetes

When running as a DaemonSet, mount host procfs so process discovery can work:

- `/host/proc` -> host `/proc`

The tracer checks `/host/proc` first and remaps resolved executable paths to `/host/...`.

You will also typically need access to:

- `/sys/fs/bpf` (for pinning links)
- required kernel capabilities for eBPF and kprobe/uprobe attachment

## Troubleshooting

- `kube-apiserver process not found`:
  - run on a control-plane node
  - verify host procfs mount if containerized
- `Failed to load eBPF objects`:
  - ensure `go generate .` succeeded
  - verify kernel/eBPF compatibility and privileges
- gRPC stream setup errors:
  - check `-hub_host` and `-hub_port`
  - tracer still prints local event output when stream is unavailable

## Repository layout

- `main.go`: userspace bootstrap, event loop, gRPC streaming
- `links.go`: attachment logic for uprobes/kprobes/tracepoints
- `get_offsets.go`: symbol and return-offset extraction using GoReSym + Capstone
- `bpf/`: eBPF C sources and map definitions
- `proto/traffic-mon.proto`: gRPC and event schema
