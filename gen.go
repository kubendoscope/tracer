package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-17 -target amd64 -tags linux uprobe bpf/uprobe.c
