package main

import (
	// "fmt"
	"log"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func AddTCPLinks(objs uprobeObjects) ([]link.Link){
	links := []link.Link{}

	tcpSendmsg, err := link.Kprobe("tcp_sendmsg", objs.TcpSendmsg, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	links = append(links, tcpSendmsg)

	tcpCleanupRbuf, err := link.Kprobe("tcp_cleanup_rbuf", objs.TcpCleanupRbuf, nil)

	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	links = append(links, tcpCleanupRbuf)

	return links
}

func AddSyscallLinks(objs uprobeObjects)([]link.Link){
	links := []link.Link{}
	// Links for fd probes
	sys_enter_read, err := link.Tracepoint("syscalls", "sys_enter_read", objs.SysEnterRead, nil); 
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	links = append(links, sys_enter_read)

	sys_enter_write, err := link.Tracepoint("syscalls", "sys_enter_write", objs.SysEnterWrite, nil); 
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	links = append(links, sys_enter_write)

	sys_enter_recvfrom, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.SysEnterRecvfrom, nil); 
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	links = append(links, sys_enter_recvfrom)

	sys_enter_sendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.SysEnterSendto, nil); 
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	links = append(links, sys_enter_sendto)

	sys_exit_read, err := link.Tracepoint("syscalls", "sys_exit_read", objs.SysExitRead, nil); 
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	links = append(links, sys_exit_read)

	sys_exit_write, err := link.Tracepoint("syscalls", "sys_exit_write", objs.SysExitWrite, nil); 
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	links = append(links, sys_exit_write)

	return links
}

func getProgramByName(objs interface{}, name string) *ebpf.Program {
	val := reflect.ValueOf(objs)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	field := val.FieldByName(name)
	if !field.IsValid() || field.IsZero() {
		log.Fatalf("Invalid or nil field: %s", name)
	}
	return field.Interface().(*ebpf.Program)
}


func AddGoTlsLinks(ex *link.Executable, objs uprobeObjects, symbols []SymbolProbe, binPath string)([]link.Link){
	links := []link.Link{}
	for _, symbol := range symbols {
		symbolData, err := GetOffsets(binPath, symbol.Name);
		if err != nil {
			log.Fatalf("Failed to get read symbol offsets: %v", err)
		}
		symbolUprobe, err := ex.Uprobe(symbol.Name, getProgramByName(objs, symbol.UprobeProgram), &link.UprobeOptions{Address: symbolData.Offset})
		if err != nil {
			log.Fatalf("creating read uprobe: %s", err)
		}
		links = append(links, symbolUprobe)

		if len(symbolData.Exits) > 0{
			for _, exit := range symbolData.Exits {
				l, err := ex.Uprobe(symbol.Name, getProgramByName(objs, symbol.UprobeExProgram), &link.UprobeOptions{Address: exit})
				if err != nil {
					log.Fatalf("failed to attach write return uprobe: %v", err)
				}
				links = append(links, l)
			}
		}
	}

	return links
	// writeUprobe, err := ex.Uprobe(writeSymbol, objs.GotlsWriteRegister, &link.UprobeOptions{Address: writeSymOffset})
	// if err != nil {
	// 	log.Fatalf("creating write uprobe: %s", err)
	// }
	// defer writeUprobe.Close()

	// for _, exit := range writeSymExits {
	// 	l, err := ex.Uprobe(writeSymbol, objs.GotlsWriteRetRegister, &link.UprobeOptions{Address: exit})
	// 	if err != nil {
	// 		log.Fatalf("failed to attach write return uprobe: %v", err)
	// 	}
	// 	links = append(links, l)
	// }

	// // Attach read-related uprobes
	// readSymVA, readSymOffset, readSymExits, err := GetOffsets(binPath, readSymbol)
	// if err != nil {
	// 	log.Fatalf("Failed to get read symbol offsets: %v", err)
	// }
	// fmt.Printf("Read Symbol Address: %d, Offset: %d\n", readSymVA, readSymOffset)
	// readUprobe, err := ex.Uprobe(readSymbol, objs.GotlsReadRegister, &link.UprobeOptions{Address: readSymOffset})
	// if err != nil {
	// 	log.Fatalf("creating read uprobe: %s", err)
	// }
	// defer readUprobe.Close()

	// for _, exit := range readSymExits {
	// 	l, err := ex.Uprobe(readSymbol, objs.GotlsReadRetRegister, &link.UprobeOptions{Address: exit})
	// 	if err != nil {
	// 		log.Fatalf("failed to attach read return uprobe: %v", err)
	// 	}
	// 	links = append(links, l)
	// }

	// return links
}