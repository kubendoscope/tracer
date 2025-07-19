package main

import (
	"encoding/binary"
	"net"
)

func int8ArrayToString(arr []int8) string {
	// Convert int8 slice to byte slice and then to string
	b := make([]byte, len(arr))
	for i, v := range arr {
		b[i] = byte(v)
	}
	return string(b)
}

func uint32ToIP(ipUint32 uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint32)
	return ip
}

func ntohs(val uint16) uint16 {
	return binary.LittleEndian.Uint16([]byte{byte(val >> 8), byte(val)})
}