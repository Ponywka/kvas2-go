package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

var (
	ListenPort             = 7548
	UsableDNSServerAddress = "127.0.0.1"
	UsableDNSServerPort    = 53
	DNSMaxPackageSize      = 4096
)

func parseName(response []byte, pos int) (string, int) {
	var nameParts []string
	var jumped bool
	var outPos int
	responseLen := len(response)

	for {
		length := int(response[pos])
		pos++
		if length == 0 {
			break
		}

		if length&0xC0 == 0xC0 {
			if !jumped {
				outPos = pos + 1
			}
			pos = int(binary.BigEndian.Uint16(response[pos-1:pos+1]) & 0x3FFF)
			jumped = true
			continue
		}

		if pos+length > responseLen {
			break
		}

		nameParts = append(nameParts, string(response[pos:pos+length]))
		pos += length
	}

	if !jumped {
		outPos = pos
	}
	return strings.Join(nameParts, "."), outPos
}

func sendToUpstream(upstreamAddr string, request []byte) ([]byte, error) {
	conn, err := net.Dial("udp", upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream DNS: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to upstream DNS: %w", err)
	}

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set timeout: %w", err)
	}

	response := make([]byte, DNSMaxPackageSize)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from upstream DNS: %w", err)
	}

	return response[:n], nil
}

func main() {
	addr := fmt.Sprintf(":%d", ListenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer conn.Close()

	fmt.Printf("DNS server is running on %s...\n", addr)

	for {
		buffer := make([]byte, DNSMaxPackageSize)
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}

		go handleDNSRequest(conn, clientAddr, buffer[:n])
	}
}

func process(response []byte) {
	responseLen := len(response)
	if responseLen <= 12 {
		return
	}

	qCount := int(binary.LittleEndian.Uint16(response[5:7]))
	aCount := int(binary.LittleEndian.Uint16(response[7:9]))

	pos := 12

	for i := 0; i < qCount; i++ {
		var name string
		name, pos = parseName(response, pos)
		fmt.Printf("Requested name: %s\n", name)
		pos += 4
	}

	for i := 0; i < aCount; i++ {
		name, newPos := parseName(response, pos)
		pos = newPos

		if pos+10 > responseLen {
			break
		}

		qtype := binary.BigEndian.Uint16(response[pos : pos+2])
		pos += 2

		qclass := binary.BigEndian.Uint16(response[pos : pos+2])
		pos += 2

		ttl := binary.BigEndian.Uint32(response[pos : pos+4])
		pos += 4

		rdlength := binary.BigEndian.Uint16(response[pos : pos+2])
		pos += 2

		if pos+int(rdlength) > responseLen {
			break
		}

		if qtype == 1 && qclass == 1 && rdlength == 4 {
			ip := net.IPv4(response[pos], response[pos+1], response[pos+2], response[pos+3])
			fmt.Printf("Parsed A record: %s -> %s, TTL: %d\n", name, ip, ttl)
		}

		pos += int(rdlength)
	}
}

func handleDNSRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, buffer []byte) {
	upstreamAddr := fmt.Sprintf("%s:%d", UsableDNSServerAddress, UsableDNSServerPort)

	upstreamResponse, err := sendToUpstream(upstreamAddr, buffer)
	if err != nil {
		log.Printf("Failed to get response from upstream DNS: %v", err)
		return
	}
	log.Printf("Response: %s", hex.EncodeToString(upstreamResponse))

	process(upstreamResponse)

	_, err = conn.WriteToUDP(upstreamResponse, clientAddr)
	if err != nil {
		log.Printf("Failed to send DNS response: %v", err)
	}
}
