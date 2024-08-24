package dnsProxy

import (
	"encoding/hex"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"log"
	"net"
	"time"
)

const (
	DNSMaxUDPPackageSize = 4096
	DNSMaxTCPPackageSize = 65536
)

type DNSProxy struct {
	listenAddr   string
	upstreamAddr string

	udpConn *net.UDPConn

	MsgHandler func(*Message)
}

func (p DNSProxy) Close() error {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("iptables init fail: %v", err)
	}

	err = ipt.DeleteIfExists("nat", "PREROUTING", "-j", "KVAS2_DNSOVERRIDE")
	if err != nil {
		log.Fatalf("failed to attaching chain: %v", err)
	}

	err = ipt.ClearAndDeleteChain("nat", "KVAS2_DNSOVERRIDE")
	if err != nil {
		log.Fatalf("failed to delete chain: %v", err)
	}

	return nil
	//return p.udpConn.Close()
}

func (p DNSProxy) sendToUpstream(isTCP bool, request []byte) ([]byte, error) {
	protocol := "udp"
	if isTCP {
		protocol = "tcp"
	}

	conn, err := net.Dial(protocol, p.upstreamAddr)
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

	var response []byte
	if !isTCP {
		response = make([]byte, DNSMaxUDPPackageSize)
	} else {
		response = make([]byte, DNSMaxTCPPackageSize)
	}

	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from upstream DNS: %w", err)
	}

	return response[:n], nil
}

func (p DNSProxy) handleDNSRequest(clientAddr *net.UDPAddr, buffer []byte) {
	upstreamResponse, err := p.sendToUpstream(false, buffer)
	if err != nil {
		log.Printf("Failed to get response from upstream DNS: %v", err)
		return
	}

	log.Printf("Response: %s", hex.EncodeToString(upstreamResponse))

	msg, err := ParseResponse(upstreamResponse)
	if err == nil {
		if p.MsgHandler != nil {
			p.MsgHandler(msg)
		}
	} else {
		log.Printf("error while parsing response: %v", err)
	}

	_, err = p.udpConn.WriteToUDP(upstreamResponse, clientAddr)
	if err != nil {
		log.Printf("Failed to send DNS response: %v", err)
	}
}

func (p DNSProxy) Listen() error {
	var err error

	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("iptables init fail: %v", err)
	}

	err = ipt.ClearChain("nat", "KVAS2_DNSOVERRIDE")
	if err != nil {
		log.Fatalf("failed to clean chain: %v", err)
	}

	err = ipt.AppendUnique("nat", "KVAS2_DNSOVERRIDE", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "7548")
	if err != nil {
		log.Fatalf("failed to create rule: %v", err)
	}

	err = ipt.InsertUnique("nat", "PREROUTING", 1, "-j", "KVAS2_DNSOVERRIDE")
	if err != nil {
		log.Fatalf("failed to attaching chain: %v", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	p.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}

	for {
		buffer := make([]byte, DNSMaxUDPPackageSize)
		n, clientAddr, err := p.udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}

		go p.handleDNSRequest(clientAddr, buffer[:n])
	}
}

func New(listenAddr string, listenPort uint16, upstreamAddr string, upstreamPort uint16) *DNSProxy {
	return &DNSProxy{
		listenAddr:   fmt.Sprintf("%s:%d", listenAddr, listenPort),
		upstreamAddr: fmt.Sprintf("%s:%d", upstreamAddr, upstreamPort),
	}
}
