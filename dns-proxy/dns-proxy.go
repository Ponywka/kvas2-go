package dnsProxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	DNSMaxUDPPackageSize = 4096
)

type DNSProxy struct {
	udpConn    *net.UDPConn
	listenPort uint16

	targetDNSServerAddress string

	MsgHandler func(*Message)
}

func (p DNSProxy) Listen(ctx context.Context) error {
	var err error

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", p.listenPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	p.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP address: %v", err)
	}

	defer func() {
		if p.udpConn != nil {
			err := p.udpConn.Close()
			if err != nil {
				log.Printf("failed to close UDP connection: %v", err)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down DNS proxy...")
			return nil
		default:
			buffer := make([]byte, DNSMaxUDPPackageSize)
			n, clientAddr, err := p.udpConn.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("failed to read UDP packet: %v", err)
				continue
			}

			go p.handleDNSRequest(clientAddr, buffer[:n])
		}
	}
}

func (p DNSProxy) handleDNSRequest(clientAddr *net.UDPAddr, buffer []byte) {
	conn, err := net.Dial("udp", p.targetDNSServerAddress)
	if err != nil {
		log.Printf("failed to dial target DNS: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(buffer)
	if err != nil {
		// TODO: Error log level
		log.Printf("failed to send request to target DNS: %v", err)
		return
	}

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		// TODO: Error log level
		log.Printf("failed to set read deadline: %v", err)
		return
	}

	response := make([]byte, DNSMaxUDPPackageSize)
	n, err := conn.Read(response)
	if err != nil {
		// TODO: Error log level
		log.Printf("failed to read response from target DNS: %v", err)
		return
	}

	// TODO: Debug log level
	log.Printf("Response: %s", hex.EncodeToString(response[:n]))

	msg, err := ParseResponse(response[:n])
	if err == nil {
		if p.MsgHandler != nil {
			p.MsgHandler(msg)
		}
	} else {
		// TODO: Warn log level
		log.Printf("error while parsing DNS message: %v", err)
	}

	_, err = p.udpConn.WriteToUDP(response[:n], clientAddr)
	if err != nil {
		// TODO: Error log level
		log.Printf("failed to send DNS message: %v", err)
		return
	}
}

func New(listenPort uint16, targetDNSServerAddress string) *DNSProxy {
	return &DNSProxy{
		listenPort:             listenPort,
		targetDNSServerAddress: targetDNSServerAddress,
	}
}
