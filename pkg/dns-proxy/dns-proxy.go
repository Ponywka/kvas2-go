package dnsProxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog/log"
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
				log.Error().Err(err).Msg("failed to close UDP connection")
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			buffer := make([]byte, DNSMaxUDPPackageSize)
			n, clientAddr, err := p.udpConn.ReadFromUDP(buffer)
			if err != nil {
				log.Error().Err(err).Msg("failed to read UDP packet")
				continue
			}

			go p.handleDNSRequest(clientAddr, buffer[:n])
		}
	}
}

func (p DNSProxy) handleDNSRequest(clientAddr *net.UDPAddr, buffer []byte) {
	conn, err := net.Dial("udp", p.targetDNSServerAddress)
	if err != nil {
		log.Error().Err(err).Msg("failed to dial target DNS")
		return
	}
	defer conn.Close()

	_, err = conn.Write(buffer)
	if err != nil {
		log.Error().Err(err).Msg("failed to send request to target DNS")
		return
	}

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Error().Err(err).Msg("failed to set read deadline")
		return
	}

	response := make([]byte, DNSMaxUDPPackageSize)
	n, err := conn.Read(response)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// Just skip it
			return
		}

		log.Error().Err(err).Msg("failed to read response from target DNS")
		return
	}

	msg, err := ParseResponse(response[:n])
	if err == nil {
		if p.MsgHandler != nil {
			p.MsgHandler(msg)
		}
	} else {
		log.Warn().Err(err).Msg("error while parsing DNS message")
	}

	_, err = p.udpConn.WriteToUDP(response[:n], clientAddr)
	if err != nil {
		log.Error().Err(err).Msg("failed to send DNS message")
		return
	}
}

func New(listenPort uint16, targetDNSServerAddress string) *DNSProxy {
	return &DNSProxy{
		listenPort:             listenPort,
		targetDNSServerAddress: targetDNSServerAddress,
	}
}
