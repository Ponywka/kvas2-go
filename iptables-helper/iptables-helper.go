package iptablesHelper

import (
	"fmt"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
)

type DNSOverrider struct {
	ipt       *iptables.IPTables
	chainName string
	destPort  uint16
}

func (o DNSOverrider) Enable() error {
	err := o.ipt.ClearChain("nat", o.chainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = o.ipt.AppendUnique("nat", o.chainName, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", strconv.Itoa(int(o.destPort)))
	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	err = o.ipt.InsertUnique("nat", "PREROUTING", 1, "-j", o.chainName)
	if err != nil {
		return fmt.Errorf("failed to linking chain: %w", err)
	}

	return nil
}

func (o DNSOverrider) Disable() error {
	err := o.ipt.DeleteIfExists("nat", "PREROUTING", "-j", o.chainName)
	if err != nil {
		return fmt.Errorf("failed to unlinking chain: %w", err)
	}

	err = o.ipt.ClearAndDeleteChain("nat", o.chainName)
	if err != nil {
		return fmt.Errorf("failed to delete chain: %w", err)
	}

	return nil
}

func NewDNSOverrider(chainName string, destPort uint16) (*DNSOverrider, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("iptables init fail: %w", err)
	}

	return &DNSOverrider{
		ipt:       ipt,
		chainName: chainName,
		destPort:  destPort,
	}, nil
}
