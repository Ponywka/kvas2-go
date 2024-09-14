package netfilterHelper

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
)

type NetfilterHelper struct {
	IPTables *iptables.IPTables
}

func New(isIPv6 bool) (*NetfilterHelper, error) {
	var proto iptables.Protocol
	if !isIPv6 {
		proto = iptables.ProtocolIPv4
	} else {
		proto = iptables.ProtocolIPv6
	}

	ipt, err := iptables.New(iptables.IPFamily(proto))
	if err != nil {
		return nil, fmt.Errorf("iptables init fail: %w", err)
	}

	return &NetfilterHelper{
		IPTables: ipt,
	}, nil
}
