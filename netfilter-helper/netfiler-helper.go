package netfilterHelper

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
)

type NetfilterHelper struct {
	IPTables *iptables.IPTables
}

func New() (*NetfilterHelper, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("iptables init fail: %w", err)
	}

	return &NetfilterHelper{
		IPTables: ipt,
	}, nil
}
