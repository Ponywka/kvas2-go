package netfilterHelper

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"strconv"
)

type PortRemap struct {
	IPTables  *iptables.IPTables
	ChainName string
	From      uint16
	To        uint16

	Enabled bool
}

func (r *PortRemap) PutIPTable(table string) error {
	if table == "all" || table == "nat" {
		err := r.IPTables.ClearChain("nat", r.ChainName)
		if err != nil {
			return fmt.Errorf("failed to clear chain: %w", err)
		}

		err = r.IPTables.AppendUnique("nat", r.ChainName, "-p", "udp", "--dport", strconv.Itoa(int(r.From)), "-j", "REDIRECT", "--to-port", strconv.Itoa(int(r.To)))
		if err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		err = r.IPTables.InsertUnique("nat", "PREROUTING", 1, "-j", r.ChainName)
		if err != nil {
			return fmt.Errorf("failed to linking chain: %w", err)
		}
	}

	return nil
}

func (r *PortRemap) ForceEnable() error {
	err := r.PutIPTable("all")
	if err != nil {
		return err
	}

	r.Enabled = true
	return nil
}

func (r *PortRemap) Disable() []error {
	var errs []error

	err := r.IPTables.DeleteIfExists("nat", "PREROUTING", "-j", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = r.IPTables.ClearAndDeleteChain("nat", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	r.Enabled = false
	return errs
}

func (r *PortRemap) Enable() error {
	if r.Enabled {
		return nil
	}

	err := r.ForceEnable()
	if err != nil {
		r.Disable()
		return err
	}

	return nil
}

func (nh *NetfilterHelper) PortRemap(name string, from, to uint16) *PortRemap {
	return &PortRemap{
		IPTables:  nh.IPTables,
		ChainName: name,
		From:      from,
		To:        to,
	}
}
