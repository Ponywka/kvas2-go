package netfilterHelper

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

type PortRemap struct {
	IPTables  *iptables.IPTables
	ChainName string
	Addresses []netlink.Addr
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

		for _, addr := range r.Addresses {
			var addrIP net.IP
			iptablesProtocol := r.IPTables.Proto()
			if (iptablesProtocol == iptables.ProtocolIPv4 && len(addr.IP) == net.IPv4len) || (iptablesProtocol == iptables.ProtocolIPv6 && len(addr.IP) == net.IPv6len) {
				addrIP = addr.IP
			}
			if addrIP == nil {
				continue
			}

			err = r.IPTables.AppendUnique("nat", r.ChainName, "-p", "udp", "-d", addrIP.String(), "--dport", strconv.Itoa(int(r.From)), "-j", "DNAT", "--to-destination", fmt.Sprintf(":%d", r.To))
			if err != nil {
				return fmt.Errorf("failed to create rule: %w", err)
			}
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

func (nh *NetfilterHelper) PortRemap(name string, from, to uint16, addr []netlink.Addr) *PortRemap {
	return &PortRemap{
		IPTables:  nh.IPTables,
		ChainName: name,
		Addresses: addr,
		From:      from,
		To:        to,
	}
}
