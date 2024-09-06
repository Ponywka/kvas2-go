package netfilterHelper

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"os"
)

type IPSet struct {
	SetName string
}

func (r *IPSet) Add(addr net.IP, timeout *uint32) error {
	err := netlink.IpsetAdd(r.SetName, &netlink.IPSetEntry{
		IP:      addr,
		Timeout: timeout,
		Replace: true,
	})
	if err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}
	return nil
}

func (r *IPSet) Create() error {
	err := r.Destroy()
	if err != nil {
		return err
	}

	defaultTimeout := uint32(300)
	err = netlink.IpsetCreate(r.SetName, "hash:ip", netlink.IpsetCreateOptions{
		Timeout: &defaultTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to create ipset: %w", err)
	}

	return nil
}

func (r *IPSet) Destroy() error {
	err := netlink.IpsetDestroy(r.SetName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	return nil
}

func (nh *NetfilterHelper) IPSet(name string) *IPSet {
	return &IPSet{
		SetName: name,
	}
}
