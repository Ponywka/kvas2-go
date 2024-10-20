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

func (r *IPSet) AddIP(addr net.IP, timeout *uint32) error {
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

func (r *IPSet) Del(addr net.IP) error {
	err := netlink.IpsetDel(r.SetName, &netlink.IPSetEntry{
		IP: addr,
	})
	if err != nil {
		return fmt.Errorf("failed to delete address: %w", err)
	}
	return nil
}

func (r *IPSet) List() (map[string]*uint32, error) {
	list, err := netlink.IpsetList(r.SetName)
	if err != nil {
		return nil, err
	}
	addresses := make(map[string]*uint32)
	for _, entry := range list.Entries {
		addresses[string(entry.IP)] = entry.Timeout
	}
	return addresses, nil
}

func (r *IPSet) Destroy() error {
	err := netlink.IpsetDestroy(r.SetName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	return nil
}

func (nh *NetfilterHelper) IPSet(name string) (*IPSet, error) {
	ipset := &IPSet{
		SetName: name,
	}
	err := ipset.Destroy()
	if err != nil {
		return nil, err
	}

	defaultTimeout := uint32(300)
	err = netlink.IpsetCreate(ipset.SetName, "hash:net", netlink.IpsetCreateOptions{
		Timeout: &defaultTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset: %w", err)
	}

	return ipset, nil
}
