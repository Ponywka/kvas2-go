package main

import (
	"net"
	"time"

	"kvas2-go/models"
	"kvas2-go/netfilter-helper"

	"github.com/coreos/go-iptables/iptables"
)

type Group struct {
	*models.Group

	Enabled bool

	iptables     *iptables.IPTables
	ipset        *netfilterHelper.IPSet
	ifaceToIPSet *netfilterHelper.IfaceToIPSet
}

func (g *Group) HandleIPv4(relatedDomains []string, address net.IP, ttl time.Duration) error {
	for _, domain := range g.Domains {
		if !domain.IsEnabled() {
			continue
		}
		for _, name := range relatedDomains {
			if domain.IsMatch(name) {
				ttlSeconds := uint32(ttl.Seconds())
				return g.ipset.Add(address, &ttlSeconds)
			}
		}
	}

	return nil
}

func (g *Group) Enable() error {
	if g.Enabled {
		return nil
	}
	defer func() {
		if !g.Enabled {
			_ = g.Disable()
		}
	}()

	if g.FixProtect {
		g.iptables.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
	}

	err := g.ipset.Create()
	if err != nil {
		return err
	}

	err = g.ifaceToIPSet.Enable()
	if err != nil {
		return err
	}

	g.Enabled = true

	return nil
}

func (g *Group) Disable() []error {
	var errs []error

	if !g.Enabled {
		return nil
	}

	errs2 := g.ifaceToIPSet.Disable()
	if errs2 != nil {
		errs = append(errs, errs2...)
	}

	err := g.ipset.Destroy()
	if err != nil {
		errs = append(errs, err)
	}

	g.Enabled = false

	return errs
}
