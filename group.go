package main

import (
	"fmt"
	netfilterHelper "kvas2-go/netfilter-helper"
	"net"
	"time"

	"kvas2-go/models"
)

type Group struct {
	*models.Group

	Enabled bool

	ipset        *netfilterHelper.IPSet
	ifaceToIPSet *netfilterHelper.IfaceToIPSet
}

func (g *Group) HandleIPv4(names []string, address net.IP, ttl time.Duration) error {
	if !g.Enabled {
		return nil
	}

	for _, domain := range g.Domains {
		if !domain.IsEnabled() {
			continue
		}
		for _, name := range names {
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

	err := g.ipset.Destroy()
	if err != nil {
		errs = append(errs, err)
	}

	errs2 := g.ifaceToIPSet.Disable()
	if errs2 != nil {
		errs = append(errs, errs2...)
	}

	g.Enabled = false

	return nil
}

func (a *App) AddGroup(group *models.Group) error {
	if _, exists := a.Groups[group.ID]; exists {
		return ErrGroupIDConflict
	}

	ipsetName := fmt.Sprintf("%s%d", a.Config.IpSetPostfix, group.ID)

	a.Groups[group.ID] = &Group{
		Group:        group,
		ipset:        a.NetfilterHelper.IPSet(ipsetName),
		ifaceToIPSet: a.NetfilterHelper.IfaceToIPSet(fmt.Sprintf("%sROUTING_%d", a.Config.ChainPostfix, group.ID), group.Interface, ipsetName, false),
	}

	return nil
}
