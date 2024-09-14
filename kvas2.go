package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"kvas2-go/dns-proxy"
	"kvas2-go/models"
	"kvas2-go/netfilter-helper"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

var (
	ErrAlreadyRunning  = errors.New("already running")
	ErrGroupIDConflict = errors.New("group id conflict")
)

type Config struct {
	MinimalTTL             time.Duration
	ChainPostfix           string
	IpSetPostfix           string
	TargetDNSServerAddress string
	ListenPort             uint16
	UseSoftwareRouting     bool
}

type App struct {
	Config Config

	DNSProxy         *dnsProxy.DNSProxy
	NetfilterHelper4 *netfilterHelper.NetfilterHelper
	Records          *Records
	Groups           map[int]*Group

	isRunning     bool
	dnsOverrider4 *netfilterHelper.PortRemap
}

func (a *App) Listen(ctx context.Context) []error {
	if a.isRunning {
		return []error{ErrAlreadyRunning}
	}
	a.isRunning = true
	defer func() { a.isRunning = false }()

	errs := make([]error, 0)
	isError := make(chan struct{})

	var once sync.Once
	var errsMu sync.Mutex
	handleError := func(err error) {
		errsMu.Lock()
		defer errsMu.Unlock()

		errs = append(errs, err)
		once.Do(func() { close(isError) })
	}
	handleErrors := func(errs2 []error) {
		errsMu.Lock()
		defer errsMu.Unlock()

		errs = append(errs, errs2...)
		once.Do(func() { close(isError) })
	}

	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				handleError(err)
			} else {
				handleError(fmt.Errorf("%v", r))
			}
		}
	}()

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.dnsOverrider4 = a.NetfilterHelper4.PortRemap(fmt.Sprintf("%sDNSOR", a.Config.ChainPostfix), 53, a.Config.ListenPort)
	err := a.dnsOverrider4.Enable()

	for _, group := range a.Groups {
		err = group.Enable()
		if err != nil {
			handleError(fmt.Errorf("failed to enable group: %w", err))
			return errs
		}
	}

	go func() {
		if err := a.DNSProxy.Listen(newCtx); err != nil {
			handleError(fmt.Errorf("failed to initialize DNS proxy: %v", err))
		}
	}()

	link := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	netlink.LinkSubscribe(link, done)

	exitListenerLoop := false
	listener, err := net.Listen("unix", "/opt/var/run/kvas2-go.sock")
	if err != nil {
		handleError(fmt.Errorf("error while serve UNIX socket: %v", err))
	}
	defer listener.Close()

	go func() {
		for {
			if exitListenerLoop {
				break
			}

			conn, err := listener.Accept()
			if err != nil {
				log.Error().Err(err).Msg("error while listening unix socket")
			}

			go func(conn net.Conn) {
				defer conn.Close()

				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}

				args := strings.Split(string(buf[:n]), ":")
				if len(args) == 3 && args[0] == "netfilter.d" {
					log.Debug().Str("table", args[2]).Msg("netfilter.d event")
					if a.dnsOverrider4.Enabled {
						err := a.dnsOverrider4.PutIPTable(args[2])
						if err != nil {
							log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
						}
					}
					for _, group := range a.Groups {
						if group.ifaceToIPSet.Enabled {
							err := group.ifaceToIPSet.PutIPTable(args[2])
							if err != nil {
								log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
							}
						}
					}
				}
			}(conn)
		}
	}()

Loop:
	for {
		select {
		case event := <-link:
			switch event.Change {
			case 0x00000001:
				log.Debug().
					Str("interface", event.Link.Attrs().Name).
					Str("operstatestr", event.Attrs().OperState.String()).
					Int("operstate", int(event.Attrs().OperState)).
					Msg("interface change")
				if event.Attrs().OperState != netlink.OperDown {
					for _, group := range a.Groups {
						if group.Interface == event.Link.Attrs().Name {
							err = group.ifaceToIPSet.IfaceHandle()
							if err != nil {
								log.Error().Int("group", group.ID).Err(err).Msg("error while handling interface up")
							}
						}
					}
				}
			case 0xFFFFFFFF:
				switch event.Header.Type {
				case 16:
					log.Debug().
						Str("interface", event.Link.Attrs().Name).
						Int("type", int(event.Header.Type)).
						Msg("interface add")
				case 17:
					log.Debug().
						Str("interface", event.Link.Attrs().Name).
						Int("type", int(event.Header.Type)).
						Msg("interface del")
				}
			}
		case <-ctx.Done():
			break Loop
		case <-isError:
			break Loop
		}
	}

	close(done)

	errs2 := a.dnsOverrider4.Disable()
	if errs2 != nil {
		handleErrors(errs2)
	}

	for _, group := range a.Groups {
		errs2 = group.Disable()
		if errs2 != nil {
			handleErrors(errs2)
		}
	}

	return errs
}

func (a *App) AddGroup(group *models.Group) error {
	if _, exists := a.Groups[group.ID]; exists {
		return ErrGroupIDConflict
	}

	ipsetName := fmt.Sprintf("%s%d", a.Config.IpSetPostfix, group.ID)
	ipset, err := a.NetfilterHelper4.IPSet(ipsetName)
	if err != nil {
		return fmt.Errorf("failed to initialize ipset: %w", err)
	}

	grp := &Group{
		Group:        group,
		iptables:     a.NetfilterHelper4.IPTables,
		ipset:        ipset,
		ifaceToIPSet: a.NetfilterHelper4.IfaceToIPSet(fmt.Sprintf("%sR_%d", a.Config.ChainPostfix, group.ID), group.Interface, ipsetName, false),
	}
	a.Groups[group.ID] = grp
	return a.SyncGroup(grp)
}

func (a *App) SyncGroup(group *Group) error {
	processedDomains := make(map[string]struct{})
	newIpsetAddressesMap := make(map[string]time.Duration)
	now := time.Now()

	oldIpsetAddresses, err := group.ListIPv4()
	if err != nil {
		return fmt.Errorf("failed to get old ipset list: %w", err)
	}

	knownDomains := a.Records.ListKnownDomains()
	for _, domain := range group.Domains {
		if !domain.IsEnabled() {
			continue
		}

		for _, domainName := range knownDomains {
			if !domain.IsMatch(domainName) {
				continue
			}

			cnames := a.Records.GetCNameRecords(domainName, true)
			if len(cnames) == 0 {
				continue
			}
			for _, cname := range cnames {
				processedDomains[cname] = struct{}{}
			}

			addresses := a.Records.GetARecords(domainName)
			for _, address := range addresses {
				ttl := now.Sub(address.Deadline)
				if oldTTL, ok := newIpsetAddressesMap[string(address.Address)]; !ok || ttl > oldTTL {
					newIpsetAddressesMap[string(address.Address)] = ttl
				}
			}
		}
	}

	for addr, ttl := range newIpsetAddressesMap {
		if _, exists := oldIpsetAddresses[addr]; exists {
			continue
		}
		ip := net.IP(addr)
		err = group.AddIPv4(ip, ttl)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to add address")
		}
	}

	for addr, _ := range oldIpsetAddresses {
		if _, exists := newIpsetAddressesMap[addr]; exists {
			continue
		}
		ip := net.IP(addr)
		err = group.DelIPv4(ip)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to delete address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("add address")
		}
	}

	return nil
}

func (a *App) ListInterfaces() ([]net.Interface, error) {
	interfaceNames := make([]net.Interface, 0)

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagPointToPoint == 0 {
			continue
		}

		interfaceNames = append(interfaceNames, iface)
	}

	return interfaceNames, nil
}

func (a *App) processARecord(aRecord dnsProxy.Address) {
	log.Trace().
		Str("name", aRecord.Name.String()).
		Str("address", aRecord.Address.String()).
		Int("ttl", int(aRecord.TTL)).
		Msg("processing a record")

	ttlDuration := time.Duration(aRecord.TTL) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.AddARecord(aRecord.Name.String(), aRecord.Address, ttlDuration)

	names := a.Records.GetCNameRecords(aRecord.Name.String(), true)
	for _, group := range a.Groups {
	Domain:
		for _, domain := range group.Domains {
			if !domain.IsEnabled() {
				continue
			}
			for _, name := range names {
				if !domain.IsMatch(name) {
					continue
				}
				err := group.AddIPv4(aRecord.Address, ttlDuration)
				if err != nil {
					log.Error().
						Str("address", aRecord.Address.String()).
						Err(err).
						Msg("failed to add address")
				} else {
					log.Trace().
						Str("address", aRecord.Address.String()).
						Str("aRecordDomain", aRecord.Name.String()).
						Str("cNameDomain", name).
						Err(err).
						Msg("add address")
				}
				break Domain
			}
		}
	}
}

func (a *App) processCNameRecord(cNameRecord dnsProxy.CName) {
	log.Trace().
		Str("name", cNameRecord.Name.String()).
		Str("cname", cNameRecord.CName.String()).
		Int("ttl", int(cNameRecord.TTL)).
		Msg("processing cname record")

	ttlDuration := time.Duration(cNameRecord.TTL) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.AddCNameRecord(cNameRecord.Name.String(), cNameRecord.CName.String(), ttlDuration)

	// TODO: Optimization
	now := time.Now()
	aRecords := a.Records.GetARecords(cNameRecord.Name.String())
	names := a.Records.GetCNameRecords(cNameRecord.Name.String(), true)
	for _, group := range a.Groups {
	Domain:
		for _, domain := range group.Domains {
			if !domain.IsEnabled() {
				continue
			}
			for _, name := range names {
				if !domain.IsMatch(name) {
					continue
				}
				for _, aRecord := range aRecords {
					err := group.AddIPv4(aRecord.Address, now.Sub(aRecord.Deadline))
					if err != nil {
						log.Error().
							Str("address", aRecord.Address.String()).
							Err(err).
							Msg("failed to add address")
					} else {
						log.Trace().
							Str("address", aRecord.Address.String()).
							Str("cNameDomain", name).
							Err(err).
							Msg("add address")
					}
				}
				continue Domain
			}
		}
	}
}

func (a *App) handleRecord(rr dnsProxy.ResourceRecord) {
	switch v := rr.(type) {
	case dnsProxy.Address:
		// TODO: Optimize equals domain A records
		a.processARecord(v)
	case dnsProxy.CName:
		a.processCNameRecord(v)
	default:
	}
}

func (a *App) handleMessage(msg *dnsProxy.Message) {
	for _, rr := range msg.AN {
		a.handleRecord(rr)
	}
	for _, rr := range msg.NS {
		a.handleRecord(rr)
	}
	for _, rr := range msg.AR {
		a.handleRecord(rr)
	}
}

func New(config Config) (*App, error) {
	var err error

	app := &App{}

	app.Config = config

	app.DNSProxy = dnsProxy.New(app.Config.ListenPort, app.Config.TargetDNSServerAddress)
	app.DNSProxy.MsgHandler = app.handleMessage

	app.Records = NewRecords()

	nh4, err := netfilterHelper.New(false)
	if err != nil {
		return nil, fmt.Errorf("netfilter helper init fail: %w", err)
	}
	app.NetfilterHelper4 = nh4

	app.Groups = make(map[int]*Group)

	return app, nil
}
