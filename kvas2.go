package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"kvas2-go/dns-proxy"
	"kvas2-go/models"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog/log"
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

	DNSProxy *dnsProxy.DNSProxy
	IPTables *iptables.IPTables
	Records  *Records
	Groups   map[int]*Group

	isRunning bool
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

	chainName := fmt.Sprintf("%sDNSOVERRIDER", a.Config.ChainPostfix)

	err := a.IPTables.ClearChain("nat", chainName)
	if err != nil {
		handleError(fmt.Errorf("failed to clear chain: %w", err))
		return errs
	}

	err = a.IPTables.AppendUnique("nat", chainName, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", strconv.Itoa(int(a.Config.ListenPort)))
	if err != nil {
		handleError(fmt.Errorf("failed to create rule: %w", err))
		return errs
	}

	err = a.IPTables.InsertUnique("nat", "PREROUTING", 1, "-j", chainName)
	if err != nil {
		handleError(fmt.Errorf("failed to linking chain: %w", err))
		return errs
	}

	for idx, _ := range a.Groups {
		err = a.Groups[idx].Enable(a)
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

	select {
	case <-ctx.Done():
	case <-isError:
	}

	for idx, _ := range a.Groups {
		err = a.Groups[idx].Disable(a)
		if err != nil {
			handleError(fmt.Errorf("failed to disable group: %w", err))
			return errs
		}
	}

	err = a.IPTables.DeleteIfExists("nat", "PREROUTING", "-j", chainName)
	if err != nil {
		handleError(fmt.Errorf("failed to unlinking chain: %w", err))
		return errs
	}

	err = a.IPTables.ClearAndDeleteChain("nat", chainName)
	if err != nil {
		handleError(fmt.Errorf("failed to delete chain: %w", err))
		return errs
	}

	return errs
}

func (a *App) AppendGroup(group *models.Group) error {
	if _, exists := a.Groups[group.ID]; exists {
		return ErrGroupIDConflict
	}

	a.Groups[group.ID] = &Group{
		Group:     group,
		ipsetName: fmt.Sprintf("%s%d", a.Config.IpSetPostfix, group.ID),
	}

	if a.isRunning {
		err := a.Groups[group.ID].Enable(a)
		if err != nil {
			return fmt.Errorf("failed to enable appended group: %w", err)
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

	a.Records.PutARecord(aRecord.Name.String(), aRecord.Address, ttlDuration)

	names := append([]string{aRecord.Name.String()}, a.Records.GetCNameRecords(aRecord.Name.String(), true, true)...)
	for _, group := range a.Groups {
		err := group.HandleIPv4(names, aRecord.Address, ttlDuration)
		if err != nil {
			log.Error().
				Str("name", aRecord.Name.String()).
				Str("address", aRecord.Address.String()).
				Int("group", group.ID).
				Err(err).
				Msg("failed to handle address")
		}
	}
}

func (a *App) processCNameRecord(cNameRecord dnsProxy.CName) {
	ttlDuration := time.Duration(cNameRecord.TTL) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.PutCNameRecord(cNameRecord.Name.String(), cNameRecord.CName.String(), ttlDuration)
}

func (a *App) handleRecord(rr dnsProxy.ResourceRecord) {
	switch v := rr.(type) {
	case dnsProxy.Address:
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

	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("iptables init fail: %w", err)
	}
	app.IPTables = ipt

	app.Groups = make(map[int]*Group)

	return app, nil
}
