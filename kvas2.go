package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"kvas2-go/models"
	"kvas2-go/pkg/dns-proxy"
	"kvas2-go/pkg/ip-helper"
	"kvas2-go/pkg/iptables-helper"
)

var (
	ErrGroupIDConflict = errors.New("group id conflict")
)

type Config struct {
	MinimalTTL             time.Duration
	ChainPostfix           string
	TargetDNSServerAddress string
	ListenPort             uint16
}

type App struct {
	Config Config

	DNSProxy     *dnsProxy.DNSProxy
	DNSOverrider *iptablesHelper.DNSOverrider
	Records      *Records
	Groups       map[int]*Group
}

func (a *App) Listen(ctx context.Context) []error {
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

	if err := a.DNSOverrider.Enable(); err != nil {
		handleError(fmt.Errorf("failed to override DNS: %w", err))
		return errs
	}

	for idx, _ := range a.Groups {
		err := a.usingGroup(idx)
		if err != nil {
			handleError(fmt.Errorf("failed to using group: %w", err))
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
		err := a.releaseGroup(idx)
		if err != nil {
			handleError(fmt.Errorf("failed to release group: %w", err))
			return errs
		}
	}

	if err := a.DNSOverrider.Disable(); err != nil {
		handleError(fmt.Errorf("failed to rollback override DNS changes: %w", err))
	}

	return errs
}

func (a *App) usingGroup(idx int) error {
	if a.Groups[idx].options.Enabled {
		return nil
	}

	fwmark, err := ipHelper.GetUnusedFwMark(1)
	if err != nil {
		return fmt.Errorf("error while getting fwmark: %w", err)
	}

	table, err := ipHelper.GetUnusedTable(1)
	if err != nil {
		return fmt.Errorf("error while getting table: %w", err)
	}

	out, err := ipHelper.ExecIp("rule", "add", "fwmark", strconv.Itoa(int(fwmark)), "table", strconv.Itoa(int(table)))
	if err != nil {
		return err
	}
	if len(out) != 0 {
		return errors.New(string(out))
	}

	a.Groups[idx].options.Enabled = true
	a.Groups[idx].options.FWMark = fwmark
	a.Groups[idx].options.Table = table

	return nil
}

func (a *App) releaseGroup(idx int) error {
	if !a.Groups[idx].options.Enabled {
		return nil
	}

	fwmark := strconv.Itoa(int(a.Groups[idx].options.FWMark))
	table := strconv.Itoa(int(a.Groups[idx].options.Table))
	out, err := ipHelper.ExecIp("rule", "del", "fwmark", fwmark, "table", table)
	if err != nil {
		return err
	}

	if len(out) != 0 {
		return errors.New(string(out))
	}

	return nil
}

func (a *App) AppendGroup(group *models.Group) error {
	if _, exists := a.Groups[group.ID]; exists {
		return ErrGroupIDConflict
	}

	a.Groups[group.ID] = &Group{
		Group: group,
	}

	return nil
}

func (a *App) processARecord(aRecord dnsProxy.Address) {
	ttlDuration := time.Duration(aRecord.TTL) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.PutARecord(aRecord.Name.String(), aRecord.Address, ttlDuration)

	cNames := append([]string{aRecord.Name.String()}, a.Records.GetCNameRecords(aRecord.Name.String(), true, true)...)
	for _, group := range a.Groups {
		for _, domain := range group.Domains {
			if !domain.IsEnabled() {
				continue
			}
			for _, cName := range cNames {
				if domain.IsMatch(cName) {
					fmt.Printf("Matched %s (%s) for %s in %s group!\n", cName, aRecord.Name, domain.Domain, group.Name)
				}
			}
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

	app.DNSOverrider, err = iptablesHelper.NewDNSOverrider(fmt.Sprintf("%sDNSOVERRIDER", app.Config.ChainPostfix), app.Config.ListenPort)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DNS overrider: %w", err)
	}

	app.Groups = make(map[int]*Group)

	return app, nil
}
