package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"kvas2-go/models"
	"kvas2-go/pkg/dns-proxy"
	"kvas2-go/pkg/iptables-helper"
)

var (
	ErrAlreadyRunning  = errors.New("already running")
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

	if err := a.DNSOverrider.Enable(); err != nil {
		handleError(fmt.Errorf("failed to override DNS: %w", err))
		return errs
	}

	for idx, _ := range a.Groups {
		err := a.Groups[idx].Enable()
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
		err := a.Groups[idx].Disable()
		if err != nil {
			handleError(fmt.Errorf("failed to disable group: %w", err))
			return errs
		}
	}

	if err := a.DNSOverrider.Disable(); err != nil {
		handleError(fmt.Errorf("failed to rollback override DNS changes: %w", err))
	}

	return errs
}

func (a *App) AppendGroup(group *models.Group) error {
	if _, exists := a.Groups[group.ID]; exists {
		return ErrGroupIDConflict
	}

	a.Groups[group.ID] = &Group{
		Group: group,
	}

	if a.isRunning {
		err := a.Groups[group.ID].Enable()
		if err != nil {
			return fmt.Errorf("failed to enable appended group: %w", err)
		}
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
