package main

import (
	"context"
	"fmt"
	"kvas2-go/models"
	"kvas2-go/pkg/dns-proxy"
	"kvas2-go/pkg/iptables-helper"
	"sync"
	"time"
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
	Groups       []*models.Group
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

	go func() {
		if err := a.DNSProxy.Listen(newCtx); err != nil {
			handleError(fmt.Errorf("failed to initialize DNS proxy: %v", err))
		}
	}()

	select {
	case <-ctx.Done():
	case <-isError:
	}

	if err := a.DNSOverrider.Disable(); err != nil {
		handleError(fmt.Errorf("failed to rollback override DNS changes: %w", err))
	}

	return errs
}

func (a *App) processARecord(aRecord dnsProxy.Address) {
	ttlDuration := time.Duration(aRecord.TTL) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.PutARecord(aRecord.Name.String(), aRecord.Address, ttlDuration)

	cNames := append([]string{aRecord.Name.String()}, a.Records.GetCNameRecords(aRecord.Name.String(), true, true)...)
	fmt.Printf("Relates CNames:\n")
	for idx, cName := range cNames {
		fmt.Printf("|- #%d: %s\n", idx, cName)
	}

	for _, group := range a.Groups {
		for _, domain := range group.Domains {
			if !domain.IsEnabled() {
				continue
			}
			for _, cName := range cNames {
				if domain.IsMatch(cName) {
					fmt.Printf("|- Matched %s (%s) for %s in %s group!\n", cName, aRecord.Name, domain.Domain, group.Name)
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

func (a *App) handleRecord(msg *dnsProxy.Message) {
	printKnownRecords := func() {
		for _, q := range msg.QD {
			fmt.Printf("%04x: DBG Known addresses for: %s\n", msg.ID, q.QName.String())
			for idx, addr := range a.Records.GetARecords(q.QName.String(), true, false) {
				fmt.Printf("%04x:     #%d: %s\n", msg.ID, idx, addr.String())
			}
		}
	}
	parseResponseRecord := func(rr dnsProxy.ResourceRecord) {
		switch v := rr.(type) {
		case dnsProxy.Address:
			fmt.Printf("%04x: -> A: Name: %s; Address: %s; TTL: %d\n", msg.ID, v.Name, v.Address.String(), v.TTL)
			a.processARecord(v)
		case dnsProxy.CName:
			fmt.Printf("%04x: -> CNAME: Name: %s; CName: %s\n", msg.ID, v.Name, v.CName)
			a.processCNameRecord(v)
		default:
			fmt.Printf("%04x: -> Unknown: %x\n", msg.ID, v.EncodeResource())
		}
	}

	printKnownRecords()
	for _, q := range msg.QD {
		fmt.Printf("%04x: <- Request name: %s\n", msg.ID, q.QName.String())
	}
	for _, a := range msg.AN {
		parseResponseRecord(a)
	}
	for _, a := range msg.NS {
		parseResponseRecord(a)
	}
	for _, a := range msg.AR {
		parseResponseRecord(a)
	}
	printKnownRecords()
	fmt.Println()
}

func New(config Config) (*App, error) {
	var err error

	app := &App{}

	app.Config = config

	app.DNSProxy = dnsProxy.New(app.Config.ListenPort, app.Config.TargetDNSServerAddress)
	app.DNSProxy.MsgHandler = app.handleRecord

	app.Records = NewRecords()

	app.DNSOverrider, err = iptablesHelper.NewDNSOverrider(fmt.Sprintf("%s_DNSOVERRIDER", app.Config.ChainPostfix), app.Config.ListenPort)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DNS overrider: %w", err)
	}

	app.Groups = make([]*models.Group, 0)

	return app, nil
}
