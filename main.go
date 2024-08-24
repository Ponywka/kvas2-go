package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	dnsProxy "kvas2-go/dns-proxy"
	iptablesHelper "kvas2-go/iptables-helper"
	ruleComposer "kvas2-go/rule-composer"
)

var (
	ChainPostfix           = "KVAS2"
	ListenPort             = uint16(7548)
	TargetDNSServerAddress = "127.0.0.1:53"
)

func main() {
	records := ruleComposer.NewRecords()
	proxy := dnsProxy.New(ListenPort, TargetDNSServerAddress)
	dnsOverrider, err := iptablesHelper.NewDNSOverrider(fmt.Sprintf("%s_DNSOVERRIDER", ChainPostfix), ListenPort)
	if err != nil {
		log.Fatalf("failed to initialize DNS overrider: %v", err)
	}

	proxy.MsgHandler = func(msg *dnsProxy.Message) {
		printKnownRecords := func() {
			for _, q := range msg.QD {
				fmt.Printf("%04x: DBG Known addresses for: %s\n", msg.ID, q.QName.String())
				for idx, addr := range records.GetARecords(q.QName.String(), true) {
					fmt.Printf("%04x:     #%d: %s\n", msg.ID, idx, addr.String())
				}
			}
		}
		parseResponseRecord := func(rr dnsProxy.ResourceRecord) {
			switch v := rr.(type) {
			case dnsProxy.Address:
				fmt.Printf("%04x: -> A: Name: %s; Address: %s; TTL: %d\n", msg.ID, v.Name, v.Address.String(), v.TTL)
				records.PutARecord(v.Name.String(), v.Address, int64(v.TTL))
			case dnsProxy.CName:
				fmt.Printf("%04x: -> CNAME: Name: %s; CName: %s\n", msg.ID, v.Name, v.CName)
				records.PutCNameRecord(v.Name.String(), v.CName.String(), int64(v.TTL))
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
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		err := proxy.Listen(ctx)
		if err != nil {
			log.Fatalf("failed to initialize DNS proxy: %v", err)
		}
	}()

	err = dnsOverrider.Enable()
	if err != nil {
		log.Fatalf("failed to override DNS: %v", err)
	}

	fmt.Printf("Started service on port '%d'\n", ListenPort)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-c:
			fmt.Println("Graceful shutdown...")
			cancel()
			err = dnsOverrider.Disable()
			if err != nil {
				log.Fatalf("failed to rollback override DNS changes: %v", err)
			}
			return
		}
	}
}
