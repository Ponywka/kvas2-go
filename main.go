package main

import (
	"fmt"
	dnsProxy "kvas2-go/dns-proxy"
	ruleComposer "kvas2-go/rule-composer"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	ListenPort             = uint16(7548)
	UsableDNSServerAddress = "127.0.0.1"
	UsableDNSServerPort    = uint16(53)
)

func main() {
	records := ruleComposer.NewRecords()
	proxy := dnsProxy.New("", ListenPort, UsableDNSServerAddress, UsableDNSServerPort)
	proxy.MsgHandler = func(msg *dnsProxy.Message) {
		for _, q := range msg.QD {
			fmt.Printf("%x: <- Request name: %s\n", msg.ID, q.QName.String())
		}
		for _, a := range msg.AN {
			switch v := a.(type) {
			case dnsProxy.Address:
				fmt.Printf("%x: -> A: Name: %s; Address: %s; TTL: %d\n", msg.ID, v.Name, v.Address.String(), v.TTL)
				records.PutIPv4Address(v.Name.String(), v.Address, int64(v.TTL))
			case dnsProxy.CName:
				fmt.Printf("%x: -> CNAME: Name: %s; CName: %s\n", msg.ID, v.Name, v.CName)
				records.PutCName(v.Name.String(), v.CName.String(), int64(v.TTL))
			default:
				fmt.Printf("%x: -> Unknown: %x\n", msg.ID, v.EncodeResource())
			}
		}
		for _, a := range msg.NS {
			fmt.Printf("%x: -> NS: %x\n", msg.ID, a.EncodeResource())
		}
		for _, a := range msg.AR {
			fmt.Printf("%x: -> NS: %x\n", msg.ID, a.EncodeResource())
		}

		for _, q := range msg.QD {
			fmt.Printf("%x: DBG Known addresses for: %s\n", msg.ID, q.QName.String())
			for idx, addr := range records.GetIPv4Addresses(q.QName.String()) {
				fmt.Printf("%x:     #%d: %s\n", msg.ID, idx, addr.String())
			}
		}
	}

	go func() {
		err := proxy.Listen()
		if err != nil {
			log.Fatal(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-c:
			proxy.Close()
			return
		}
	}
}
