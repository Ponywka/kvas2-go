package main

import (
	"fmt"
	dnsProxy "kvas2-go/dns-proxy"
	"log"
)

var (
	ListenPort             = uint16(7548)
	UsableDNSServerAddress = "127.0.0.1"
	UsableDNSServerPort    = uint16(53)
)

func main() {
	proxy := dnsProxy.New("", ListenPort, UsableDNSServerAddress, UsableDNSServerPort)
	proxy.MsgHandler = func(msg *dnsProxy.Message) {
		for _, q := range msg.QD {
			fmt.Printf("%x: <- Request name: %s\n", msg.ID, q.QName.String())
		}
		for _, a := range msg.AN {
			switch v := a.(type) {
			case dnsProxy.Address:
				fmt.Printf("%x: -> A: Name: %s; Address: %s; TTL: %d\n", msg.ID, v.Name, v.Address.String(), v.TTL)
			case dnsProxy.CName:
				fmt.Printf("%x: -> CNAME: Name: %s; CName: %s\n", msg.ID, v.Name, v.CName)
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
	}
	err := proxy.Listen()
	if err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()
}
