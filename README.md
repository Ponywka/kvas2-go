# kvas2-go

Better implementation of [KVAS](https://github.com/qzeleza/kvas)

Realized features:
- [x] DNS Proxy (UDP)
- [ ] DNS Proxy (TCP)
- [x] Records memory
- [x] IPTables rules for rebind DNS server port
- [X] IPSet integration
- [X] IP integration
- [X] IPTables rules to IPSet
- [ ] Catch interface up/down
- [ ] Catch `netfilter.d` event
- [ ] Rule composer (CRUD)
- [ ] GORM integration
- [X] Listing of interfaces
- [ ] HTTP API
- [ ] HTTP GUI
- [ ] CLI
- [ ] (Keenetic) Support for custom interfaces [1]
- [ ] It is not a concept now... REFACTORING TIME!!!
- [ ] (Keenetic) Getting readable names of interfaces from Keenetic NDMS
- [ ] HTTP Auth

[1] Example
```bash
INTERFACE=ovpn_br0
iptables -A _NDM_SL_FORWARD -o ${INTERFACE} -m state --state NEW -j _NDM_SL_PROTECT
```
