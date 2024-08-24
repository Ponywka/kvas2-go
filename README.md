# kvas2-go

Better implementation of [KVAS](https://github.com/qzeleza/kvas)

Roadmap:
- [x] DNS Proxy
- [x] DNS Records table
- [ ] IPTables rules to remap DNS server [1]
- [ ] Rule composer
- [ ] List loading/watching (temporary)
- [ ] IPSet integration
- [ ] Listing of interfaces
- [ ] IPTables rules to IPSet [2]
- [ ] HTTP API
- [ ] HTTP GUI
- [ ] Getting readable names of interfaces from Keenetic NDMS
- [ ] HTTP Auth

[1] Example
```bash
KVAS2_DNS_PORT=7548
iptables -t nat -I PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-port $KVAS2_DNS_PORT
```

[2] Example
```bash
IPSET_TABLE=kvas2
MARK=1
TABLE=100
INTERFACE=ovpn_br0
iptables -t mangle -A PREROUTING -m set --match-set $IPSET_TABLE dst -j MARK --set-mark $MARK
ip rule add fwmark $MARK table $TABLE
ip route add default dev $INTERFACE table $TABLE
iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
```
