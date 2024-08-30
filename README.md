# kvas2-go

Better implementation of [KVAS](https://github.com/qzeleza/kvas)

Realized features:
- [x] DNS Proxy (UDP)
- [ ] DNS Proxy (TCP)
- [x] Records table
- [x] IPTables rules to remap DNS server [1]
- [ ] Rule composer
- [ ] List loading/watching (temporary)
- [X] IPSet integration
- [ ] Listing of interfaces
- [ ] IPTables rules to IPSet [2]
- [ ] It is not a concept now... REFACTORING TIME!!!
- [ ] HTTP API
- [ ] HTTP GUI
- [ ] Getting readable names of interfaces from Keenetic NDMS
- [ ] HTTP Auth

[1] Example
```bash
KVAS2_NAME=KVAS2
KVAS2_DNS_PORT=7548

# Создание правил
iptables -t nat -N ${KVAS2_NAME}_DNSOVERRIDE_PREROUTING
iptables -t nat -A ${KVAS2_NAME}_DNSOVERRIDE_PREROUTING -p udp --dport 53 -j REDIRECT --to-port ${KVAS2_DNS_PORT}

# Применение правил
iptables -t nat -I PREROUTING 1 -j ${KVAS2_NAME}_DNSOVERRIDE_PREROUTING

# Удаление правил
iptables -t nat -D PREROUTING -j ${KVAS2_NAME}_DNSOVERRIDE_PREROUTING
iptables -t nat -F ${KVAS2_NAME}_DNSOVERRIDE_PREROUTING
iptables -t nat -X ${KVAS2_NAME}_DNSOVERRIDE_PREROUTING
```

[2] Example
```bash
KVAS2_NAME=KVAS2
IPSET_TABLE=kvas2
MARK=1
TABLE=100
INTERFACE=ovpn_br0

# Создание правил
iptables -t mangle -N ${KVAS2_NAME}_ROUTING_PREROUTING
iptables -t nat -N ${KVAS2_NAME}_ROUTING_POSTROUTING
iptables -t mangle -A ${KVAS2_NAME}_ROUTING_PREROUTING -m set --match-set ${IPSET_TABLE} dst -j MARK --set-mark ${MARK}
iptables -t nat -A ${KVAS2_NAME}_ROUTING_POSTROUTING -o ${INTERFACE} -j MASQUERADE

# Применение правил
ip rule add fwmark ${MARK} table ${TABLE}
ip route add default dev ${INTERFACE} table ${TABLE}
iptables -t mangle -A PREROUTING -j ${KVAS2_NAME}_ROUTING_PREROUTING
iptables -t nat -A POSTROUTING -j ${KVAS2_NAME}_ROUTING_POSTROUTING

# Удаление правил
ip rule del fwmark ${MARK} table ${TABLE}
ip route del default dev ${INTERFACE} table ${TABLE}
iptables -t mangle -D PREROUTING -j ${KVAS2_NAME}_ROUTING_PREROUTING
iptables -t mangle -F ${KVAS2_NAME}_ROUTING_PREROUTING
iptables -t mangle -X ${KVAS2_NAME}_ROUTING_PREROUTING
iptables -t nat -D POSTROUTING -j ${KVAS2_NAME}_ROUTING_POSTROUTING
iptables -t nat -F ${KVAS2_NAME}_ROUTING_POSTROUTING
iptables -t nat -X ${KVAS2_NAME}_ROUTING_POSTROUTING
```
