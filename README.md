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
KVAS2_NAME=KVAS2
KVAS2_DNS_PORT=7548

# Создание правил
iptables -t nat -N ${KVAS2_NAME}_PREROUTING
iptables -t nat -A ${KVAS2_NAME}_PREROUTING -p udp --dport 53 -j REDIRECT --to-port ${KVAS2_DNS_PORT}

# Применение правил
iptables -t nat -I PREROUTING 1 -j ${KVAS2_NAME}_PREROUTING

# Удаление правил
iptables -t nat -D PREROUTING -j ${KVAS2_NAME}_PREROUTING
```

[2] Example
```bash
KVAS2_NAME=KVAS2
IPSET_TABLE=kvas2
MARK=1
TABLE=100
INTERFACE=ovpn_br0

# Создание правил
iptables -t mangle -N ${KVAS2_NAME}_PREROUTING
iptables -t nat -N ${KVAS2_NAME}_POSTROUTING
iptables -t mangle -A ${KVAS2_NAME}_PREROUTING -m set --match-set ${IPSET_TABLE} dst -j MARK --set-mark ${MARK}
iptables -t nat -A ${KVAS2_NAME}_POSTROUTING -o ${INTERFACE} -j MASQUERADE

# Применение правил
ip rule add fwmark ${MARK} table ${TABLE}
ip route add default dev ${INTERFACE} table ${TABLE}
iptables -t mangle -A PREROUTING -j ${KVAS2_NAME}_PREROUTING
iptables -t nat -A POSTROUTING -j ${KVAS2_NAME}_POSTROUTING

# Удаление правил
ip rule del fwmark ${MARK} table ${TABLE}
ip route del default dev ${INTERFACE} table ${TABLE}
iptables -t mangle -D PREROUTING -j ${KVAS2_NAME}_PREROUTING
iptables -t nat -D POSTROUTING -j ${KVAS2_NAME}_POSTROUTING
```
