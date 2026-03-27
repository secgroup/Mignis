# Multi-WAN Load Balancing Guide

Complete guide for setting up dual WAN with FTTC (public IP) + 5G (CGNAT).

## Scenario

- **WAN1 (FTTC)**: Public IP, low latency, exposes services
- **WAN2 (5G)**: CGNAT, higher bandwidth, outbound only
- **Goal**: Load balancing + failover

## Architecture

```
Internet (FTTC) ──┬─── eth0 (1.2.3.4/24) [wan]
                  │
Internet (5G) ────┼─── eth1 (100.64.x.x/10) [wan, CGNAT]
                  │
                Router (Mignis)
                  │
LAN ──────────────┴─── eth2 (192.168.1.0/24)
```

## Step 1: Mignis Configuration

Use `ex_dual_wan_loadbalance.config`:

```bash
mignis -c examples/ex_dual_wan_loadbalance.config -w /etc/iptables/rules.v4
```

### What Mignis handles:
- ✅ NAT/Firewall rules
- ✅ DNAT for incoming services (FTTC only)
- ✅ NAT reflection (hairpinning)
- ✅ SNAT with correct public IP for multi-WAN
- ✅ MASQUERADE for both WAN interfaces

### What Mignis does NOT handle:
- ❌ Routing decisions (which WAN to use)
- ❌ Load balancing algorithm
- ❌ Failover detection
- ❌ Health checks

## Step 2: Policy Routing Setup

### A. Define Routing Tables

Edit `/etc/iproute2/rt_tables`:
```
1 fttc
2 lte5g
```

### B. Setup Routes

```bash
#!/bin/bash
# /etc/network/if-up.d/multi-wan-routes

# FTTC routing table
ip route add default via 1.2.3.1 dev eth0 table fttc
ip route add 192.168.1.0/24 dev eth2 table fttc

# 5G routing table
ip route add default via 100.64.0.1 dev eth1 table lte5g
ip route add 192.168.1.0/24 dev eth2 table lte5g

# Routing rules (mark-based)
ip rule add fwmark 1 table fttc
ip rule add fwmark 2 table lte5g

# Default multipath routing (load balancing)
ip route add default scope global \
    nexthop via 1.2.3.1 dev eth0 weight 2 \
    nexthop via 100.64.0.1 dev eth1 weight 1
```

**Weights explanation:**
- `weight 2` (FTTC): 66% of traffic
- `weight 1` (5G): 33% of traffic

## Step 3: Traffic Shaping (Optional)

### Strategy: Use FTTC for latency-sensitive, 5G for bulk

#### Mark packets in iptables (already in CUSTOM section):

```bash
# Low latency traffic → FTTC (mark 1)
iptables -t mangle -A PREROUTING -i eth2 -p tcp -m multiport --dports 80,443,22,53 -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i eth2 -p udp --dport 53 -j MARK --set-mark 1

# Bulk traffic → 5G (mark 2)
iptables -t mangle -A PREROUTING -i eth2 -p tcp --dport 443 -m connbytes --connbytes 10000000: --connbytes-dir both --connbytes-mode bytes -j MARK --set-mark 2

# Preserve connection marks (sticky sessions)
iptables -t mangle -A PREROUTING -m connmark --mark 1 -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -m connmark --mark 2 -j MARK --set-mark 2
iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark
```

## Step 4: Failover Script

### Basic health check:

```bash
#!/bin/bash
# /usr/local/bin/wan-failover.sh

FTTC_GW="1.2.3.1"
LTE5G_GW="100.64.0.1"
CHECK_HOST="8.8.8.8"

while true; do
    # Check FTTC
    if ! ping -c 3 -W 2 -I eth0 $CHECK_HOST > /dev/null 2>&1; then
        echo "FTTC down, removing from routing"
        ip route del default via $FTTC_GW dev eth0 2>/dev/null
    else
        # FTTC is up, ensure route exists
        ip route replace default via $FTTC_GW dev eth0
    fi

    # Check 5G
    if ! ping -c 3 -W 2 -I eth1 $CHECK_HOST > /dev/null 2>&1; then
        echo "5G down, removing from routing"
        ip route del default via $LTE5G_GW dev eth1 2>/dev/null
    else
        ip route replace default via $LTE5G_GW dev eth1
    fi

    # Rebuild multipath route with available WANs
    ip route replace default scope global \
        $(ip route show | grep "via $FTTC_GW" > /dev/null && echo "nexthop via $FTTC_GW dev eth0 weight 2") \
        $(ip route show | grep "via $LTE5G_GW" > /dev/null && echo "nexthop via $LTE5G_GW dev eth1 weight 1")

    sleep 10
done
```

Run as systemd service:
```ini
# /etc/systemd/system/wan-failover.service
[Unit]
Description=WAN Failover Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wan-failover.sh
Restart=always

[Install]
WantedBy=multi-user.target
```

## Step 5: Testing

### Test 1: NAT Reflection (LAN client accessing public IP)

From LAN client (192.168.1.10):
```bash
curl http://1.2.3.4
# Should reach web_server (192.168.1.100)
```

Check on router:
```bash
tcpdump -i eth2 -n host 192.168.1.100
# Should see:
# 1.2.3.4 → 192.168.1.100 (SNAT applied)
```

### Test 2: Load Balancing

From LAN client:
```bash
# Multiple requests should use different WANs
for i in {1..10}; do
  curl -s ifconfig.me
  sleep 1
done
```

Expected: Mix of IPs (FTTC public IP and 5G exit IP)

### Test 3: Failover

```bash
# Disconnect FTTC
ip link set eth0 down

# Wait 10 seconds (failover script interval)
sleep 10

# Test connectivity (should use 5G)
curl ifconfig.me

# Reconnect FTTC
ip link set eth0 up
```

## Advanced: mwan3 (Recommended for Production)

For production environments, use **mwan3** (available on OpenWrt):

```bash
opkg install mwan3 luci-app-mwan3

# Configure via LuCI web interface:
# - Define interfaces (fttc, lte5g)
# - Setup tracking (ping tests)
# - Configure policies (load balance, failover)
# - Define rules (traffic splitting)
```

Benefits:
- ✅ Automatic failover
- ✅ Health monitoring
- ✅ Advanced load balancing algorithms
- ✅ Per-protocol/destination routing
- ✅ Web UI configuration

## Troubleshooting

### Issue: Connections hang when switching WANs

**Cause:** Connection tracking expects replies via same interface

**Solution:** Flush conntrack on failover:
```bash
conntrack -F
```

### Issue: Asymmetric routing drops packets

**Cause:** `rp_filter` (reverse path filtering)

**Solution:** Disable for WAN interfaces:
```bash
echo 0 > /proc/sys/net/ipv4/conf/eth0/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/eth1/rp_filter
```

Make permanent in `/etc/sysctl.conf`:
```
net.ipv4.conf.eth0.rp_filter = 0
net.ipv4.conf.eth1.rp_filter = 0
```

### Issue: DNS resolution fails

**Cause:** DNS queries going out wrong WAN

**Solution:** Use both ISP DNS servers:
```bash
# /etc/resolv.conf
nameserver 1.2.3.1      # FTTC DNS
nameserver 100.64.0.1   # 5G DNS
nameserver 8.8.8.8      # Fallback
```

## Performance Tuning

### TCP Window Scaling (for high bandwidth)

```bash
echo 1 > /proc/sys/net/ipv4/tcp_window_scaling
echo 4096 87380 16777216 > /proc/sys/net/ipv4/tcp_rmem
echo 4096 65536 16777216 > /proc/sys/net/ipv4/tcp_wmem
```

### MTU Optimization

5G often has lower MTU due to tunneling:
```bash
ip link set eth1 mtu 1400
```

## Summary

| Component | Tool | Purpose |
|-----------|------|---------|
| Firewall/NAT | **Mignis** | Rules, DNAT, NAT reflection |
| Routing | **iproute2** | Policy routing, multipath |
| Failover | **Custom script** or **mwan3** | Health checks, automatic switching |
| Traffic shaping | **iptables mangle** | Mark packets for routing |

**Mignis handles the firewall/NAT layer correctly for multi-WAN.**
The rest requires external routing configuration.
