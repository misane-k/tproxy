sudo sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -i wlan2 -p tcp -m tcp --dport 12345 -j RETURN
iptables -t nat -A PREROUTING -i wlan2 -p tcp -j REDIRECT --to-port 12345

# dnsmasq -C $(pwd)/dnsmasq.conf -d
