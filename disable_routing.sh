iptables -t nat -F
iptables -F
echo 0 > /proc/sys/net/ipv4/ip_forward
