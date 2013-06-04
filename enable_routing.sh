iptables -t nat -F
iptables -F
echo 1 > /proc/sys/net/ipv4/ip_forward
echo IP forwarding enabled
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo Masquerading enabled
