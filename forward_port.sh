echo Forwarding all traffic to port $1 to port $2 on localhost
iptables -t nat -A PREROUTING -p tcp --destination-port $1 -j REDIRECT --to-port $2
