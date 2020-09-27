iptables -A INPUT -p tcp -s  $1 --sport $2 -j NFQUEUE
iptables -A INPUT -p udp -s  $1 --sport $2 -j NFQUEUE
iptables -A INPUT   ! -s   $1  -j ACCEPT

#echo "ip is $1 port is:$2"