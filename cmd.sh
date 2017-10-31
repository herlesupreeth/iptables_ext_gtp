# Clear the iptables mangle table
sudo iptables -t mangle -F
# Clear the POSTROUTING table in eNB to avoid packet corruption
sudo iptables -t POSTROUTING -F
# Default route in router should be the IP address of eNB

# Remove GTPU KLM
sudo rmmod xt_GTPU

# Insert the GTPU KLM
sudo insmod ./Bin/xt_GTPU.ko

# Copy the userland iptables extenstion library
if [ -d /lib/xtables ]; then
    sudo cp -f ./Bin/libxt_GTPU.so /lib/xtables/
fi

# For now only encap works, decap crashes the kernel

# Some sample commands for demonstration
#iptables -t mangle -A POSTROUTING -d 8.8.8.8 -j GTPU --own-ip 192.168.0.98 --own-tun 100 --peer-ip 192.168.0.109 --peer-tun 101 --action add
#iptables -t mangle -A PREROUTING -d 8.8.8.8 -j GTPU --own-ip 192.168.0.98 --own-tun 100 --peer-ip 192.168.0.109 --peer-tun 101 --action add
#iptables -t mangle -A PREROUTING -s 192.168.0.109 -d 192.168.0.98 -p udp --dport 2152 -j GTPU --action remove
