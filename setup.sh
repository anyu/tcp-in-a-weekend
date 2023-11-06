# set up `tun0`
sudo ip link del tun0
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up
# The first IP below (`192.0.2.1`) is the primary address to be assigned to the tun device `tun0`.
# The second ip (`192.0.2.2`) is the peer address, indicating that this TUN device is part of a point-to-point link, which is a type of network connection in 
# which there are only two devices or endpoints communicating directly with each other (each endpoint needs an IP address)
# The user-space program that will make use of this tun device acts the remote computer at the other side of the tunnel in this case.
sudo ip addr add 192.0.2.1 peer 192.0.2.2 dev tun0

# set up NAT
sudo iptables -t nat -A POSTROUTING -s 192.0.2.2 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -s 192.0.2.2 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -d 192.0.2.2 -j ACCEPT
sudo sysctl -w net.ipv4.ip_forward=1
