# Notes

# Implementing ping

Here we ping the IP of the TUN device we created during setup, *from* the peer IP address (the IP of our user-space program we also created during setup).

When we send the packet to the TUN device, the OS' network stack extracts the encapsulated ICMP packet and generates the ICMP echo reply.

The echo reply is sent to the TUN device, which encapsulates the echo reply in its tunnel (wraps the reply in an IPv4 header if required by the tunnel protocol used within the TUN device)
