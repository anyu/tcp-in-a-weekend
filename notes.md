# Notes

## Setup

What's a good tool these days for spinning up a Linux VM?
- [Lima](https://lima-vm.io/)
  - Some potential [network issues](https://jvns.ca/blog/2023/07/10/lima--a-nice-way-to-run-linux-vms-on-mac/)? 
- [Colima](https://github.com/abiosoft/colima)  
- [OrbStack](https://orbstack.dev/): free for personal use, subscription otherwise. 
- [UTM](https://mac.getutm.app/)

I went with OrbStack with Ubuntu.
`iptables` wasn't installed by default, so I had to install it before proceeding with the setup script.
```sh
sudo apt get -y iptables
```

# Implementing ping

Here we ping the IP of the TUN device we created during setup, *from* the peer IP address (the IP of our user-space program we also created during setup).

When we send the packet to the TUN device, the OS' network stack extracts the encapsulated ICMP packet and generates the ICMP echo reply.

The echo reply is sent to the TUN device, which encapsulates the echo reply in its tunnel (wraps the reply in an IPv4 header if required by the tunnel protocol used within the TUN device)
