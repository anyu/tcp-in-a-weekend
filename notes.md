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

## Part 0

### What's a tun device?

TUN (short for network TUNnel) is a **virtual interface** that essentially implements a software version of a network by emulating physical devices (eg. Ethernet or WiFi interface cards)

It operates on Layer 3 of the OSI model, so can handle IP packets.

It can be used to **route traffic** through a tunnel, so it's good for VPN functionality.

It lets applications read and write to this network inferface.

#### How to create a TUN interface

With `ip`

```sh
$ sudo ip tuntap add name tun0 mode tun user $USER
```

With `tunctl` (less common, less general purpose?)
```sh
$ sudo tunctl -t tun0
```

### What's a network tunnel

A way to for transport data across a network using protocols that are not supported by that network.

It works by **encapsulating packets** (wrapping packets inside other packets).

Encapsulation use case examples: 
- encapsulate IPv6 packets inside IPv4 packets through a network that only supports IPv4
- encapsulate encrypted network packet inside an unencrypted packet so it can travel across networks

### What's TUN/TAP?

---

### Backlog of questions and things to explore

- Loopback interface
- NIC, physical network interface cards
- How does VPNs really work

### Resources
- **TUN/TAP**:
  - https://www.gabriel.urdhr.fr/2021/05/08/tuntap/#tun-vs-tap

