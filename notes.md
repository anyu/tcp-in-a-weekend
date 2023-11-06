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