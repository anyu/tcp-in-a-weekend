# tcp-in-a-weekend

Implementation of the following in Go:
- ping utility
- UDP protocol
- TCP protocol

## Setup
From a Linux VM (eg. [OrbStack](https://orbstack.dev) - ubuntu)

1. Install dependencies
    ```sh
    # Install tools
    $ sudo apt install -y iptables lsof

    # Install Go
    $ wget -O /tmp/go.tar.gz $LINK_TO_GO_BINARY (https://go.dev/dl)

    # Untar, add to path
    $ tar -C /usr/local -xzf /tmp/go.tar.gz
    $ export PATH=$PATH:/usr/local/go/bin

    # Confirm installation successful
    $ go version

2. Run a local server at: `192.0.2.1:8080`
    ```sh
    $ python3 -m http.server --bind 192.0.2.1 8080
    ```

3. Run setup script to create a network tunnel (`tun0`) and set up NAT
    ```sh
    bash setup.sh
    ```

## Usage

### Ping

```sh
go run cmd/ping/main.go 192.0.2.1

go run cmd/ping/main.go -c 3 192.0.2.1
```

### UDP

```sh
go run cmd/udp/main.go 8.8.8.8
```

### TCP

```sh
go run cmd/tcp/main.go 192.0.2.1
```

## Linux VM options
- [Lima](https://lima-vm.io/): some potential [network issues](https://jvns.ca/blog/2023/07/10/lima--a-nice-way-to-run-linux-vms-on-mac/)? 
- [Colima](https://github.com/abiosoft/colima)  
- [OrbStack](https://orbstack.dev/): free for personal use, subscription otherwise. 
- [UTM](https://mac.getutm.app/)

## Debugging

1. **tcpdump**
    ```sh
    sudo tcpdump -ni tun0

    sudo tcpdump -ni tun0 host 192.0.2.1
    ```

2. **tshark** (terminal Wireshark)
    ```sh
    sudo tshark -f "tcp port 12345" -i tun0 -w dump.pcap
    ```
    Open `dump.pcap` in Wireshark.

3. **nc**
    ```sh
    nc -l 192.0.2.1 8080
    ```
