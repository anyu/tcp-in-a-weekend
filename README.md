# tcp-in-a-weekend
TCP in a Weekend in Go

## Using Orbstack

### Dependencies

Install tools
```sh
sudo apt install -y iptables lsof 
# openssh-server?
```

Install Go:
1. wget Go binary from https://go.dev/doc/install into `/usr/local`
2. `tar -C /usr/local -xzf go1.XX.X.linux-amd64.tar.gz`
3. `export PATH=$PATH:/usr/local/go/bin`
4. `go version`