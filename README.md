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

## Usage

### Ping

```sh
go run cmd/ping/main.go 192.0.2.1
```

### UDP

```sh
go run cmd/udp/main.go 8.8.8.8
```

### TCP

```sh
go run cmd/tcp/main.go 192.0.2.1
```