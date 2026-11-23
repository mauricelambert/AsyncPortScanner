![AsyncPortScanner Logo](https://mauricelambert.github.io/info/nim/security/AsyncPortScanner_small.png "AsyncPortScanner logo")

# AsyncPortScanner

## Description

Cross-platform asynchronous port scanner written in Nim.

## Requirements

 - No requirements

## Download

 - https://github.com/mauricelambert/AsyncPortScanner/releases

## Compilation

### Windows

Windows need an internal structure to stop an asynchronous call using IOCP, the name is `OVERLAPPED`. It's a structure defined at the `ConnectEx` call time, you can't access it through the Nim API, so i patch `asyncdispatch.nim` and `asyncnet.nim` to access the structure and call `CancelIoEx` with it. It's required because without this call there is an error on the `close` call (OSError on the `setSockOptInt` call because the socket was not in the good state).

You should use an equivalent patch to compile it, see modifications on [asyncdispatch.nim here](https://github.com/mauricelambert/AsyncPortScanner/commit/cd60da16a0f9440c60d3431b6eb025164b4d8cef#diff-b08d10c4a03a9de74ea2de73c0beb74f3d7e9ee0ec77ebb3654abca870296bd6) and on [asyncnet.nim here](https://github.com/mauricelambert/AsyncPortScanner/commit/cd60da16a0f9440c60d3431b6eb025164b4d8cef#diff-0f0eb4cdcd292535e59a629316753fe1fe251013f9f67817fb03365caabb3def).

#### Non static

```bash
nim.exe c --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:windows AsyncPortScanner.nim
```

#### Static with size optimization

I recommend using this compilation if you don't know the system (and DLL installed on the system) where the scan will be lanched.

```bash
nim.exe c --passl:"-static -static-libgcc -static-libstdc++" --opt:size --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:windows AsyncPortScanner.nim
```

### Linux

```bash
nim c --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:linux AsyncPortScanner.nim
```

## Usages

### Default scan

Without any arguments the scan will detect all of your network interfaces and scan all IP on it.

```bash
./scan
```

By default the scan is a TCP scan on all of this ports range:

 - 21-25
 - 53
 - 80
 - 110-143
 - 389
 - 443-465
 - 631-636
 - 993-995
 - 1433-1434
 - 1521
 - 3000
 - 3306
 - 3389
 - 5000-5357
 - 5432
 - 6001
 - 6379
 - 7474
 - 7547
 - 7687
 - 8000-8888
 - 27017

### Custom scan policy

```bash
./scan -w=1000 192.168.56.1-50:tcp:21-25,135-139,80,443-445,3000,5000-5357,8000-8888,30102
```

#### Multiples policies

```bash
./scan -w=3000 192.168.0.1-192.168.56.255 192.168.0.1-192.168.56.255:udp:67-68
```

> Note: the default protocole is `icmp`, it's equivalent of `192.168.0.1-192.168.56.255:icmp`.

This scan performs a `ICMP` scan on the first IP range and `UDP` scan on the second IP range (on port 67 and 68).

> Note: It's better for optimization to use a range of port instead of a list of port ranges (`67-68` instead of `67,68`).

#### Multiples IP range

```bash
./scan -w=100 192.168.0.1/24,192.168.56.1/255.255.255.240:tcp:1-1024
```

### Options

#### Timeout

```bash
./scan -w=100 -t=3 192.168.0.1/24,192.168.56.1/255.255.255.240:tcp:1-1024
```

Set timeout to 3 seconds (instead of 1 second by default).

#### Workers

Workers should alway be set, it's necessary to adapt the value with your computer resources (by default 3000 on Windows, but on a VM Windows i needed set it to 100, by default on Linux is 1000).

```bash
./scan -w=1000 192.168.0.1/24,192.168.56.1/255.255.255.240:tcp:1-1024
```

#### Print

Print all (maximum verbosity):

```bash
./scan -w=100 -a 192.168.0.1/24,192.168.56.1/255.255.255.240:tcp:1-1024
```

Print filtered:

```bash
./scan -w=100 -f 192.168.0.1/24,192.168.56.1/255.255.255.240:tcp:1-1024
```

Print close:

```bash
./scan -w=100 -c 192.168.0.1/24,192.168.56.1/255.255.255.240:tcp:1-1024
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
