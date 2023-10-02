# AsyncPortScanner

## Description

Cross-platform asynchronous port scanner written in Nim.

## Requirements

 - No requirements

## Download

 - https://github.com/mauricelambert/AsyncPortScanner/releases

## Compilation

```bash
nim c --stackTrace:off --lineTrace:off --checks:off --assertions:off -d:release AsyncPortScanner.nim
```

## Usages

```bash
./scan 127.0.0.1
./scan --first=135 --last=1024 127.0.0.1
./scan -f=135 -l=1024 10.10.10.1 127.0.0.1
./scan --first-port=135 --last-port=1024 127.0.0.1
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
