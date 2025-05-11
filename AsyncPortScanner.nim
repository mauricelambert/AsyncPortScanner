#    Cross-platform asynchronous port scanner written in Nim.
#    Copyright (C) 2023, 2024, 2025  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# To compile on windows with nim 2.0.8:
# nim.exe c --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:windows AsyncPortScanner.nim
# Adding static library (useful to start it on Windows Server):
# nim.exe c --passl:"-static -static-libgcc -static-libstdc++" --opt:size --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:windows AsyncPortScanner.nim

# To compile on windows with nim 1.6.14:
# nim c --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:linux AsyncPortScanner.nim

import asyncnet, asyncdispatch, net, strutils, parseopt, system, sequtils, math, tables
when defined(windows):
    import winim/lean
when defined(linux):
    import posix

type
    NetworkGenerator = object
        current_ip: uint32
        current_port: uint16
        protocol: uint8
        start_ip: uint32
        end_ip: uint32
        start_port: uint16
        end_port: uint16
        empty: bool

    IpState = enum
        not_checked = 0, in_arptable = 1, not_in_arptable = 2, not_local_ip = 3

type RefNetworkGenerator = ref NetworkGenerator
type IpStartEnd = tuple[start_ip: string, end_ip: string]
type NetworkStartEnd = tuple[start_ip: uint32, end_ip: uint32]
type PortStartEnd = tuple[start_port: uint16, end_port: uint16]

var
    print_all = false
    timeout = 1 * 1000
    print_close = false
    print_filtered = false
    networks = newSeq[NetworkStartEnd]()
    ip_used = initTable[uint64, IpState]()

proc ip_ranges_to_network(ip_ranges: string): seq[NetworkStartEnd]

proc isPositiveInteger(s: string): bool =
  s.len > 0 and s.all(isDigit)

proc int_to_ip(ip: uint32): string =
    return $((ip shr 24) and 0xFF) & "." & $((ip shr 16) and 0xFF) & "." & $((ip shr 8) and 0xFF) & "." & $(ip and 0xFF)

proc ip_to_int(ip: string): uint32 =
    var returns: int

    if isPositiveInteger(ip):
        returns = ip.parseInt()
        if returns > 0 and returns <= 0xffffffff:
            return uint32(returns)
        else:
            raise newException(ValueError, "Invalid IP address format: " & ip)

    let parts = ip.split('.')
    if parts.len != 4:
        raise newException(ValueError, "Invalid IP address format: " & ip)

    var shift = 24
    for i, temp_string in parts:
        if not isPositiveInteger(temp_string):
            raise newException(ValueError, "Invalid IP address format: " & ip)
        var temp_int = temp_string.parseInt()
        if temp_int > 255:
            raise newException(ValueError, "Invalid IP address format: " & ip)
        returns += temp_int shl shift
        shift -= 8
     
    return uint32(returns)

when defined(windows):
    const
        NO_ERROR = 0
        ERROR_INSUFFICIENT_BUFFER = 122

    type
      MIB_IPNETROW* {.packed.} = object
        dwIndex*: uint32
        dwPhysAddrLen*: uint32
        bPhysAddr*: array[8, uint8]
        dwAddr*: uint32
        dwType*: uint32

      MIB_IPNETTABLE* {.packed.} = object
        dwNumEntries*: uint32
        table*: UncheckedArray[MIB_IPNETROW]

      IP_ADDR_STRING* = object
        Next: ptr IP_ADDR_STRING
        IpAddress: array[16, char]
        IpMask: array[16, char]
        Context: uint32

      IP_ADAPTER_INFO* = object
        Next: ptr IP_ADAPTER_INFO
        ComboIndex: uint32
        AdapterName: array[260, char]
        Description: array[132, char]
        AddressLength: uint32
        Address: array[8, byte]
        Index: uint32
        Type: uint32
        DhcpEnabled: uint32
        CurrentIpAddress: ptr IP_ADDR_STRING
        IpAddressList: IP_ADDR_STRING
        GatewayList: IP_ADDR_STRING
        DhcpServer: IP_ADDR_STRING
        HaveWins: bool
        PrimaryWinsServer: IP_ADDR_STRING
        SecondaryWinsServer: IP_ADDR_STRING
        LeaseObtained: int64
        LeaseExpires: int64

    proc GetAdaptersInfo(lpAdapterInfo: ptr IP_ADAPTER_INFO; pOutBufLen: ptr uint32): int32 {.stdcall, dynlib: "iphlpapi.dll", importc.}
    proc GetIpNetTable*(pIpNetTable: ptr MIB_IPNETTABLE, pdwSize: ptr uint32, bOrder: uint32): int32 {.cdecl, dynlib: "iphlpapi.dll", importc.}

    proc check_ip_in_arp_cache(ip: uint32): bool =
      var table_size: uint32 = 0
      var net_table_return = GetIpNetTable(nil, addr table_size, 0)
      if net_table_return == ERROR_INSUFFICIENT_BUFFER:
        var table_pointer: ptr MIB_IPNETTABLE
        table_pointer = cast[ptr MIB_IPNETTABLE](alloc(table_size))
        defer: dealloc(table_pointer)

        net_table_return = GetIpNetTable(table_pointer, addr table_size, 0)
        if net_table_return == NO_ERROR:
          for i in 0..<int(table_pointer.dwNumEntries):
            if table_pointer.table[i].dwAddr == uint32(ip):
              return true
      return false

    proc getIPv4andNetmask(): string =
      var output = "-w=3000"
      var size: uint32
      var error_code = GetAdaptersInfo(nil, addr size)
      if error_code != 111:
        return ""

      let adapterInfo = cast[ptr IP_ADAPTER_INFO](alloc(size))

      error_code = GetAdaptersInfo(adapterInfo, addr size)
      if error_code == 0:
        var adapter: ptr IP_ADAPTER_INFO = adapterInfo
        while adapter != nil:
          let ipAddr = cast[cstring](adapter.IpAddressList.IpAddress.addr)
          let ipMask = cast[cstring](adapter.IpAddressList.IpMask.addr)

          if ipAddr[0] != '\0':
            if ip_to_int($ipAddr) != 0 and ip_to_int($ipMask) != 0:
                let network_repr = $ipAddr & "/" & $ipMask
                networks.add(ip_ranges_to_network(network_repr)[0])
                output = output & " " & network_repr & ":tcp:21-25,135-139,80,443-445,3000,3389,5000-5357,8000-8888,30102"
          adapter = adapter.Next
      return output

when defined(linux):
    type
      sockaddr_in = ref object
        sin_family: Domain
        sin_port: uint16
        sin_addr: array[4, uint8]
        sin_zero: array[8, uint8]

      sockaddr {.importc: "struct sockaddr", header: "<sys/socket.h>", pure, final.} = object
        sa_family: uint16
        sa_data: array[14, char]

      ifaddrs {.importc: "struct ifaddrs", header: "<ifaddrs.h>".} = object
        ifa_next: ref ifaddrs
        ifa_name: cstring
        ifa_flags: uint32
        ifa_addr: ref sockaddr
        ifa_netmask: ref sockaddr
        ifa_ifu: ref sockaddr
        ifa_data: ptr uint

    proc getifaddrs(ifap: ptr ref ifaddrs): cint {.importc: "getifaddrs", dynlib: "c", header: "<ifaddrs.h>" .}
    proc freeifaddrs(ifap: ref ifaddrs) {.importc: "freeifaddrs", dynlib: "c", header: "<ifaddrs.h>" .}

    proc check_ip_in_arp_cache(ip: uint32): bool =
      let ip_address = int_to_ip(ip)
      let arp_table = readFile("/proc/net/arp")
      for line in arp_table.splitLines():
        let columns = line.splitWhitespace()
        if columns.len > 0 and columns[0] == ip_address:
          return true
      return false

    proc sockaddrToIP(address: ref sockaddr): string =
      var output = ""
      if address.sa_family == uint16(Domain.AF_INET):
        if address.sa_data[2] != '\x7f':
            output = $int(address.sa_data[2]) & "." & $int(address.sa_data[3]) & "." & $int(address.sa_data[4]) & "." & $int(address.sa_data[5])
      return output

    proc setMaxFileDescriptors(workers: uint64): uint64 =
      var rl: Rlimit
      let resource = RLIMIT_NOFILE

      if getrlimit(resource, rl) != 0:
        return 1024'u64

      if rl.rlim_cur < 0 or rl.rlim_max < 0:
        return 1024'u64

      let max_soft: uint64 = uint64(rl.rlim_cur)

      if workers > uint64(rl.rlim_max):
        rl.rlim_cur = 65535
      else:
        rl.rlim_cur = int(workers)

      if setrlimit(resource, rl) != 0:
        return max_soft

      return uint64(rl.rlim_cur)

    proc getIPv4Addresses(worker_number: uint64): string =
      var output = "-w=" & $worker_number
      var ifaddr: ref ifaddrs
      if getifaddrs(addr(ifaddr)) != 0:
        echo "Error getting interface addresses."
        return

      var current: ref ifaddrs = ifaddr
      while current != nil:
        if current.ifa_addr != nil and current.ifa_netmask != nil:
          let ipAddr = sockaddrToIP(current.ifa_addr)
          let netmaskAddr = sockaddrToIP(current.ifa_netmask)

          if ipAddr.len > 0 and netmaskAddr.len > 0:
            let network_repr = $ipAddr & "/" & $netmaskAddr
            networks.add(ip_ranges_to_network(network_repr)[0])
            output = output & " " & network_repr & ":tcp:21-25,135-139,80,443-445,3000,3389,5000-5357,8000-8888,30102"

        current = current.ifa_next

      freeifaddrs(ifaddr)
      return output

proc construct(start_ip: string, end_ip: string, start_port: uint16, end_port: uint16, protocol: string): RefNetworkGenerator =
    var protocol_int: uint8

    if protocol == "tcp":
        protocol_int = 6
    elif protocol == "udp":
        protocol_int = 17
    elif protocol == "icmp":
        protocol_int = 1

    let start_ip_int = ip_to_int(start_ip)

    return RefNetworkGenerator(
        current_ip: start_ip_int,
        current_port: start_port,
        protocol: protocol_int,
        start_ip: start_ip_int,
        end_ip: ip_to_int(end_ip),
        start_port: start_port,
        end_port: end_port,
        empty: false
    )

proc next(self: RefNetworkGenerator): uint64 =
    let returns: uint64 = self.protocol + uint64(self.current_port) shl 8 + uint64(self.current_ip) shl 24

    if self.current_ip == self.end_ip:
        self.current_ip = self.start_ip
        if self.current_port == self.end_port:
            self.empty = true
        else:
            self.current_port += 1
    else:
        self.current_ip += 1

    return returns

proc test_tcp(ip: string, port: uint16): Future[void] {.async.} =
    var
        state = "filtered"
        no_timeout: bool
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_STREAM)
    try:
        no_timeout = await withTimeout(socket.connect(ip, Port(port)), timeout)
        if no_timeout:
            state = "open"
    except OSError:
        state = "close"
    finally:
        if not socket.isClosed:
          try:
            socket.close()
          except OSError:
            state = "close"

    if print_all or state == "open" or (print_filtered and state == "filtered") or (print_close and state == "close"):
        echo "IP: " & ip & ", port: " & $port & "/tcp, state: " & state

proc test_udp(ip: string, port: uint16): Future[void] {.async.} =
    var
        state = "open/filtered"
        no_timeout: bool
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)
    try:
        await socket.sendTo(ip, Port(port), "")
        no_timeout = await withTimeout(socket.recvFrom(1024), timeout)
        if no_timeout:
            state = "open"
    except OSError:
        state = "close"
    finally:
        if not socket.isClosed:
          socket.close()

    if print_all or state == "open" or state == "open/filtered" or (print_close and state == "close"):
        echo "IP: " & ip & ", port: " & $port & "/udp, state: " & state

proc test_icmp(ip: string): Future[void] {.async.} =
    var
        state = "down"
        no_timeout: bool
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_RAW, Protocol.IPPROTO_ICMP)
    try:
        await socket.sendTo(ip, Port(0), "\x08\x00K\xba\x00\x01\x01\xa1abcdefghijklmnopqrstuvwabcdefghi")
        no_timeout = await withTimeout(socket.recvFrom(1024), timeout)
        if no_timeout:
            state = "up"
    except OSError:
        discard
    finally:
        if not socket.isClosed:
          socket.close()

    if state == "up" or print_all  or (print_close and state == "down"):
        echo "IP: " & ip & "/icmp, state: " & state

proc test_connection(self: RefNetworkGenerator): Future[void] {.async.} =
    let next = self.next()
    let
        protocol: uint8 = uint8(next and 0xff)
        port: uint16 = uint16(next shr 8 and 0xffff)
        ip_int: uint32 = uint32(next shr 24 and uint64(0xffffffff))
        ip: string = int_to_ip(ip_int)

    if not ip_used.hasKey(ip_int):
        ip_used[ip_int] = IpState.not_local_ip
        for i in 0 ..< networks.len:
            let network = networks[i]
            if ip_int >= network.start_ip and ip_int <= network.end_ip:
                ip_used[ip_int] = IpState.not_checked

    if ip_used[ip_int] == IpState.not_in_arptable:
        return

    if protocol == 6:
        await test_tcp(ip, port)
    elif protocol == 17:
        await test_udp(ip, port)
    elif protocol == 1:
        await test_icmp(ip)

    if ip_used[ip_int] == IpState.not_checked:
        if check_ip_in_arp_cache(ip_int):
            ip_used[ip_int] = IpState.in_arptable
        else:
            ip_used[ip_int] = IpState.not_in_arptable

proc first_loop(generator: RefNetworkGenerator): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    while generator.current_ip != generator.end_ip:
        futures.add(generator.test_connection())
    await all(futures)

proc scan(generators: seq[RefNetworkGenerator]): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    for i in 0 ..< generators.len:
        let generator: RefNetworkGenerator = generators[i]
        await first_loop(generator)
        while not generator.empty:
            futures.add(generator.test_connection())
    await all(futures)

proc first_shared_loop(generator: RefNetworkGenerator, workers: uint64, id: uint64): Future[void] {.async.} =
    for i in 0..(generator.end_ip - generator.start_ip):
        if (i mod workers) == id:
            await generator.test_connection()

proc worker_scan(generators: seq[RefNetworkGenerator], workers: uint64, id: uint64): Future[void] {.async.} =
    for i in 0 ..< generators.len:
        var generator: RefNetworkGenerator = generators[i]
        if not generator.empty:
            await first_shared_loop(generator, workers, id)
        while not generator.empty:
            await generator.test_connection()

proc workers_scan(generators: seq[RefNetworkGenerator], workers: uint64): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    for i in 0 ..< workers:
        futures.add(worker_scan(generators, workers, i))
    await all(futures)

proc argument_to_int(key: string, value: string, maximum: uint64, minimum: uint64): (uint64, bool) =
    var int_value: uint64 = 0
    try:
        int_value = uint64(parseInt(value))
    except ValueError:
        stderr.writeLine("Error: " & key & " should be a valid integer (not " & value & ")")
        return (1, true)
    if maximum != minimum:
        if int_value > minimum and int_value < maximum:
            return (int_value, false)
        else:
            stderr.writeLine("Error: " & key & " should be between " & $minimum & " and " & $maximum & "(not " & value & ")")
            return (int_value, true)
    return (int_value, false)

proc check_network_mask(mask: uint32): bool =
    let invers_mask = not(mask)
    return (invers_mask and (invers_mask + 1)) == 0

proc get_network_mask(base_mask_string: string): uint32 =
    var mask: uint32

    if base_mask_string.contains('.'):
        mask = ip_to_int(base_mask_string)
    else:
        if not isPositiveInteger(base_mask_string):
            raise newException(ValueError, "Invalid network mask format: " & base_mask_string)
        let base_mask = base_mask_string.parseInt()
        if base_mask > 32:
            raise newException(ValueError, "Invalid network mask format: " & base_mask_string)
        mask = uint32((2 ^ base_mask - 1) shl (32 - base_mask))

    if check_network_mask(mask):
        return mask

    raise newException(ValueError, "Invalid network mask value: " & base_mask_string & " " & $mask)

proc ip_ranges_to_network(ip_ranges: string): seq[NetworkStartEnd] =
    var networks: seq[NetworkStartEnd] = @[]

    for ip_range in ip_ranges.split(','):
        var network: NetworkStartEnd
        if ip_range.contains('/'):
            
            let base = ip_range.split('/', maxsplit=1)
            let 
                base_ip_string = base[0]
                base_mask_string = base[1]

            let mask = get_network_mask(base_mask_string)
            let base_ip = ip_to_int(base_ip_string)
            network = (start_ip: (base_ip and mask), end_ip: (base_ip or (mask xor uint32(0xffffffff))))

        elif ip_range.contains('-'):
            let parts = ip_range.split('-')

            if len(parts) != 2:
                raise newException(ValueError, "Invalid IP range format: " & ip_range)

            if parts[1].contains('.'):
                network = (start_ip: ip_to_int(parts[0]), end_ip: ip_to_int(parts[1]))
            else:
                network = (start_ip: ip_to_int(parts[0]), end_ip: ip_to_int(parts[0].rsplit('.', maxsplit=1)[0] & "." & parts[1]))
        else:
            network = (start_ip: ip_to_int(ip_range), end_ip: ip_to_int(ip_range))

        networks.add(network)

    return networks

proc ip_ranges_to_startend(ip_ranges: string): seq[IpStartEnd] =
    var ips_ranges: seq[IpStartEnd] = @[]

    for network in ip_ranges_to_network(ip_ranges):
        var ipstartend: IpStartEnd
        ipstartend = (start_ip: int_to_ip(network.start_ip), end_ip: int_to_ip(network.end_ip))
        ips_ranges.add(ipstartend)

    return ips_ranges

proc port_ranges_to_startend(port_ranges: string): seq[PortStartEnd] =
    var ports_ranges: seq[PortStartEnd] = @[]

    for port_range in port_ranges.split(','):
        var portstartend: PortStartEnd
        if port_range.contains('-'):

            let parts = port_range.split('-')
            if not isPositiveInteger(parts[0]) or not isPositiveInteger(parts[1]):
                raise newException(ValueError, "Invalid port range format: " & port_range)
            let start_port = parts[0].parseInt()
            let end_port = parts[1].parseInt()
            if start_port > 0xffff or end_port > 0xffff:
                raise newException(ValueError, "Invalid port range format: " & port_range)
            portstartend = (start_port: uint16(start_port), end_port: uint16(end_port))

        else:
            if not isPositiveInteger(port_range):
                raise newException(ValueError, "Invalid port range format: " & port_range)

            let start_port = port_range.parseInt()

            if start_port > 0xffff:
                raise newException(ValueError, "Invalid port range format: " & port_range)

            portstartend = (start_port: uint16(start_port), end_port: uint16(start_port))

        ports_ranges.add(portstartend)

    return ports_ranges


proc ranges_string_to_generators(full_ranges: string, scan_range: var seq[RefNetworkGenerator]): bool =
    let parts = full_ranges.split(':')
    if len(parts) == 1:
        for startend in ip_ranges_to_startend(parts[0]):
            scan_range.add(construct(startend[0], startend[1], 0, 0, "icmp"))
    elif len(parts) == 3:
        for ip_startend in ip_ranges_to_startend(parts[0]):
            for port_startend in port_ranges_to_startend(parts[2]):
                scan_range.add(construct(ip_startend[0], ip_startend[1], port_startend[0], port_startend[1], parts[1]))
    return false

proc parse_args(commandline: string): tuple[generators: seq[RefNetworkGenerator], workers: uint64, error: bool] =
    var
        error = false
        workers: uint64 = 0
        local_timeout: uint64 = 0 
        scan_range = newSeq[RefNetworkGenerator]()

    var parser = initOptParser(commandline)
    for kind, key, value in parser.getopt():
        case kind
            of cmdEnd: break
            of cmdShortOption, cmdLongOption:
                case key:
                    of "w", "workers":
                        (workers, error) = argument_to_int("[-w/--workers]", value, 0, 0)
                    of "f", "filtered", "print-filtered":
                        print_filtered = true
                    of "a", "all", "print-all":
                        print_all = true
                    of "c", "close", "print-close":
                        print_close = true
                    of "t", "timeout":
                        (local_timeout, error) = argument_to_int("[-t/--timeout]", value, 0, 0)
                        timeout = int(local_timeout) * 1000
                    else:
                        stderr.writeLine("Error: invalid option: ", key, " (", value, ")")
                        error = true
            of cmdArgument:
                error = ranges_string_to_generators(key, scan_range)
        if error:
            break

    return (scan_range, workers, error)

proc usages(): uint64 =
    stderr.writeLine("Usages: scan [-t/--timeout] [-w/--workers=integer] [-f/--filtered/--print-filtered] [-c/--close/--print-close] [-a/--all/--print-all] scan-range1 scan-range2 ... scan-rangeN")
    stderr.writeLine("\tscan 127.0.0.1:tcp:20-445")
    stderr.writeLine("\tscan -t=3 -w=3000 -a 192.168.0.1-254,172.16.0.0-172.16.255.254,10.0.0.0/8:icmp 192.168.0.1-254,172.16.0.0-172.16.255.254,10.0.0.0/255.0.0.0:tcp:20-445 192.168.0.1-254,172.16.0.0-172.16.255.254,10.0.0.0/8:udp:53,68,5353,5355")
    return 1

proc main(): uint64 =
    var commandline: string = ""
    var (generators, workers, error) = parse_args(commandline)
    when defined(linux):
        if workers == 0:
            workers = setMaxFileDescriptors(1024'u64)
        else:
            workers = setMaxFileDescriptors(workers + 5)
        workers = workers - 5

    when defined(windows):
        commandline = getIPv4andNetmask()
    when defined(linux):
        commandline = getIPv4Addresses(workers)

    if generators.len == 0:
        (generators, workers, error) = parse_args(commandline)

    if error or generators.len == 0:
        return usages()

    if workers == 0:
        waitFor scan(generators)
    else:
        waitFor workers_scan(generators, workers)
    return 0

system.quit(int(main()))
