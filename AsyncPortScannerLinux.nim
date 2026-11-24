#    Cross-platform asynchronous port scanner written in Nim.
#    Copyright (C) 2023-2026  Maurice Lambert

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
# nim c --os:linux --cpu:amd64 --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d:linux AsyncPortScanner.nim

import std/[asyncnet, asyncdispatch, net, strutils, parseopt, sequtils, math, tables, times, nativesockets]
import system
when defined(windows):
    import winim/lean
when defined(linux):
    import posix

type
    IpEntryKind = enum
        SingleIp,
        IpRange

    PortEntryKind = enum
        SinglePort,
        PortRange

    IpEntry = object
        case kind: IpEntryKind
        of SingleIp:
          ip: uint32
        of IpRange:
          start_ip: uint32
          end_ip: uint32

    PortEntry = object
        case kind: PortEntryKind
        of SinglePort:
          port: uint16
        of PortRange:
          start_port: uint16
          end_port: uint16

    IpGenerator = object
        ips: seq[IpEntry]
        current_ip_index: uint32
        sub_current_ip_index: uint32
        size: uint64

    RefIpGenerator = ref IpGenerator

    PortGenerator = object
        ports: seq[PortEntry]
        current_port_index: uint32
        sub_current_port_index: uint16
        size: uint64

    RefPortGenerator = ref PortGenerator

    ScanGenerator = object
        ip_generator: RefIpGenerator
        port_generator: RefPortGenerator
        protocol: uint8
        size: uint64
        current_index: uint64

    RefScanGenerator = ref ScanGenerator

    GlobalScanGenerator = object
        scans: seq[RefScanGenerator]
        size: uint64
        current_scan_index: uint32
        current_index: uint64

    RefGlobalScanGenerator = ref GlobalScanGenerator

    UniqueRandom = object
        minimum: uint64
        n: uint64
        a: uint64
        b: uint64
        index: uint64

    RefUniqueRandom = ref UniqueRandom

    IpState = enum
        not_checked = 0, in_arptable = 1, not_in_arptable = 2, not_local_ip = 3, self_ip = 4

    IpStartEnd = tuple[start_ip: uint64, end_ip: uint64]
    NetworkStartEnd = tuple[start_ip: uint32, end_ip: uint32]
    PortStartEnd = tuple[start_port: uint16, end_port: uint16]
    StopIteration = object of CatchableError

var
    tests = 0
    opens = 0
    errors = 0
    cancels = 0
    random = true
    optimized = true
    print_all = false
    timeout = 1 * 1000
    print_close = false
    print_filtered = false
    self_ips = newSeq[uint32]()
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
      HANDLE = int
      DWORD = int32
      PULONG = ptr int

      OVERLAPPED {.pure, inheritable.} = object
        internal: PULONG
        internalHigh: PULONG
        offset: DWORD
        offsetHigh: DWORD
        hEvent: HANDLE

      POVERLAPPED = ptr OVERLAPPED

      MIB_IPNETROW {.packed.} = object
        dwIndex: uint32
        dwPhysAddrLen: uint32
        bPhysAddr: array[8, uint8]
        dwAddr: uint32
        dwType: uint32

      MIB_IPNETTABLE {.packed.} = object
        dwNumEntries: uint32
        table: UncheckedArray[MIB_IPNETROW]

      IP_ADDR_STRING = object
        Next: ptr IP_ADDR_STRING
        IpAddress: array[16, char]
        IpMask: array[16, char]
        Context: uint32

      IP_ADAPTER_INFO = object
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

    proc CancelIoEx(hFile: HANDLE, lpOverlapped: POVERLAPPED): WINBOOL {.stdcall, dynlib: "kernel32", importc: "CancelIoEx".}
    proc GetAdaptersInfo(lpAdapterInfo: ptr IP_ADAPTER_INFO; pOutBufLen: ptr uint32): int32 {.stdcall, dynlib: "iphlpapi.dll", importc.}
    proc GetIpNetTable(pIpNetTable: ptr MIB_IPNETTABLE, pdwSize: ptr uint32, bOrder: uint32): int32 {.cdecl, dynlib: "iphlpapi.dll", importc.}

    proc swap_ip(ip: uint32): uint32 =
        ((ip and 0x000000FF'u32) shl 24) or
        ((ip and 0x0000FF00'u32) shl 8) or
        ((ip and 0x00FF0000'u32) shr 8) or
        ((ip and 0xFF000000'u32) shr 24)

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
            if swap_ip(table_pointer.table[i].dwAddr) == ip and (table_pointer.table[i].dwType == 3 or table_pointer.table[i].dwType == 4):
              return true
      return false

    proc getIPv4andNetmask(): string =
      var output = "-w=100"
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
                self_ips.add(ip_to_int($ipAddr))
                networks.add(ip_ranges_to_network(network_repr)[0])
                output = output & " " & network_repr & ":tcp:21-25,53,80,110-143,389,443-465,587,631-636,993-995,1433-1434,1521,3000,3306,3389,5000-5357,5432,6001,6379,7474,7547,7687,8000-8888,27017"
          adapter = adapter.Next
      return output

when defined(linux):
    const FIONREAD_LINUX = culong(0x541B)
    type
      sockaddr_in = ref object
        sin_family: Domain
        sin_port: uint16
        sin_addr: array[4, uint8]
        sin_zero: array[8, uint8]

      sockaddr {.importc: "struct sockaddr", header: "<sys/socket.h>", pure, final.} = object
        sa_family: uint16
        sa_data: array[14, char]

      # ifaddrs {.importc: "struct ifaddrs", header: "<ifaddrs.h>".} = object
      #   ifa_next: ref ifaddrs
      #   ifa_name: cstring
      #   ifa_flags: uint32
      #   ifa_addr: ref sockaddr
      #   ifa_netmask: ref sockaddr
      #   ifa_ifu: ref sockaddr
      #   ifa_data: ptr uint

      ifaddrs {.importc: "struct ifaddrs", header: "<ifaddrs.h>".} = object
        ifa_next: ptr ifaddrs
        ifa_name: cstring
        ifa_flags: uint32
        ifa_addr: ptr sockaddr
        ifa_netmask: ptr sockaddr
        ifa_ifu: ptr sockaddr
        ifa_data: ptr uint

    # proc getifaddrs(ifap: ptr ref ifaddrs): cint {.importc: "getifaddrs", dynlib: "c", header: "<ifaddrs.h>" .}
    # proc freeifaddrs(ifap: ref ifaddrs) {.importc: "freeifaddrs", dynlib: "c", header: "<ifaddrs.h>" .}

    proc getifaddrs(ifap: ptr ptr ifaddrs): cint {.importc, header: "<ifaddrs.h>".}
    proc freeifaddrs(ifap: ptr ifaddrs) {.importc, header: "<ifaddrs.h>".}
    proc ioctl3(fd: cint, request: culong, arg: pointer): cint {.importc: "ioctl", header: "<sys/ioctl.h>", varargs.}

    proc check_ip_in_arp_cache(ip: uint32): bool =
      let ip_address = int_to_ip(ip)
      let arp_table = readFile("/proc/net/arp")
      for line in arp_table.splitLines():
        let columns = line.splitWhitespace()
        if columns.len > 0 and columns[0] == ip_address and columns[2] != "0x0":
          return true
      return false

    # proc sockaddrToIP(address: ref sockaddr): string =
    proc sockaddrToIP(address: ptr sockaddr): string =
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
      var ifaddr: ptr ifaddrs
      if getifaddrs(addr(ifaddr)) != 0:
        echo "Error getting interface addresses."
        return

      var current: ptr ifaddrs = ifaddr
      while current != nil:
        if current.ifa_addr != nil and current.ifa_netmask != nil:
          let ipAddr = sockaddrToIP(current.ifa_addr)
          let netmaskAddr = sockaddrToIP(current.ifa_netmask)

          if ipAddr.len > 0 and netmaskAddr.len > 0:
            let network_repr = $ipAddr & "/" & $netmaskAddr
            self_ips.add(ip_to_int($ipAddr))
            networks.add(ip_ranges_to_network(network_repr)[0])
            output = output & " " & network_repr & ":tcp:21-25,53,80,110-143,389,443-465,587,631-636,993-995,1433-1434,1521,3000,3306,3389,5000-5357,5432,6001,6379,7474,7547,7687,8000-8888,27017"

        current = current.ifa_next

      freeifaddrs(ifaddr)
      return output

proc constructUniqueRandom(minimum: uint64, maximum: uint64, key: uint64 = 123456789): RefUniqueRandom =
    let n = maximum - minimum
    var a = key or 1'u64
    if n == 0:
        return RefUniqueRandom()
    while gcd(a, n) != 1:
        a += 2
    return RefUniqueRandom(minimum: minimum, n: n, a: a, b: (key * 6364136223846793005'u64) mod n)

proc get(self: RefUniqueRandom, index: uint64): uint64 =
    if self.n == 0 and index == 0: return self.minimum
    if index >= self.n:
        raise newException(StopIteration, "All values returned")
    self.minimum + (self.a * index + self.b) mod self.n

proc infinite_get(self: RefUniqueRandom, index: uint64): uint64 =
    if self.n == 0: return self.minimum
    self.minimum + (self.a * index + self.b) mod self.n

proc has_next(self: RefUniqueRandom): bool =
    if self.n == 0 and self.index == 0: return true
    if self.index >= self.n:
        return false
    return true

proc next(self: RefUniqueRandom): uint64 =
    if self.n == 0 and self.index == 0:
        self.index += 1
        return self.minimum
    if self.index >= self.n:
        raise newException(StopIteration, "All values returned")
    result = self.minimum + (self.a * self.index + self.b) mod self.n
    self.index += 1

proc add_ips(self: RefIpGenerator, start_ip: uint32, end_ip: uint32): uint64 =
    if end_ip == 0:
        self.ips.add(IpEntry(kind: SingleIp, ip: start_ip))
        self.size += 1
        return 1
    self.ips.add(IpEntry(kind: IpRange, start_ip: start_ip, end_ip: end_ip))
    let count = end_ip - start_ip + 1
    self.size += count
    return count

proc find_ip(self: RefIpGenerator, index: uint32): uint32 =
    var remaining = index

    for entry in self.ips:
        case entry.kind:
        of SingleIp:
            if remaining == 0:
                return entry.ip
            remaining -= 1
        of IpRange:
            let count = entry.end_ip - entry.start_ip + 1
            if remaining < count:
                return entry.start_ip + remaining
            remaining -= count

    raise newException(IndexDefect, "IP index out of bounds (" & $index & "/" & $self.size & ")")

proc next_ip(self: RefIpGenerator): uint32 =
    if self.current_ip_index >= uint32(self.ips.len):
        raise newException(IndexDefect, "No more IPs")

    let entry = self.ips[self.current_ip_index]

    case entry.kind:
    of SingleIp:
        result = entry.ip
        self.current_ip_index += 1
        self.sub_current_ip_index = 0
    of IpRange:
        result = entry.start_ip + self.sub_current_ip_index
        if result == entry.end_ip:
            self.current_ip_index += 1
            self.sub_current_ip_index = 0
        else:
            self.sub_current_ip_index += 1

proc has_next(self: RefIpGenerator): bool =
    if self.current_ip_index >= uint32(self.ips.len):
        return false
    return true

proc add_ports(self: RefPortGenerator, start_port: uint16, end_port: uint16): uint64 =
    if end_port == 0:
        self.ports.add(PortEntry(kind: SinglePort, port: start_port))
        self.size += 1
        return 1
    self.ports.add(PortEntry(kind: PortRange, start_port: start_port, end_port: end_port))
    let count = end_port - start_port + 1
    self.size += count
    return count

proc find_port(self: RefPortGenerator, index: uint32): uint16 =
    var remaining = index

    for entry in self.ports:
        case entry.kind:
        of SinglePort:
            if remaining == 0:
                return entry.port
            remaining -= 1
        of PortRange:
            let count = entry.end_port - entry.start_port + 1
            if remaining < count:
                return entry.start_port + uint16(remaining)
            remaining -= count

    raise newException(IndexDefect, "Port index out of bounds (" & $index & "/" & $self.size & ")")

proc next_port(self: RefPortGenerator): uint16 =
    if self.current_port_index >= uint32(self.ports.len):
        raise newException(IndexDefect, "No more ports")

    let entry = self.ports[self.current_port_index]

    case entry.kind:
    of SinglePort:
        result = entry.port
        self.current_port_index += 1
        self.sub_current_port_index = 0
    of PortRange:
        result = entry.start_port + self.sub_current_port_index
        if result == entry.end_port:
            self.current_port_index += 1
            self.sub_current_port_index = 0
        else:
            self.sub_current_port_index += 1

proc has_next(self: RefPortGenerator): bool =
    if self.current_port_index >= uint32(self.ports.len):
        return false
    return true

proc add_connections(self: RefScanGenerator, ip_generator: RefIpGenerator, port_generator: RefPortGenerator): uint64 =
    self.ip_generator = ip_generator
    self.port_generator = port_generator
    result = ip_generator.size * port_generator.size
    self.size += result

proc find_connection(self: RefScanGenerator, index: uint64): uint64 =
    if index >= self.size:
        raise newException(IndexDefect, "Connection index out of bounds (" & $index & "/" & $self.size & ")")

    let ip_count = self.ip_generator.size
    let ip_index = index mod ip_count
    let port_index = index div ip_count
    let ip = self.ip_generator.find_ip(uint32(ip_index))
    let port = self.port_generator.find_port(uint32(port_index))

    return uint64(self.protocol) + (uint64(port) shl 8) + (uint64(ip) shl 24)

proc has_next(self: RefScanGenerator): bool =
    if self.current_index >= self.size:
        return false
    return true

proc next_connection(self: RefScanGenerator): uint64 =
    if self.current_index >= self.size:
        raise newException(IndexDefect, "No more connection combinations")
    result = self.find_connection(self.current_index)
    self.current_index += 1

proc add_scans(self: RefGlobalScanGenerator, scan: RefScanGenerator): uint64 =
    self.scans.add(scan)
    self.size += scan.size
    return scan.size

proc find_scan(self: RefGlobalScanGenerator, index: uint64): uint64 =
    if index >= self.size:
        raise newException(IndexDefect, "Scan index out of bounds (" & $index & "/" & $self.size & ")")

    var remaining = index
    for scan in self.scans:
        if remaining < scan.size:
            return scan.find_connection(remaining)
        remaining -= scan.size

    raise newException(IndexDefect, "Scan index out of bounds (" & $index & "/" & $self.size & ")")

proc next_scan(self: RefGlobalScanGenerator): uint64 =
    while self.current_scan_index < uint32(self.scans.len):
        let scan_index = self.current_scan_index
        let scan = addr self.scans[scan_index]

        if scan[].current_index < scan[].size:
            result = scan[].next_connection()
            return
        self.current_scan_index += 1

    raise newException(IndexDefect, "No more scan combinations")

proc constructScanGenerator(ip_generator: RefIpGenerator, port_generator: RefPortGenerator, protocol: string): RefScanGenerator =
    var protocol_int: uint8
    let scan_generator: RefScanGenerator = RefScanGenerator()

    if protocol == "tcp":
        protocol_int = 6
    elif protocol == "udp":
        protocol_int = 17
    elif protocol == "icmp":
        protocol_int = 1
    else:
        raise newException(ValueError, "Protocol may be 'icmp', 'tcp' or 'udp', not: " & protocol)

    discard scan_generator.add_connections(ip_generator, port_generator)
    scan_generator.protocol = protocol_int
    return scan_generator

proc test_tcp(ip: string, port: uint16, error: bool = false): Future[string] {.async.} =
    tests += 1
    var
        state = "filtered"
        no_timeout: bool
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_STREAM)
    try:
        no_timeout = await withTimeout(socket.connect(ip, Port(port)), timeout)
        if no_timeout:
            opens += 1
            state = "open"
        else:
            when defined(windows):
                cancels += 1
                if CancelIoEx(cast[HANDLE](socket.fd.AsyncFD), cast[LPOVERLAPPED](w.wrapperSocket.additionalData)) == 0:
                    if GetLastError() == 0x490:
                        errors += 1
                        if error:
                            stderr.writeLine("Warning: Too many errors detected. Consider reducing the number of workers.")
                        socket.closed = true
                        return await test_tcp(ip, port, true)
    except OSError:
        state = "close"
    finally:
        if not socket.isClosed:
          try:
            socket.close()
          except OSError:
            state = "close"

    if print_all or state == "open" or (print_filtered and state == "filtered") or (print_close and state == "close"):
        return "IP: " & ip & ", port: " & $port & "/tcp, state: " & state
    return ""

proc test_udp(ip: string, port: uint16): Future[string] {.async.} =
    var
        state = "open/filtered"
        no_timeout: bool
        error: cint
        errorLen = SockLen(sizeof(error))
        available: cint

    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)

    try:
        await socket.connect(ip, Port(port))
    except OSError:
        return ""
    await socket.send("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")

    let fd = socket.getFd()
    for i in 0..<100:
        await sleepAsync(timeout div 100)
        if getsockopt(fd, posix.SOL_SOCKET, posix.SO_ERROR, cast[pointer](addr error), addr errorLen) == 0:
            if error != 0:
                state = "close"
                break
        if ioctl3(cint(fd), FIONREAD_LINUX, addr available) == 0:
            if available > 0:
                state = "open"
                break

    if not socket.isClosed:
      socket.close()

    if print_all or state == "open" or state == "open/filtered" or (print_close and state == "close"):
        return "IP: " & ip & ", port: " & $port & "/udp, state: " & state
    return ""

proc test_icmp(ip: string): Future[string] {.async.} =
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
        return "IP: " & ip & "/icmp, state: " & state
    return ""

proc test_connection(next: uint64): Future[void] {.async.} =
    let
        protocol: uint8 = uint8(next and 0xff)
        port: uint16 = uint16(next shr 8 and 0xffff)
        ip_int: uint32 = uint32(next shr 24 and uint64(0xffffffff))
        ip: string = int_to_ip(ip_int)

    var message: string

    if not ip_used.hasKey(ip_int):
        ip_used[ip_int] = IpState.not_local_ip
        for i in 0 ..< networks.len:
            let network = networks[i]
            if (network.end_ip == 0 and ip_int == network.start_ip) or (ip_int >= network.start_ip and ip_int <= network.end_ip):
                ip_used[ip_int] = IpState.not_checked

        for self_ip in self_ips:
            if ip_int == self_ip:
                ip_used[ip_int] = IpState.self_ip

    if ip_used[ip_int] == IpState.not_in_arptable:
        return

    if protocol == 6:
        message = await test_tcp(ip, port)
    elif protocol == 17:
        message = await test_udp(ip, port)
    elif protocol == 1:
        message = await test_icmp(ip)

    if ip_used[ip_int] == IpState.not_checked:
        if check_ip_in_arp_cache(ip_int):
            ip_used[ip_int] = IpState.in_arptable
        else:
            ip_used[ip_int] = IpState.not_in_arptable
            return

    if ip_used[ip_int] != IpState.not_in_arptable and message != "":
        echo message

proc first_random_loop(generator: RefScanGenerator): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    let time = uint64(epochTime())
    let random_ip_index = constructUniqueRandom(0, generator.ip_generator.size, time)
    let random_port_index = constructUniqueRandom(0, generator.port_generator.size, time)
    for i in 0 ..< generator.ip_generator.size:
        let connection = uint64(generator.protocol) + (uint64(generator.port_generator.find_port(uint32(random_port_index.infinite_get(uint64(i))))) shl 8) + (uint64(generator.ip_generator.find_ip(uint32(random_ip_index.get(uint64(i))))) shl 24)
        futures.add(test_connection(connection))
    await all(futures)

proc optimized_random_scan(generators: RefGlobalScanGenerator): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    for i in 0 ..< generators.scans.len:
        let generator: RefScanGenerator = generators.scans[i]
        await first_random_loop(generator)
        let random_index = constructUniqueRandom(0, generator.size, uint64(epochTime()))
        for i in 0 ..< generator.size:
            futures.add(test_connection(generator.find_connection(random_index.get(uint64(i)))))
    await all(futures)

proc random_scan(generators: RefGlobalScanGenerator): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    let random_index = constructUniqueRandom(0, generators.size, uint64(epochTime()))
    for i in 0 ..< generators.size:
        futures.add(test_connection(generators.find_scan(random_index.get(uint64(i)))))
    await all(futures)

proc first_loop(generator: RefScanGenerator): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    for i in 0 ..< generator.ip_generator.size:
        futures.add(test_connection(generator.next_connection()))
    await all(futures)

proc scan(generators: RefGlobalScanGenerator): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    for i in 0 ..< generators.scans.len:
        let generator: RefScanGenerator = generators.scans[i]
        await first_loop(generator)
        while generator.has_next():
            futures.add(test_connection(generator.next_connection()))
    await all(futures)

proc first_random_shared_loop(generator: RefScanGenerator, random_index: RefUniqueRandom, workers: uint64, id: uint64): Future[void] {.async.} =
    while random_index.has_next():
        let i = random_index.next()
        if (i mod workers) == id:
            await test_connection(generator.find_connection(i))

proc optimized_worker_random_scan(generators: RefGlobalScanGenerator, workers: uint64, id: uint64): Future[void] {.async.} =
    for i in 0 ..< generators.scans.len:
        let generator: RefScanGenerator = generators.scans[i]
        let random_index = constructUniqueRandom(0, generator.ip_generator.size, uint64(epochTime()))
        await first_random_shared_loop(generator, random_index, workers, id)
        let random_index2 = constructUniqueRandom(generator.ip_generator.size, generator.size, uint64(epochTime()))
        while random_index2.has_next():
            let i = random_index2.next()
            if (i mod workers) == id:
                await test_connection(generator.find_connection(i))

proc optimized_workers_random_scan(generators: RefGlobalScanGenerator, workers: uint64): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    for i in 0 ..< workers:
        futures.add(optimized_worker_random_scan(generators, workers, i))
    await all(futures)

proc worker_random_scan(generators: RefGlobalScanGenerator, random_index: RefUniqueRandom): Future[void] {.async.} =
    while random_index.has_next():
        await test_connection(generators.find_scan(random_index.next()))

proc workers_random_scan(generators: RefGlobalScanGenerator, workers: uint64): Future[void] {.async.} =
    var futures = newSeq[Future[void]]()
    let random_index = constructUniqueRandom(0, generators.size, uint64(epochTime()))
    for i in 0 ..< workers:
        futures.add(worker_random_scan(generators, random_index))
    await all(futures)

proc first_shared_loop(generator: RefScanGenerator, workers: uint64, id: uint64): Future[void] {.async.} =
    for i in 0 ..< generator.ip_generator.size:
        if (i mod workers) == id:
            await test_connection(generator.find_connection(uint64(i)))

proc worker_scan(generators: RefGlobalScanGenerator, workers: uint64, id: uint64): Future[void] {.async.} =
    for i in 0 ..< generators.scans.len:
        let generator: RefScanGenerator = generators.scans[i]
        generator.current_index = generator.ip_generator.size
        await first_shared_loop(generator, workers, id)
        while generator.has_next():
            await test_connection(generator.next_connection())

proc workers_scan(generators: RefGlobalScanGenerator, workers: uint64): Future[void] {.async.} =
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
            network = (start_ip: ip_to_int(ip_range), end_ip: 0)

        networks.add(network)

    return networks

proc ip_ranges_to_startend(ip_ranges: string): RefIpGenerator =
    let ips_ranges: RefIpGenerator = RefIpGenerator()
    for network in ip_ranges_to_network(ip_ranges):
        discard ips_ranges.add_ips(network.start_ip, network.end_ip)
    return ips_ranges

proc port_ranges_to_startend(port_ranges: string): RefPortGenerator =
    let ports_ranges: RefPortGenerator = RefPortGenerator()

    for port_range in port_ranges.split(','):
        if port_range.contains('-'):
            let parts = port_range.split('-')
            if not isPositiveInteger(parts[0]) or not isPositiveInteger(parts[1]):
                raise newException(ValueError, "Invalid port range format: " & port_range)
            let start_port = parts[0].parseInt()
            let end_port = parts[1].parseInt()
            if start_port > 0xffff or end_port > 0xffff:
                raise newException(ValueError, "Invalid port range format: " & port_range)
            discard ports_ranges.add_ports(uint16(start_port), uint16(end_port))

        else:
            if not isPositiveInteger(port_range):
                raise newException(ValueError, "Invalid port range format: " & port_range)
            let start_port = port_range.parseInt()
            if start_port > 0xffff:
                raise newException(ValueError, "Invalid port range format: " & port_range)
            discard ports_ranges.add_ports(uint16(start_port), 0)

    return ports_ranges


proc ranges_string_to_generators(full_ranges: string, scan_range: RefGlobalScanGenerator): bool =
    let parts = full_ranges.split(':')
    if len(parts) == 1:
        let port_generator = RefPortGenerator()
        discard port_generator.add_ports(0, 0)
        discard scan_range.add_scans(constructScanGenerator(ip_ranges_to_startend(parts[0]), port_generator, "icmp"))
    elif len(parts) == 2:
        discard scan_range.add_scans(constructScanGenerator(ip_ranges_to_startend(parts[0]), port_ranges_to_startend(parts[1]), "tcp"))
    elif len(parts) == 3:
        discard scan_range.add_scans(constructScanGenerator(ip_ranges_to_startend(parts[0]), port_ranges_to_startend(parts[2]), parts[1]))
    return false

proc parse_args(commandline: string): tuple[generators: RefGlobalScanGenerator, workers: uint64, error: bool] =
    var
        error = false
        workers: uint64 = 0
        local_timeout: uint64 = 0 
        scan_range: RefGlobalScanGenerator = RefGlobalScanGenerator()

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
                    of "r", "no-random":
                        random = false
                    of "o", "no-optimization":
                        optimized = false
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
    stderr.writeLine("Usages: scan [-o/--optimization] [-r/--no-random] [-t/--timeout] [-w/--workers=integer] [-f/--filtered/--print-filtered] [-c/--close/--print-close] [-a/--all/--print-all] scan-range1 scan-range2 ... scan-rangeN")
    stderr.writeLine("\tscan 127.0.0.1:tcp:20-445")
    stderr.writeLine("\tscan -o -r -t=3 -w=3000 -a 192.168.0.1-254,172.16.0.0-172.16.255.254,10.0.0.0/8:icmp 192.168.0.1-254,172.16.0.0-172.16.255.254,10.0.0.0/255.0.0.0:tcp:20-445 192.168.0.1-254,172.16.0.0-172.16.255.254,10.0.0.0/8:udp:53,68,5353,5355")
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

    if generators.size == 0:
        (generators, workers, error) = parse_args(commandline)

    if error or generators.size == 0:
        return usages()

    if workers == 0:
        if random:
            if optimized:
                waitFor optimized_random_scan(generators)
            else:
                waitFor random_scan(generators)
        else:
            waitFor scan(generators)
    else:
        if random:
            if optimized:
                waitFor optimized_workers_random_scan(generators, workers)
            else:
                waitFor workers_random_scan(generators, workers)
        else:
            waitFor workers_scan(generators, workers)

    if errors != 0:
        stderr.writeLine("Report:\n\t" & $tests  & " tests,\n\t" & $opens & " opens,\n\t" & $cancels & " cancels,\n\t" & $errors & " errors. Consider reducing the number of workers.")
    return 0

system.quit(int(main()))
