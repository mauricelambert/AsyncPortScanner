#    Cross-platform asynchronous port scanner written in Nim.
#    Copyright (C) 2023  Maurice Lambert

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

echo """
AsyncPortScanner  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""

import asyncnet, asyncdispatch, net, strutils, parseopt, system

proc test_port(ip: string, port: int) {.async.} =
  var state = false
  let socket = newAsyncSocket(AF_INET, SOCK_STREAM)
  try:
    state = await withTimeout(socket.connect(ip, Port(port)), 1000)
  except OSError:
    discard
  finally:
    socket.close()
  if state:
    echo "[+] Port: ", ip, ":", port, " open"
  else:
    echo "[-] Port: ", ip, ":", port, " closed"

proc scan(ips: seq[string], first: int, last: int): Future[void] {.async.} =
  for port in first..last:
    for ip in ips:
      echo ip, ":", port
      asyncCheck test_port(ip, port)
      echo ip, ":", port

proc argument_to_int(key: string, value: string): (int, bool) =
  var int_value = 0
  try:
    int_value = parseInt(value)
  except ValueError:
    stderr.writeLine("Error: ", key, " should be a valid integer (not ", value, ")")
    return (1, true)
  if int_value > 0 and int_value < 65535:
    return (int_value, false)

var first_port = 1
var last_port = 65535
var ips = newSeq[string]()
var error = true

var parser = initOptParser()
for kind, key, value in parser.getopt():
  case kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case key:
        of "f", "first-port", "first":
          (first_port, error) = argument_to_int("[-f/--first/--first-port]", value)
        of "l", "last-port", "last":
          (last_port, error) = argument_to_int("[-l/--last/--last-port]", value)
        else:
          stderr.writeLine("Error: invalid option: ", key, " (", value, ")")
          error = true
    of cmdArgument:
      ips.add(key)
      error = false
  if error:
    break

if error:
  stderr.writeLine("Description: Cross-platform asynchronous port scanner written in Nim.")
  stderr.writeLine("Usages: scan [-f/--first/--first-port integer] [-l/--last/--last-port integer] ip1 ip2 ... ipN")
  stderr.writeLine("\tExample 1: scan 127.0.0.1")
  stderr.writeLine("\tExample 2: scan --first=135 --last=1024 127.0.0.1")
  stderr.writeLine("\tExample 3: scan -f=135 -l=1024 10.10.10.1 127.0.0.1")
  stderr.writeLine("\tExample 4: scan --first-port=135 --last-port=1024 127.0.0.1")
  system.quit(1)

waitFor scan(ips, first_port, last_port)
