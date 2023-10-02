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

import asyncnet, asyncdispatch, net, strutils, parseopt, system, selectors, typetraits, os, std/times

## This function try to connect to a port asynchronously
proc test_port(ip: string, port: int, timeout: int): Future[void] {.async.} =
  var state = false
  var socket: AsyncSocket
  try:
    socket = newAsyncSocket(AF_INET, SOCK_STREAM)
  except IOSelectorsException, OSError:
    await sleepAsync(timeout)
    await test_port(ip, port, timeout)
    return
  try:
    state = await withTimeout(socket.connect(ip, Port(port)), timeout)
  except OSError as e:
    if e.errorCode == 10055:
      await sleepAsync(timeout)
      await test_port(ip, port, timeout)
      return
    raise e
  finally:
    try:
      socket.close()
    except OSError:
      discard
  if state:
    echo "[+] Port: ", ip, ":", port, " open"


## This function runs the asynchronous scan.
proc scan(futures: seq[Future[void]]): Future[void] {.async.} =
  await all(futures)

## This function generates Futures for asynchronous scan.
proc generate_futures(ips: seq[string], first: int, last: int, timeout: int): seq[Future[void]] = 
  var futures = newSeq[Future[void]]()
  for port in first..last:
    for ip in ips:
      futures.add(test_port(ip, port, timeout))
  return futures

## This function is a wrapper for scan function to manage OSError on Windows
proc start_scan(ips: seq[string], first: int, last: int, timeout: int) = 
  var futures = generate_futures(ips, first, last, timeout)

  while true:
    try:
      waitFor scan(futures)
      break
    except OSError as e:
      if e.errorCode != 10038:
        echo "There is an error, restart smallest scans..."
        start_scan(ips, first, first + int((last - first) / 2), timeout)
        start_scan(ips, first + int((last - first) / 2), last, timeout)
        raise e
      sleep(timeout)


## This function converts an integer arguments (string) to integer
proc argument_to_int(key: string, value: string): (int, bool) =
  var int_value = 0
  try:
    int_value = parseInt(value)
  except ValueError:
    stderr.writeLine("Error: ", key, " should be a valid integer (not ", value, ")")
    return (1, true)
  if int_value > 0 and int_value < 65536:
    return (int_value, false)
  return (1, true)

var first_port = 1
var last_port = 65535
var timeout = 1000
var ips = newSeq[string]()
var error = true
let executable = getAppFilename()

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
        of "t", "timeout":
          (timeout, error) = argument_to_int("[-t/--timeout]", value)
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
  stderr.writeLine("Usages: \"" & executable & "\" [-f/--first/--first-port=integer] [-l/--last/--last-port=integer] [-t/--timeout=integer] ip1 ip2 ... ipN")
  stderr.writeLine("\tExample 1: \"" & executable & "\" 127.0.0.1")
  stderr.writeLine("\tExample 2: \"" & executable & "\" --first=135 --last=1024 127.0.0.1")
  stderr.writeLine("\tExample 3: \"" & executable & "\" --t=1000 -f=135 -l=1024 10.10.10.1 127.0.0.1")
  stderr.writeLine("\tExample 4: \"" & executable & "\" --first-port=135 --last-port=1024 127.0.0.1")
  stderr.writeLine("\tExample 5: \"" & executable & "\" --timeout=1000 127.0.0.1")
  system.quit(1)

start_scan(ips, first_port, last_port, timeout)
