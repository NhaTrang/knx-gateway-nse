# knx-gateway.nse
Nmap NSE scripts to discover KNX home automation gateways via multicast and unicast methods.

Further information:
* DIN EN 13321-2
* http://www.knx.org/

## knx-gateway-info

## Usage

```
# nmap -sU -p3671 --script ./knx-gateway-info.nse 192.168.178.11
```

**Note**: Increase verbosity/debug to see full message contents:

```
# nmap -sU -p3671 -d --script ./knx-gateway-info.nse 192.168.178.11
```

## Sample Output

```
# nmap -sU -p3671 --script ./knx-gateway-info.nse 192.168.178.11

Starting Nmap 6.47SVN ( http://nmap.org ) at 2015-08-08 18:53 CEST
Nmap scan report for 192.168.178.11
Host is up (0.00047s latency).
PORT     STATE         SERVICE
3671/udp open|filtered efcp
| knx-gateway-info:
|   KNX address: 15.15.255
|   Supported Services:
|     KNXnet/IP Core
|     KNXnet/IP Device Management
|     KNXnet/IP Tunnelling
|     KNXnet/IP Object Server
|   Device friendly name: IP-Viewer
|   Device multicast address: 0.0.0.0
|_  Device serial number: 00EF2650065C
MAC Address: 00:05:26:50:06:5C (Ipas Gmbh)
```

## knx-gateway-discover

### Usage

```
# nmap -e eth0 --script ./knx-gateway-discover.nse
```

**Note**: Increase verbosity/debug to see full message contents:

```
# nmap -e eth0 -v -d --script ./knx-gateway-discover.nse
```

The script supports the following `script-args`:
* timeout: Defines how long the script waits for responses
* newtargets: Add found gateways to target list

### Sample Output

#### Default

```
# nmap -e eth0 --script ./knx-gateway-discover.nse

Starting Nmap 6.47SVN ( http://nmap.org ) at 2015-08-08 17:00 CEST
Pre-scan script results:
| knx-gateway-discover:
|   192.168.178.11:
|     Port: 3671
|     Supported Services:
|       KNXnet/IP Core
|       KNXnet/IP Device Management
|       KNXnet/IP Tunnelling
|       KNXnet/IP Object Server
|     Device MAC address: 00052650065C
|     KNX address: 15.15.255
|_    Device friendly name: IP-Viewer  
```

#### Debug

```
# nmap -d -e eth0 --script ./knx-gateway-discover.nse

Starting Nmap 6.47SVN ( http://nmap.org ) at 2015-08-08 17:00 CEST
PORTS: Using top 1000 ports found open (TCP:1000, UDP:0, SCTP:0)
--------------- Timing report ---------------
  hostgroups: min 1, max 100000
  rtt-timeouts: init 1000, min 100, max 10000
  max-scan-delay: TCP 1000, UDP 1000, SCTP 1000
  parallelism: min 0, max 0
  max-retries: 10, host-timeout: 0
  min-rate: 0, max-rate: 0
---------------------------------------------
NSE: Using Lua 5.2.
NSE: Arguments from CLI:
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 1) scan.
Initiating NSE at 17:00
NSE: Starting knx-gateway-discover.
NSE: Finished knx-gateway-discover.
NSE: Finished knx-gateway-discover.
Completed NSE at 17:01, 3.07s elapsed
Pre-scan script results:
| knx-gateway-discover:
|   192.168.178.11:
|     Header:
|       Protocol version: 16
|       Header length: 6
|       Service type: SEARCH_RESPONSE (0x0202)
|       Total length: 78
|     Body:
|       HPAI:
|         Port: 3671
|         IP address: 192.168.178.11
|         Protocol code: 01
|       DIB_SUPP_SVC_FAMILIES:
|         KNXnet/IP Core:
|           Version: 1
|         KNXnet/IP Object Server:
|           Version: 1
|         KNXnet/IP Device Management:
|           Version: 1
|         KNXnet/IP Tunnelling:
|           Version: 1
|       DIB_DEV_INFO:
|         Decive serial: 00EF2650065C
|         Device status: 00
|         KNX address: 15.15.255
|         KNX medium: KNX TP1
|         Device friendly name: IP-Viewer
|         Multicast address: 0.0.0.0
|         Project installation identifier: 0000
|         Device MAC address: 00052650065C
|_        Description type: Device Information
```
