# knx-gateway-discover

Nmap NSE script to discover KNX home automation gateways by sending multicast search requests.

Further information:
* DIN EN 13321-2
* http://www.knx.org/knx-en/index.php

## Usage

```
# nmap -e eth0 --script ./knx-gateway-discover.nse
```

**Note**: Increase verbosity/debug to see full message contents:

```
# nmap -e eth0 -v -d --script ./knx-gateway-discover.nse
```

## Sample Output

### Default

```
# nmap -e eth0 --script ./knx-gateway-discover.nse

Starting Nmap 6.47SVN ( http://nmap.org ) at 2015-08-07 16:39 CEST
Pre-scan script results:
| knx-gateway-discover:
|   Status: Found 1 KNX gateway(s)
|   Gateways:
|     Gateway1:
|       IP address: 192.168.178.11
|       Port: 3671
|       KNX address: 15.15.255
|       Device MAC address: 00052650065C
|       Device friendly name: IP-Viewer
|       Supported Services:
|         KNXnet/IP Core
|         KNXnet/IP Device Management
|         KNXnet/IP Tunnelling
|_        KNXnet/IP Object Server

```

### Debug

```
# nmap -d -e eth0 --script ./knx-gateway-discover.nse

Starting Nmap 6.47SVN ( http://nmap.org ) at 2015-08-07 16:46 CEST
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
Initiating NSE at 16:46
NSE: Starting knx-gateway-discover.
NSE: Finished knx-gateway-discover.
NSE: Finished knx-gateway-discover.
Completed NSE at 16:46, 3.06s elapsed
Pre-scan script results:
| knx-gateway-discover:
|   Status: Found 1 KNX gateway(s)
|   Gateways:
|     Gateway1:
|       Body:
|         DIB_DEV_INFO:
|           Description type: Device Information
|           KNX medium: KNX TP1
|           Device status: 00
|           KNX address: 15.15.255
|           Project installation identifier: 0000
|           Decive serial: 00EF2650065C
|           Multicast address: 0.0.0.0
|           Device MAC address: 00052650065C
|           Device friendly name: IP-Viewer
|         HPAI:
|           Protocol code: 01
|           IP address: 192.168.178.11
|           Port: 3671
|         DIB_SUPP_SVC_FAMILIES:
|           KNXnet/IP Device Management:
|             Version: 1
|           KNXnet/IP Object Server:
|             Version: 1
|           KNXnet/IP Tunnelling:
|             Version: 1
|           KNXnet/IP Core:
|             Version: 1
|       Header:
|         Header length: 6
|         Protocol version: 16
|         Service type: SEARCH_RESPONSE (0x0202)
|_        Total length: 78
NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 1) scan.
Initiating NSE at 16:46
Completed NSE at 16:46, 0.00s elapsed
Read from /usr/bin/../share/nmap: nmap-services.
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.28 seconds
           Raw packets sent: 0 (0B) | Rcvd: 0 (0B)
```
