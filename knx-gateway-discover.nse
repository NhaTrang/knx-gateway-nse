local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local bin = require "bin"
local bit = require "bit"
local packet = require "packet"
local ipOps = require "ipOps"
local target = require "target"
local math = require "math"
local string = require "string"

description = [[
Discovers KNX gateways by sending a KNX Search Request to the multicast address
224.0.23.12 on port 3671.

This script is heavily based on the llmnr-resolve.nse script, as it technicallly
does the same thing. Credits go out to the author.
]]

prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("not running due to lack of privileges.")
    return false
  end
  return true
end

author = "Niklaus Schiess <nschiess@ernw.de>, Dominik Schneider <dschneider@ernw.de>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "broadcast"}

local knxServiceFamilies = {
  [0x02]="KNXnet/IP Core",
  [0x03]="KNXnet/IP Device Management",
  [0x04]="KNXnet/IP Tunnelling",
  [0x05]="KNXnet/IP Routing",
  [0x06]="KNXnet/IP Remote Logging",
  [0x08]="KNXnet/IP Object Server",
  [0x07]="KNXnet/IP Remote Configuration and Diagnosis"
}

local knxDibDescriptionTypes = {
  [0x01]="Device Infon",
  [0x02]="Supp_Svc_families",
  [0x03]="IP_Config",
  [0x04]="IP_Cur_Config",
  [0x05]="IP_Config"
}

local knxMediumTypes = {
  [0x01]="reserved",
  [0x02]="KNX TP1",
  [0x04]="KNX PL110",
  [0x08]="reserved",
  [0x10]="KNX RF",
  [0x20]="KNX IP"
}

--- Returns a raw knx search request
-- @param ip_address IP address of the sending host
-- @param port Port where gateways should respond to
local knxQuery = function(ip_address, port)
  return bin.pack(">C2S2C2IS",
    0x06, -- Header length
    0x10, -- Protocol version
    0x0201, -- Service type
    0x000e, -- Total length
    0x08, -- Structure length
    0x01, -- Host protocol
    ipOps.todword(ip_address),
    port
  )
end

--- Sends a knx search request
-- @param query KNX search request message
-- @param mcat Multicast destination address
-- @param port Port to sent to
local knxSend = function(query, mcast, mport)
  -- Multicast IP and UDP port
  local sock = nmap.new_socket()
  local status, err = sock:connect(mcast, mport, "udp")
  if not status then
    stdnse.debug1("%s", err)
    return
  end
  sock:send(query)
  sock:close()
end

-- Parse a KNX address from raw bytes
-- @param addr Unpacked 2 bytes
local parseKnxAddress = function(addr)
  local a = bit.rshift(bit.band(addr, 0xf000),12)
  local b = bit.rshift(bit.band(addr, 0x0f00), 8)
  local c = bit.band(addr, 0xff)
  return a..'.'..b..'.'..c
end

--- Parse a Search Response
local knxParseSearchResponse = function(knxMessage)
  local _, knx_header_length =  bin.unpack('>C', knxMessage)
  local _, knx_protocol_version = bin.unpack('>C', knxMessage, _)
  local _, knx_service_type = bin.unpack('>S', knxMessage, _)
  local _, knx_total_length = bin.unpack('>S', knxMessage, _)

  if knx_header_length ~= 0x06 and knx_protocol_version ~= 0x10 and  knx_service_type ~= 0x0202 then
    return
  end

  local _, knx_hpai_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_hpai_protocol_code = bin.unpack('>H1', knxMessage, _)
  local _, knx_hpai_ip_address = bin.unpack('>H4', knxMessage, _)
  knx_hpai_ip_address = ipOps.bin_to_ip(ipOps.hex_to_bin(knx_hpai_ip_address))
  local _, knx_hpai_port = bin.unpack('>S', knxMessage, _)

  local _, knx_dib_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_dib_description_type = bin.unpack('>C', knxMessage, _)
  knx_dib_description_type = knxDibDescriptionTypes[knx_dib_description_type]
  local _, knx_dib_knx_medium = bin.unpack('>C', knxMessage, _)
  knx_dib_knx_medium = knxMediumTypes[knx_dib_knx_medium]
  local _, knx_dib_device_status = bin.unpack('>H1', knxMessage, _)
  local _, knx_dib_knx_address = bin.unpack('>S', knxMessage, _)
  local _, knx_dib_project_install_ident = bin.unpack('>H2', knxMessage, _)
  local _, knx_dib_dev_serial = bin.unpack('>H6', knxMessage, _)
  local _, knx_dib_dev_multicast_addr = bin.unpack('>H4', knxMessage, _)
  local _, knx_dib_dev_mac = bin.unpack('>H6', knxMessage, _)
  local _, knx_dib_dev_friendly_name = bin.unpack('>A30', knxMessage, _)

  local knx_supp_svc_families = {}
  local _, knx_supp_svc_families_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_supp_svc_families_description = bin.unpack('>C', knxMessage, _)

  if knx_supp_svc_families_description == 0x02 then -- SUPP_SVC_FAMILIES
    knx_supp_svc_families_description = knxDibDescriptionTypes[knx_supp_svc_families_description]
    for i=0,(knx_total_length-_),2 do
      local i = #knx_supp_svc_families+1
      knx_supp_svc_families[i] = {}
      _, knx_supp_svc_families[i].service_id = bin.unpack('>C', knxMessage, _)
      knx_supp_svc_families[i].service_id = knxServiceFamilies[knx_supp_svc_families[i].service_id]
      _, knx_supp_svc_families[i].version = bin.unpack('>C', knxMessage, _)
    end

    --Build a proper response table
    local search_response = {}

    if nmap.debugging() > 0 then
      search_response.header = {}
      search_response.header[1] = "Header length: "..knx_header_length
      search_response.header[2] = "Protocol version: "..knx_protocol_version
      search_response.header[3] = "Service type: SEARCH_RESPONSE (0x0202)"
      search_response.header[4] = "Total length: "..knx_total_length

      search_response.body = {}
      search_response.body.hpai = {}
      search_response.body.hpai[1] = "Protocol code: "..knx_hpai_protocol_code
      search_response.body.hpai[2] = "IP address: "..knx_hpai_ip_address
      search_response.body.hpai[3] = "Port: "..knx_hpai_port

      search_response.body.dib_dev_info = {}
      search_response.body.dib_dev_info[1] = "Description type: "..knx_dib_description_type
      search_response.body.dib_dev_info[2] = "KNX medium: "..knx_dib_knx_medium
      search_response.body.dib_dev_info[3] = "Device status: "..knx_dib_device_status
      search_response.body.dib_dev_info[4] = "KNX address: "..parseKnxAddress(knx_dib_knx_address)
      search_response.body.dib_dev_info[5] = "Project installation identifier: "..knx_dib_project_install_ident
      search_response.body.dib_dev_info[6] = "Decive serial: "..knx_dib_dev_serial
      search_response.body.dib_dev_info[7] = "Multicast address: "..ipOps.bin_to_ip(ipOps.hex_to_bin(knx_dib_dev_multicast_addr))
      search_response.body.dib_dev_info[8] = "Device MAC address: "..knx_dib_dev_mac
      search_response.body.dib_dev_info[9] = "Device friendly name: "..knx_dib_dev_friendly_name

      search_response.body.dib_supp_svc_families = {}
      for i=1, #knx_supp_svc_families do
        search_response.body.dib_supp_svc_families[i] = knx_supp_svc_families[i]
      end
    else
      search_response[1] = "IP address: "..knx_hpai_ip_address
      search_response[2] = "Port: "..knx_hpai_port
      search_response[3] = "KNX address: "..parseKnxAddress(knx_dib_knx_address)
      search_response[4] = {}
      search_response[4]['Supported Services'] = {}
      for i=1, #knx_supp_svc_families do
        search_response[4]['Supported Services'][i] = knx_supp_svc_families[i].service_id
      end
    end

    return search_response
  end
end

-- Listens for knx search responses
-- @param interface Network interface to listen on.
-- @param timeout Maximum time to listen.
-- @param result table to put responses into.
local knxListen = function(interface, timeout, result)
  local condvar = nmap.condvar(result)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local status, l3data, _

  -- packets that are sent to our UDP port number 3671
  local filter = 'dst host ' .. interface.address .. ' and udp src port 3671'
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1024, true, filter)

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()
    if status then
      local p = packet.Packet:new(l3data, #l3data)
      -- Skip IP and UDP headers
      local knxMessage = string.sub(l3data, p.ip_hl*4 + 8 + 1)
      table.insert(result, knxParseSearchResponse(knxMessage))
    end
  end
  condvar("signal")
end

-- Returns the network interface used to send packets to a target host.
--@param target host to which the interface is used.
--@return interface Network interface used for target host.
local getInterface = function(target)
  -- First, create dummy UDP connection to get interface
  local sock = nmap.new_socket()
  local status, err = sock:connect(target, "12345", "udp")
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  local status, address, _, _, _ = sock:get_info()
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  for _, interface in pairs(nmap.list_interfaces()) do
    if interface.address == address then
      return interface
    end
  end
end


action = function()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 3) * 1000
  local result, output = {}, {}
  local mcast = "224.0.23.12"
  local mport = 3671
  local lport = 55772

  -- Check if a valid interface was provided
  local interface = nmap.get_interface()
  if interface then
    interface = nmap.get_interface_info(interface)
  else
    interface = getInterface(mcast)
  end
  if not interface then
    return ("\n ERROR: Couldn't get interface for %s"):format(mcast)
  end

  -- Launch listener thread
  stdnse.new_thread(knxListen, interface, timeout, result)
  -- Craft raw query
  local query = knxQuery(interface.address, lport)
  -- Small sleep so the listener doesn't miss the response
  stdnse.sleep(0.5)
  -- Send query
  knxSend(query, mcast, mport)
  -- Wait for listener thread to finish
  local condvar = nmap.condvar(result)
  condvar("wait")

  -- Check responses
  if #result > 0 then
    local output = stdnse.output_table()
    output.Status = 'Found '.. #result ..' KNX gateway(s)'
    output.Gateways = {}

    for _, response in pairs(result) do
      output.Gateways['Gateway'.._] = response
     end
    return output
  end
end
