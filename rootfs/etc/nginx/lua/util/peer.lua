local tonumber = tonumber
local ipairs = ipairs
local table = table
local type = type
local select = select
local math_floor = math.floor

local _M = {}

local function parse_ipv4(address)
  local a, b, c, d = address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then
    return nil
  end

  local octets = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
  for _, octet in ipairs(octets) do
    if octet > 255 then
      return nil
    end
  end

  return octets
end

local function parse_hextets(part)
  local hextets = {}
  if part == "" then
    return hextets
  end

  for group in (part .. ":"):gmatch("([^:]*):") do
    if not group:match("^%x%x?%x?%x?$") then
      return nil
    end
    table.insert(hextets, tonumber(group, 16))
  end

  return hextets
end

-- returns the 8 16-bit groups of an IPv6 address, or nil if it is not one
local function parse_ipv6(address)
  address = address:gsub("%%.*$", "")
  if not address:find(":", 1, true) then
    return nil
  end

  local tail = {}
  local ipv4_tail = address:match(":(%d+%.%d+%.%d+%.%d+)$")
  if ipv4_tail then
    local octets = parse_ipv4(ipv4_tail)
    if not octets then
      return nil
    end
    tail = { octets[1] * 256 + octets[2], octets[3] * 256 + octets[4] }
    address = address:sub(1, #address - #ipv4_tail)
    if address:sub(-2) ~= "::" then
      address = address:sub(1, -2)
    end
  end

  local groups
  local head, rest = address:match("^(.-)::(.*)$")
  if head then
    if rest:find("::", 1, true) then
      return nil
    end
    local left, right = parse_hextets(head), parse_hextets(rest)
    if not left or not right then
      return nil
    end
    for _, v in ipairs(tail) do
      table.insert(right, v)
    end
    local missing = 8 - #left - #right
    if missing < 1 then
      return nil
    end
    groups = left
    for _ = 1, missing do
      table.insert(groups, 0)
    end
    for _, v in ipairs(right) do
      table.insert(groups, v)
    end
  else
    groups = parse_hextets(address)
    if not groups then
      return nil
    end
    for _, v in ipairs(tail) do
      table.insert(groups, v)
    end
    if #groups ~= 8 then
      return nil
    end
  end

  return groups
end

-- 0.0.0.0/8 is "this host" and 127.0.0.0/8 is loopback; Linux delivers
-- connections to either to local listeners.
local function is_local_ipv4(octets)
  return octets[1] == 0 or octets[1] == 127
end

local function is_local_ipv6(groups)
  for i = 1, 5 do
    if groups[i] ~= 0 then
      return false
    end
  end

  -- ::, ::1, IPv4-compatible (::a.b.c.d) and IPv4-mapped (::ffff:a.b.c.d)
  if groups[6] == 0 or groups[6] == 0xffff then
    return is_local_ipv4({ math_floor(groups[7] / 256) })
  end

  return false
end

local function is_local_address(address)
  local host = address:lower():gsub("%.$", "")
  if host == "localhost" or host:sub(-10) == ".localhost" then
    return true
  end

  local octets = parse_ipv4(host)
  if octets then
    return is_local_ipv4(octets)
  end

  local groups = parse_ipv6(host)
  if groups then
    return is_local_ipv6(groups)
  end

  return false
end

-- splits "host:port" or "[ipv6]:port"; port is nil if the peer has none
function _M.split(peer)
  local address, port = peer:match("^%[(.*)%]:(%d+)$")
  if address then
    return address, port
  end

  address = peer:match("^%[(.*)%]$")
  if address then
    return address, nil
  end

  address, port = peer:match("^([^:]*):(%d+)$")
  if address then
    return address, port
  end

  return peer, nil
end

-- is_local returns true when the peer would connect back to this host:
-- loopback or unspecified IPv4/IPv6 addresses (including IPv4-mapped
-- IPv6 forms) and localhost names, regardless of port.
function _M.is_local(peer)
  if type(peer) ~= "string" or peer == "" then
    return true
  end

  local address = _M.split(peer)
  if is_local_address(address) then
    return true
  end

  -- an unbracketed IPv6 peer is ambiguous, check it with and without
  -- the trailing group treated as a port
  if not peer:find("[", 1, true) and select(2, peer:gsub(":", "")) > 1 then
    if is_local_address(peer) then
      return true
    end
    local without_port = peer:match("^(.*):%d+$")
    if without_port and is_local_address(without_port) then
      return true
    end
  end

  return false
end

return _M
