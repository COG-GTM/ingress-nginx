local string = string
local tonumber = tonumber
local ipairs = ipairs
local math = math

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

local function parse_ipv6_groups(part)
  local groups = {}
  if part == "" then
    return groups
  end
  for group in (part .. ":"):gmatch("([^:]*):") do
    if not group:match("^%x%x?%x?%x?$") then
      return nil
    end
    groups[#groups + 1] = tonumber(group, 16)
  end
  return groups
end

-- returns the address as eight 16-bit groups, or nil if it is not IPv6
local function parse_ipv6(address)
  if address:find("[^%x:%.]") then
    return nil
  end

  local head, tail = address:match("^(.*:)(%d+%.%d+%.%d+%.%d+)$")
  if tail then
    local octets = parse_ipv4(tail)
    if not octets then
      return nil
    end
    address = head .. string.format("%x:%x", octets[1] * 256 + octets[2],
                                    octets[3] * 256 + octets[4])
  end

  local gap_start, gap_end = address:find("::", 1, true)
  local left, right
  if gap_start then
    if address:find("::", gap_start + 1, true) then
      return nil
    end
    left = parse_ipv6_groups(address:sub(1, gap_start - 1))
    right = parse_ipv6_groups(address:sub(gap_end + 1))
  else
    left = parse_ipv6_groups(address)
    right = {}
  end
  if not left or not right then
    return nil
  end

  if gap_start then
    if #left + #right > 7 then
      return nil
    end
    for _ = 1, 8 - #left - #right do
      left[#left + 1] = 0
    end
  elseif #left ~= 8 then
    return nil
  end
  for _, group in ipairs(right) do
    left[#left + 1] = group
  end
  return left
end

local function ipv4_kind(octets)
  if octets[1] == 127 then
    return "loopback"
  end
  if octets[1] == 0 then
    return "unspecified"
  end
  if octets[1] == 169 and octets[2] == 254 then
    return "link-local"
  end
  return nil
end

-- Classifies an IP address literal (IPv6 may be wrapped in brackets).
-- Returns "loopback", "unspecified", "link-local" or nil, and whether the
-- address is an IPv4 address embedded in IPv6 (::ffff:a.b.c.d or ::a.b.c.d).
function _M.special_address_kind(address)
  if not address then
    return nil, false
  end
  address = address:match("^%[(.*)%]$") or address

  local octets = parse_ipv4(address)
  if octets then
    return ipv4_kind(octets), false
  end

  local groups = parse_ipv6(address)
  if not groups then
    return nil, false
  end

  local leading_zeros = 0
  for i = 1, 8 do
    if groups[i] ~= 0 then
      break
    end
    leading_zeros = i
  end

  if leading_zeros == 8 then
    return "unspecified", false
  end
  if leading_zeros == 7 and groups[8] == 1 then
    return "loopback", false
  end
  if groups[1] >= 0xfe80 and groups[1] <= 0xfebf then
    return "link-local", false
  end
  if leading_zeros >= 5 and (leading_zeros >= 6 or groups[6] == 0xffff) then
    local embedded = {
      math.floor(groups[7] / 256), groups[7] % 256,
      math.floor(groups[8] / 256), groups[8] % 256,
    }
    return ipv4_kind(embedded), true
  end
  return nil, false
end

-- splits "host:port" or "[ipv6]:port" into host and port
function _M.split_host_port(peer)
  local host, port = peer:match("^%[(.*)%]:(%d+)$")
  if host then
    return host, port
  end
  host, port = peer:match("^([^:]*):(%d+)$")
  if host then
    return host, port
  end
  return peer, nil
end

-- Returns a reason when an upstream peer must never be used because it points
-- back at the controller itself. The only legitimate loopback peer is the
-- controller's own default backend, so plain loopback addresses are refused
-- only on the internal ports, while unspecified, link-local and IPv4-in-IPv6
-- forms of these addresses are always refused.
function _M.forbidden_reason(peer, internal_ports)
  local host, port = _M.split_host_port(peer)
  local kind, embedded = _M.special_address_kind(host)
  if not kind then
    return nil
  end
  if kind == "loopback" and not embedded then
    if port and internal_ports and internal_ports[port] then
      return "loopback address on internal port " .. port
    end
    return nil
  end
  if embedded then
    return "IPv4-embedded " .. kind .. " address"
  end
  return kind .. " address"
end

-- Drops resolved ExternalName endpoints that point at loopback, unspecified
-- or link-local addresses; these are never valid ExternalName targets.
function _M.filter_external_endpoints(endpoints, log)
  local allowed = {}
  for _, endpoint in ipairs(endpoints) do
    local kind = _M.special_address_kind(endpoint.address)
    if kind then
      if log then
        log(endpoint, kind)
      end
    else
      allowed[#allowed + 1] = endpoint
    end
  end
  return allowed
end

return _M
