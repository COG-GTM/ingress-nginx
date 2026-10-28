local string_format = string.format
local string_match = string.match
local tonumber = tonumber
local type = type
local tostring = tostring
local ipairs = ipairs
local math_floor = math.floor
local table_insert = table.insert

local _M = {}

-- IPv4 ranges that are not globally routable unicast destinations
-- (RFC 6890 special-purpose registry plus multicast/reserved).
local NON_PUBLIC_IPV4_CIDRS = {
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
}

local NON_PUBLIC_IPV6_CIDRS = {
  "::/96",          -- unspecified, loopback and deprecated IPv4-compatible
  "64:ff9b:1::/48", -- local-use IPv4/IPv6 translation
  "100::/64",       -- discard-only
  "2001::/23",      -- IETF protocol assignments (incl. Teredo)
  "2001:db8::/32",  -- documentation
  "fc00::/7",       -- unique local
  "fe80::/10",      -- link-local
  "fec0::/10",      -- deprecated site-local
  "ff00::/8",       -- multicast
}

local function parse_ipv4(address)
  local a, b, c, d = string_match(address, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then
    return nil
  end

  local octets = { a, b, c, d }
  for i, octet in ipairs(octets) do
    -- reject leading zeros so that octal notation can not be smuggled in
    if #octet > 3 or (#octet > 1 and octet:sub(1, 1) == "0") then
      return nil
    end
    local value = tonumber(octet)
    if value > 255 then
      return nil
    end
    octets[i] = value
  end

  return octets
end

local function parse_hextets(part)
  local hextets = {}
  if part == "" then
    return hextets
  end

  for group in (part .. ":"):gmatch("([^:]*):") do
    if not string_match(group, "^%x%x?%x?%x?$") then
      return nil
    end
    table_insert(hextets, tonumber(group, 16))
  end

  return hextets
end

-- returns the address as an array of eight 16 bit integers
local function parse_ipv6(address)
  if not address:find(":", 1, true) then
    return nil
  end

  local head, tail = address, nil
  local double_colon = address:find("::", 1, true)
  if double_colon then
    head = address:sub(1, double_colon - 1)
    tail = address:sub(double_colon + 2)
    if tail:find("::", 1, true) then
      return nil
    end
  end

  local embedded_ipv4
  local last = tail or head
  local ipv4_part = string_match(last, "([^:]*%.[^:]*)$")
  if ipv4_part then
    embedded_ipv4 = parse_ipv4(ipv4_part)
    if not embedded_ipv4 then
      return nil
    end
    last = last:sub(1, #last - #ipv4_part)
    if last ~= "" then
      if last:sub(-1) ~= ":" then
        return nil
      end
      last = last:sub(1, -2)
    end
    if tail then tail = last else head = last end
  end

  local head_hextets = parse_hextets(head)
  local tail_hextets = parse_hextets(tail or "")
  if not head_hextets or not tail_hextets then
    return nil
  end

  if embedded_ipv4 then
    local target = double_colon and tail_hextets or head_hextets
    table_insert(target, embedded_ipv4[1] * 256 + embedded_ipv4[2])
    table_insert(target, embedded_ipv4[3] * 256 + embedded_ipv4[4])
  end

  local count = #head_hextets + #tail_hextets
  if double_colon then
    if count > 7 then
      return nil
    end
  elseif count ~= 8 then
    return nil
  end

  local hextets = {}
  for _, h in ipairs(head_hextets) do
    table_insert(hextets, h)
  end
  for _ = 1, 8 - count do
    table_insert(hextets, 0)
  end
  for _, h in ipairs(tail_hextets) do
    table_insert(hextets, h)
  end

  return hextets
end

-- matches arrays of fixed-width integers against a prefix
local function prefix_match(units, prefix_units, bits, unit_bits)
  local remaining = bits
  for i = 1, #units do
    if remaining <= 0 then
      return true
    end
    if remaining >= unit_bits then
      if units[i] ~= prefix_units[i] then
        return false
      end
    else
      local divisor = 2 ^ (unit_bits - remaining)
      return math_floor(units[i] / divisor) == math_floor(prefix_units[i] / divisor)
    end
    remaining = remaining - unit_bits
  end
  return true
end

local function compile(cidrs, parse)
  local compiled = {}
  for _, cidr in ipairs(cidrs) do
    local address, bits = string_match(cidr, "^(.+)/(%d+)$")
    local units = parse(address)
    if not units then
      error(string_format("invalid CIDR %s", cidr))
    end
    table_insert(compiled, { units = units, bits = tonumber(bits) })
  end
  return compiled
end

local NON_PUBLIC_IPV4 = compile(NON_PUBLIC_IPV4_CIDRS, parse_ipv4)
local NON_PUBLIC_IPV6 = compile(NON_PUBLIC_IPV6_CIDRS, parse_ipv6)

local function matches_any(units, ranges, unit_bits)
  for _, range in ipairs(ranges) do
    if prefix_match(units, range.units, range.bits, unit_bits) then
      return true
    end
  end
  return false
end

local function is_public_ipv4(octets)
  return not matches_any(octets, NON_PUBLIC_IPV4, 8)
end

local function embedded_ipv4(hextets, first)
  return {
    math_floor(hextets[first] / 256), hextets[first] % 256,
    math_floor(hextets[first + 1] / 256), hextets[first + 1] % 256,
  }
end

local function is_public_ipv6(hextets)
  if matches_any(hextets, NON_PUBLIC_IPV6, 16) then
    return false
  end

  -- IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) carry an IPv4
  -- destination in the low 32 bits
  local is_mapped = hextets[1] == 0 and hextets[2] == 0 and hextets[3] == 0 and
    hextets[4] == 0 and hextets[5] == 0 and hextets[6] == 0xffff
  local is_nat64 = hextets[1] == 0x64 and hextets[2] == 0xff9b and hextets[3] == 0 and
    hextets[4] == 0 and hextets[5] == 0 and hextets[6] == 0
  if is_mapped or is_nat64 then
    return is_public_ipv4(embedded_ipv4(hextets, 7))
  end

  -- 6to4 (2002::/16) carries an IPv4 relay in bits 16-47
  if hextets[1] == 0x2002 then
    return is_public_ipv4(embedded_ipv4(hextets, 2))
  end

  return true
end

-- returns true when address is an IPv4 or IPv6 literal (without brackets)
function _M.is_ip(address)
  if type(address) ~= "string" then
    return false
  end
  return parse_ipv4(address) ~= nil or parse_ipv6(address) ~= nil
end

-- returns true only for IP literals that are globally routable unicast
-- addresses, i.e. not loopback, private, link-local (incl. cloud metadata),
-- shared, multicast, documentation or otherwise reserved
function _M.is_public(address)
  if type(address) ~= "string" then
    return false
  end

  local octets = parse_ipv4(address)
  if octets then
    return is_public_ipv4(octets)
  end

  local hextets = parse_ipv6(address)
  if hextets then
    return is_public_ipv6(hextets)
  end

  return false
end

-- parses a list of IPv4/IPv6 addresses or CIDRs for use with in_cidrs
function _M.parse_cidrs(cidrs)
  local parsed = { ipv4 = {}, ipv6 = {} }
  for _, cidr in ipairs(cidrs) do
    if type(cidr) ~= "string" then
      return nil, "invalid CIDR " .. tostring(cidr)
    end

    local address, bits = string_match(cidr, "^([^/]+)/(%d+)$")
    if not address then
      address = cidr
    end

    local octets = parse_ipv4(address)
    local hextets = not octets and parse_ipv6(address)
    local max_bits = octets and 32 or 128
    bits = bits and tonumber(bits) or max_bits
    if (not octets and not hextets) or bits > max_bits then
      return nil, "invalid CIDR " .. cidr
    end

    if octets then
      table_insert(parsed.ipv4, { units = octets, bits = bits })
    else
      table_insert(parsed.ipv6, { units = hextets, bits = bits })
    end
  end
  return parsed, nil
end

-- returns true when address is contained in one of the parsed CIDRs
function _M.in_cidrs(address, parsed)
  if type(address) ~= "string" or not parsed then
    return false
  end

  local octets = parse_ipv4(address)
  if octets then
    return matches_any(octets, parsed.ipv4, 8)
  end

  local hextets = parse_ipv6(address)
  if hextets then
    return matches_any(hextets, parsed.ipv6, 16)
  end

  return false
end

return _M
