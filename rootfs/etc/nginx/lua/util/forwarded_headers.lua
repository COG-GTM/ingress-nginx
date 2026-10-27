local ngx_re_match = ngx.re.match
local ngx_re_split = require("ngx.re").split
local string = string
local tonumber = tonumber

local _M = {}

-- hostname, IPv4 address or bracketed IPv6 address, optionally with a port
local HOST_REGEX = [[^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,252}))(?::[0-9]{1,5})?\z]]

local function first_value(header)
  if not header then
    return nil
  end

  local values, err = ngx_re_split(header, ",")
  if err or not values or not values[1] then
    return nil
  end

  local value = string.match(values[1], "^%s*(.-)%s*$")
  if value == "" then
    return nil
  end

  return value
end

-- X-Forwarded-* headers are only honored when the connection comes from an
-- address in proxy-real-ip-cidr; the template exposes that as
-- $forwarded_headers_trusted when use-forwarded-headers is enabled.
function _M.trusted()
  return ngx.var.forwarded_headers_trusted == "1"
end

function _M.proto()
  local proto = first_value(ngx.var.http_x_forwarded_proto)
  if not proto then
    return nil
  end

  proto = string.lower(proto)
  if proto ~= "http" and proto ~= "https" then
    return nil
  end

  return proto
end

function _M.port()
  local port = first_value(ngx.var.http_x_forwarded_port)
  if not port or not string.match(port, "^%d+$") then
    return nil
  end

  local number = tonumber(port)
  if number < 1 or number > 65535 then
    return nil
  end

  return port
end

function _M.host()
  local host = first_value(ngx.var.http_x_forwarded_host)
  if not host then
    return nil
  end

  if not ngx_re_match(host, HOST_REGEX, "jo") then
    return nil
  end

  return host
end

return _M
