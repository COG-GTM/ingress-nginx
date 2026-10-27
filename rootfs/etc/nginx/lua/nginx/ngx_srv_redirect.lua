local forwarded_headers = require("util.forwarded_headers")

local request_uri = ngx.var.request_uri
local redirect_to = ngx.arg[1]

local luaconfig = ngx.shared.luaconfig
local use_forwarded_headers = luaconfig:get("use_forwarded_headers")

if string.sub(request_uri, -1) == "/" then
    request_uri = string.sub(request_uri, 1, -2)
end

local redirectScheme = ngx.var.scheme
local redirectPort = ngx.var.server_port

if use_forwarded_headers and forwarded_headers.trusted() then
    redirectScheme = forwarded_headers.proto() or redirectScheme
    redirectPort = forwarded_headers.port() or redirectPort
end

return string.format("%s://%s:%s%s", redirectScheme,
    redirect_to, redirectPort, request_uri)