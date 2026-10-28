local http = require("resty.http")
local ssl = require("ngx.ssl")
local ocsp = require("ngx.ocsp")
local ngx = ngx
local string = string
local tostring = tostring
local type = type
local re_sub = ngx.re.sub
local ipairs = ipairs

local dns_lookup = require("util.dns").lookup
local ip_util = require("util.ip")

local _M = {
  is_ocsp_stapling_enabled = false
}

local DEFAULT_CERT_HOSTNAME = "_"

local OCSP_RESPONDER_SCHEMES = { http = true, https = true }
-- a failed OCSP fetch for a certificate is retried only after this many seconds
local OCSP_FETCH_RETRY_INTERVAL = 300
local OCSP_FETCH_LOCK_PREFIX = "fetch_lock:"

-- non-public networks OCSP responders may be reached on, see
-- set_ocsp_responder_allowed_cidrs
local ocsp_responder_allowed_cidrs = nil

local certificate_data = ngx.shared.certificate_data
local certificate_servers = ngx.shared.certificate_servers
local ocsp_response_cache = ngx.shared.ocsp_response_cache

local function get_der_cert_and_priv_key(pem_cert_key)
  local der_cert, der_cert_err = ssl.cert_pem_to_der(pem_cert_key)
  if not der_cert then
    return nil, nil, "failed to convert certificate chain from PEM to DER: " .. der_cert_err
  end

  local der_priv_key, dev_priv_key_err = ssl.priv_key_pem_to_der(pem_cert_key)
  if not der_priv_key then
    return nil, nil, "failed to convert private key from PEM to DER: " .. dev_priv_key_err
  end

  return der_cert, der_priv_key, nil
end

local function set_der_cert_and_key(der_cert, der_priv_key)
  local set_cert_ok, set_cert_err = ssl.set_der_cert(der_cert)
  if not set_cert_ok then
    return "failed to set DER cert: " .. set_cert_err
  end

  local set_priv_key_ok, set_priv_key_err = ssl.set_der_priv_key(der_priv_key)
  if not set_priv_key_ok then
    return "failed to set DER private key: " .. set_priv_key_err
  end
end

local function get_pem_cert_uid(raw_hostname)
  -- Convert hostname to ASCII lowercase (see RFC 6125 6.4.1) so that requests with uppercase
  -- host would lead to the right certificate being chosen (controller serves certificates for
  -- lowercase hostnames as specified in Ingress object's spec.rules.host)
  local hostname = re_sub(raw_hostname, "\\.$", "", "jo"):gsub("[A-Z]",
    function(c) return c:lower() end)

  local uid = certificate_servers:get(hostname)
  if uid then
    return uid
  end

  local wildcard_hostname, _, err = re_sub(hostname, "^[^\\.]+\\.", "*.", "jo")
  if err then
    ngx.log(ngx.ERR, "error: ", err)
    return uid
  end

  if wildcard_hostname then
    uid = certificate_servers:get(wildcard_hostname)
  end

  return uid
end

local function is_ocsp_stapling_enabled_for(_)
  -- TODO: implement per ingress OCSP stapling control
  -- and make use of uid. The idea is to have configureCertificates
  -- in controller side to push uid -> is_ocsp_enabled data to Lua land.

  return _M.is_ocsp_stapling_enabled
end

-- The responder URL comes from the (tenant supplied) certificate, so only
-- connect to it when it resolves exclusively to public unicast addresses or
-- explicitly allowed networks. Otherwise the controller could be used to send
-- requests to internal services.
local function resolve_ocsp_responder(parsed_url)
  local scheme, host = parsed_url[1], parsed_url[2]
  if not OCSP_RESPONDER_SCHEMES[scheme] then
    return nil, "unsupported scheme " .. tostring(scheme)
  end
  if not host or host == "" then
    return nil, "missing host"
  end

  local bare_host = host:match("^%[(.+)%]$") or host

  local addresses
  if ip_util.is_ip(bare_host) then
    addresses = { bare_host }
  else
    addresses = dns_lookup(bare_host)
  end

  if not addresses or #addresses == 0 then
    return nil, "could not resolve " .. bare_host
  end

  for _, address in ipairs(addresses) do
    if not ip_util.is_ip(address) then
      return nil, "could not resolve " .. bare_host
    end
    if not ip_util.is_public(address) and
        not ip_util.in_cidrs(address, ocsp_responder_allowed_cidrs) then
      return nil, "responder resolves to non-public address " .. address
    end
  end

  return addresses[1], nil
end

local function get_resolved_url(parsed_url, ip)
  local scheme, port, path = parsed_url[1], parsed_url[3], parsed_url[4]
  if ip:find(":", 1, true) then
    ip = "[" .. ip .. "]"
  end
  return string.format("%s://%s:%s%s", scheme, ip, port, path)
end

local function do_ocsp_request(url, ocsp_request)
  local httpc = http.new()
  httpc:set_timeout(1000, 1000, 2000)

  local parsed_url, err = httpc:parse_uri(url)
  if not parsed_url then
    return nil, err
  end

  local ip
  ip, err = resolve_ocsp_responder(parsed_url)
  if not ip then
    return nil, "refused OCSP responder URL " .. url .. ": " .. err
  end

  local resolved_url = get_resolved_url(parsed_url, ip)

  local http_response
  http_response, err = httpc:request_uri(resolved_url, {
    method = "POST",
    headers = {
      ["Content-Type"] = "application/ocsp-request",
      ["Host"] = parsed_url[2],
    },
    body = ocsp_request,
    ssl_server_name = parsed_url[2],
  })
  if not http_response then
    return nil, err
  end
  if http_response.status ~= 200 then
    return nil, "unexpected OCSP responder status code: " .. tostring(http_response.status)
  end

  return http_response.body, nil
end

local function ocsp_fetch_lock_key(uid)
  return OCSP_FETCH_LOCK_PREFIX .. uid
end

-- Callers must hold the fetch lock (see schedule_ocsp_fetch). The lock is only
-- released after a successful fetch, so a failing responder is retried at most
-- once per OCSP_FETCH_RETRY_INTERVAL (negative caching).
local function fetch_and_cache_ocsp_response(uid, der_cert)
  local url, err = ocsp.get_ocsp_responder_from_der_chain(der_cert)
  if not url and err then
    ngx.log(ngx.ERR, "could not extract OCSP responder URL: ", err)
    return
  end
  if not url and not err then
    ngx.log(ngx.DEBUG, "no OCSP responder URL returned")
    return
  end

  local request
  request, err = ocsp.create_ocsp_request(der_cert)
  if not request then
    ngx.log(ngx.ERR, "could not create OCSP request: ", err)
    return
  end

  local ocsp_response
  ocsp_response, err = do_ocsp_request(url, request)
  if err then
    ngx.log(ngx.ERR, "could not get OCSP response: ", err)
    return
  end
  if not ocsp_response or #ocsp_response == 0 then
    ngx.log(ngx.ERR, "OCSP responder returned an empty response")
    return
  end

  local ok
  ok, err = ocsp.validate_ocsp_response(ocsp_response, der_cert)
  if not ok then
    -- We are doing the same thing as vanilla Nginx here - if response status is not "good"
    -- we do not use it - no stapling.
    -- We can look into differentiation of validation errors and when status is i.e "revoked"
    -- we might want to continue with stapling - it is at the least counterintuitive that
    -- one would not staple response when certificate is revoked (I have not managed to find
    -- and spec about this). Also one would expect browsers to do all these verifications
    -- comprehensively, so why we bother doing this on server side? This can be tricky though:
    -- imagine the certificate is not revoked but its OCSP responder is having some issues
    -- and not generating a valid OCSP response. We would then staple that invalid OCSP response
    -- and then browser would fail the connection because of invalid OCSP response - as a result
    -- user request fails. But as a server we can validate response here and not staple it
    -- to the connection if it is invalid. But if browser/client has must-staple enabled
    -- then this will break anyway. So for must-staple there's no difference from users'
    -- perspective. When must-staple is not enabled though it is better to not staple
    -- invalid response and let the client/browser to fallback to CRL check or retry OCSP
    -- on its own.
    --

    ngx.log(ngx.NOTICE, "OCSP response validation failed: ", err)
    return
  end

  -- Normally this should be (nextUpdate - thisUpdate), but Lua API does not expose
  -- those attributes.
  local expiry = 3600 * 24 * 3
  local success, forcible
  success, err, forcible = ocsp_response_cache:set(uid, ocsp_response, expiry)
  if not success then
    ngx.log(ngx.ERR, "failed to cache OCSP response: ", err)
  end
  if forcible then
    ngx.log(ngx.NOTICE, "removed an existing item when saving OCSP response, ",
      "consider increasing shared dictionary size for 'ocsp_response_cache'")
  end

  ocsp_response_cache:delete(ocsp_fetch_lock_key(uid))
end

-- schedule_ocsp_fetch enqueues at most one fetch per certificate across all
-- workers and OCSP_FETCH_RETRY_INTERVAL.
local function schedule_ocsp_fetch(uid, der_cert)
  local lock_key = ocsp_fetch_lock_key(uid)
  local ok, err = ocsp_response_cache:add(lock_key, true, OCSP_FETCH_RETRY_INTERVAL)
  if not ok then
    if err ~= "exists" then
      ngx.log(ngx.ERR, "failed to acquire OCSP fetch lock: ", err)
    end
    return
  end

  ok, err = ngx.timer.at(0, function() fetch_and_cache_ocsp_response(uid, der_cert) end)
  if not ok then
    ocsp_response_cache:delete(lock_key)
    ngx.log(ngx.ERR, "failed to schedule OCSP fetch: ", err)
  end
end

-- ocsp_staple looks at the cache and staples response from cache if it exists
-- if there is no cached response or the existing response is stale,
-- it enqueues fetch_and_cache_ocsp_response function to refetch the response
-- (unless a fetch is already in flight or recently failed).
-- This design tradeoffs lack of OCSP response in the first request with better latency.
--
-- Serving stale response ensures that we don't serve another request without OCSP response
-- when the cache entry expires. Instead we serve the single request with stale response
-- and enqueue fetch_and_cache_ocsp_response for refetch.
local function ocsp_staple(uid, der_cert)
  local response, _, is_stale = ocsp_response_cache:get_stale(uid)
  if not response or is_stale then
    schedule_ocsp_fetch(uid, der_cert)
    return false, nil
  end

  local ok, err = ocsp.set_ocsp_status_resp(response)
  if not ok then
    return false, err
  end

  return true, nil
end

-- allows OCSP requests to responders on the given non-public networks
-- (e.g. an in-cluster responder of a trusted internal CA)
function _M.set_ocsp_responder_allowed_cidrs(cidrs)
  if type(cidrs) ~= "table" then
    ocsp_responder_allowed_cidrs = nil
    return nil
  end

  local parsed, err = ip_util.parse_cidrs(cidrs)
  if not parsed then
    return err
  end

  ocsp_responder_allowed_cidrs = parsed
  return nil
end

-- drops the cached OCSP response and any fetch backoff for a certificate,
-- e.g. when the certificate has been renewed
function _M.invalidate_ocsp_response(uid)
  ocsp_response_cache:delete(uid)
  ocsp_response_cache:delete(ocsp_fetch_lock_key(uid))
end

function _M.configured_for_current_request()
  if ngx.ctx.cert_configured_for_current_request == nil then
    ngx.ctx.cert_configured_for_current_request = get_pem_cert_uid(ngx.var.host) ~= nil
  end

  return ngx.ctx.cert_configured_for_current_request
end

function _M.call()
  local hostname, hostname_err = ssl.server_name()
  if hostname_err then
    ngx.log(ngx.ERR, "error while obtaining hostname: " .. hostname_err)
  end
  if not hostname then
    ngx.log(ngx.INFO, "obtained hostname is nil (the client does "
      .. "not support SNI?), falling back to default certificate")
    hostname = DEFAULT_CERT_HOSTNAME
  end

  local pem_cert
  local pem_cert_uid = get_pem_cert_uid(hostname)
  if not pem_cert_uid then
    pem_cert_uid = get_pem_cert_uid(DEFAULT_CERT_HOSTNAME)
  end
  if pem_cert_uid then
    pem_cert = certificate_data:get(pem_cert_uid)
  end
  if not pem_cert then
    ngx.log(ngx.ERR, "certificate not found, falling back to fake certificate for hostname: "
      .. tostring(hostname))
    return
  end

  local clear_ok, clear_err = ssl.clear_certs()
  if not clear_ok then
    ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates: " .. clear_err)
    return ngx.exit(ngx.ERROR)
  end

  local der_cert, der_priv_key, der_err = get_der_cert_and_priv_key(pem_cert)
  if der_err then
    ngx.log(ngx.ERR, der_err)
    return ngx.exit(ngx.ERROR)
  end

  local set_der_err = set_der_cert_and_key(der_cert, der_priv_key)
  if set_der_err then
    ngx.log(ngx.ERR, set_der_err)
    return ngx.exit(ngx.ERROR)
  end

  if is_ocsp_stapling_enabled_for(pem_cert_uid) then
    local _, err = ocsp_staple(pem_cert_uid, der_cert)
    if err then
      ngx.log(ngx.ERR, "error during OCSP stapling: ", err)
    end
  end
end

return _M
