local certificate = require("certificate")
local ssl = require("ngx.ssl")

local function read_file(path)
  local file = assert(io.open(path, "rb"))
  local content = file:read("*a")
  file:close()
  return content
end

local EXAMPLE_CERT = read_file("rootfs/etc/nginx/lua/test/fixtures/example-com-cert.pem")
local DEFAULT_CERT = read_file("rootfs/etc/nginx/lua/test/fixtures/default-cert.pem")
local DEFAULT_CERT_HOSTNAME = "_"
local UUID = "2ea8adb5-8ebb-4b14-a79b-0cdcd892e884"
local DEFAULT_UUID = "00000000-0000-0000-0000-000000000000"

local function assert_certificate_is_set(cert)
  spy.on(ngx, "log")
  spy.on(ssl, "set_der_cert")
  spy.on(ssl, "set_der_priv_key")

  assert.has_no.errors(certificate.call)
  assert.spy(ngx.log).was_not_called_with(ngx.ERR, _)
  assert.spy(ssl.set_der_cert).was_called_with(ssl.cert_pem_to_der(cert))
  assert.spy(ssl.set_der_priv_key).was_called_with(ssl.priv_key_pem_to_der(cert))
end

local function refute_certificate_is_set()
  spy.on(ssl, "set_der_cert")
  spy.on(ssl, "set_der_priv_key")

  assert.has_no.errors(certificate.call)
  assert.spy(ssl.set_der_cert).was_not_called()
  assert.spy(ssl.set_der_priv_key).was_not_called()
end

local function set_certificate(hostname, certificate, uuid)
  local success, err = ngx.shared.certificate_servers:set(hostname, uuid)
  if not success then
    error(err)
  end
  success, err = ngx.shared.certificate_data:set(uuid, certificate)
  if not success then
    error(err)
  end
end

local unmocked_ngx = _G.ngx

describe("Certificate", function()
  describe("call", function()
    before_each(function()
      ssl.server_name = function() return "hostname", nil end
      ssl.clear_certs = function() return true, "" end
      ssl.set_der_cert = function(cert) return true, "" end
      ssl.set_der_priv_key = function(priv_key) return true, "" end

      ngx.exit = function(status) end


      set_certificate(DEFAULT_CERT_HOSTNAME, DEFAULT_CERT, DEFAULT_UUID)
    end)

    after_each(function()
      ngx = unmocked_ngx
      ngx.shared.certificate_data:flush_all()
      ngx.shared.certificate_servers:flush_all()
    end)

    it("sets certificate and key when hostname is found in dictionary", function()
      set_certificate("hostname", EXAMPLE_CERT, UUID)
      assert_certificate_is_set(EXAMPLE_CERT)
    end)

    it("sets certificate and key for wildcard cert", function()
      ssl.server_name = function() return "sub.hostname", nil end
      set_certificate("*.hostname", EXAMPLE_CERT, UUID)

      assert_certificate_is_set(EXAMPLE_CERT)
    end)

    it("sets certificate and key for domain with trailing dot", function()
      ssl.server_name = function() return "hostname.", nil end
      set_certificate("hostname", EXAMPLE_CERT, UUID)

      assert_certificate_is_set(EXAMPLE_CERT)
    end)

    it("fallbacks to default certificate and key for domain with many trailing dots", function()
      ssl.server_name = function() return "hostname..", nil end
      set_certificate("hostname", EXAMPLE_CERT, UUID)

      assert_certificate_is_set(DEFAULT_CERT)
    end)

    it("sets certificate and key for nested wildcard cert", function()
      ssl.server_name = function() return "sub.nested.hostname", nil end
      set_certificate("*.nested.hostname", EXAMPLE_CERT, UUID)

      assert_certificate_is_set(EXAMPLE_CERT)
    end)

    it("logs error message when certificate in dictionary is invalid", function()
      set_certificate("hostname", "something invalid", UUID)

      spy.on(ngx, "log")

      refute_certificate_is_set()
      assert.spy(ngx.log).was_called_with(ngx.ERR, "failed to convert certificate chain from PEM to DER: PEM_read_bio_X509_AUX() failed")
    end)

    it("uses default certificate when there's none found for given hostname", function()
      assert_certificate_is_set(DEFAULT_CERT)
    end)

    it("uses default certificate when hostname can not be obtained", function()
      ssl.server_name = function() return nil, "crazy hostname error" end

      assert_certificate_is_set(DEFAULT_CERT)
      assert.spy(ngx.log).was_called_with(ngx.ERR, "error while obtaining hostname: crazy hostname error")
    end)

    it("fails when hostname does not have certificate and default cert is invalid", function()
      set_certificate(DEFAULT_CERT_HOSTNAME, "invalid", UUID)

      spy.on(ngx, "log")

      refute_certificate_is_set()
      assert.spy(ngx.log).was_called_with(ngx.ERR, "failed to convert certificate chain from PEM to DER: PEM_read_bio_X509_AUX() failed")
    end)

    describe("OCSP stapling", function()
      local ocsp = require("ngx.ocsp")
      local http = require("resty.http")
      local resty_dns_resolver = require("resty.dns.resolver")
      local original_ocsp = {}
      local original_http_new = http.new
      local original_dns_resolver_new = resty_dns_resolver.new
      local original_timer_at
      local responder_url, responder_response, requests

      before_each(function()
        certificate.is_ocsp_stapling_enabled = true
        ngx.shared.ocsp_response_cache:flush_all()
        set_certificate("hostname", EXAMPLE_CERT, UUID)

        for _, name in ipairs({ "get_ocsp_responder_from_der_chain", "create_ocsp_request",
            "validate_ocsp_response", "set_ocsp_status_resp" }) do
          original_ocsp[name] = ocsp[name]
        end
        responder_url = "http://1.1.1.1/ocsp"
        responder_response = { status = 500, body = "" }
        requests = {}

        ocsp.get_ocsp_responder_from_der_chain = function() return responder_url, nil end
        ocsp.create_ocsp_request = function() return "ocsp-request", nil end
        ocsp.validate_ocsp_response = function() return true, nil end
        ocsp.set_ocsp_status_resp = function() return true, nil end

        http.new = function()
          local httpc = original_http_new()
          httpc.request_uri = function(_, uri, params)
            table.insert(requests, { uri = uri, params = params })
            return responder_response, nil
          end
          return httpc
        end

        original_timer_at = ngx.timer.at
        ngx.timer.at = function(_, callback)
          callback(false)
          return true, nil
        end
      end)

      after_each(function()
        certificate.is_ocsp_stapling_enabled = false
        certificate.set_ocsp_responder_allowed_cidrs(nil)
        for name, func in pairs(original_ocsp) do
          ocsp[name] = func
        end
        http.new = original_http_new
        resty_dns_resolver.new = original_dns_resolver_new
        ngx.timer.at = original_timer_at
        ngx.shared.ocsp_response_cache:flush_all()
      end)

      local function mock_dns(addresses)
        helpers.mock_resty_dns_new(function()
          return {
            query = function(_, _, options)
              local answers = {}
              for _, address in ipairs(addresses) do
                local is_ipv6 = address:find(":", 1, true) ~= nil
                if (options.qtype == resty_dns_resolver.TYPE_AAAA) == is_ipv6 then
                  table.insert(answers, { address = address, ttl = 60 })
                end
              end
              return answers, nil
            end,
          }
        end)
      end

      it("fetches and caches OCSP response when there is no cached response", function()
        responder_response = { status = 200, body = "ocsp-response" }

        assert.has_no.errors(certificate.call)

        assert.are.equal(1, #requests)
        assert.are.equal("http://1.1.1.1:80/ocsp", requests[1].uri)
        assert.are.equal("1.1.1.1", requests[1].params.headers["Host"])
        assert.are.equal("ocsp-response", ngx.shared.ocsp_response_cache:get(UUID))
      end)

      it("fetches and caches OCSP response when cached response is stale", function()
      end)

      it("staples using cached OCSP response", function()
      end)

      it("staples using cached stale OCSP response", function()
      end)

      it("does negative caching when OCSP response URL extraction fails", function()
        local s = spy.new(function() return nil, "extraction failed" end)
        ocsp.get_ocsp_responder_from_der_chain = s

        assert.has_no.errors(certificate.call)
        assert.has_no.errors(certificate.call)

        assert.spy(s).was.called(1)
      end)

      it("does negative caching when the request to OCSP responder fails", function()
        assert.has_no.errors(certificate.call)
        assert.has_no.errors(certificate.call)
        assert.are.equal(1, #requests)

        certificate.invalidate_ocsp_response(UUID)
        assert.has_no.errors(certificate.call)
        assert.are.equal(2, #requests)
      end)

      it("refuses responders on non-public addresses", function()
        for _, url in ipairs({
          "http://127.0.0.1/",
          "http://10.0.0.5:8080/internal/reset",
          "http://169.254.169.254/latest/meta-data",
          "http://[::1]/",
          "http://[fd00:ec2::254]/",
          "http://[::ffff:10.0.0.5]/",
        }) do
          responder_url = url
          ngx.shared.ocsp_response_cache:flush_all()
          spy.on(ngx, "log")

          assert.has_no.errors(certificate.call)

          assert.are.equal(0, #requests, url)
          assert.spy(ngx.log).was.called_with(ngx.ERR, "could not get OCSP response: ",
            match.matches("^refused OCSP responder URL " .. url:gsub("%p", "%%%0")))
          ngx.log:revert()
        end
      end)

      it("refuses responders with unsupported schemes", function()
        responder_url = "ftp://1.1.1.1/"
        spy.on(ngx, "log")

        assert.has_no.errors(certificate.call)

        assert.are.equal(0, #requests)
        assert.spy(ngx.log).was.called_with(ngx.ERR, "could not get OCSP response: ",
          match.is_string())
      end)

      it("refuses responder hostnames resolving to a non-public address", function()
        mock_dns({ "1.1.1.1", "10.0.0.5" })
        responder_url = "http://mixed-ocsp.example.com./"
        spy.on(ngx, "log")

        assert.has_no.errors(certificate.call)

        assert.are.equal(0, #requests)
        assert.spy(ngx.log).was.called_with(ngx.ERR, "could not get OCSP response: ",
          match.matches("non%-public address 10%.0%.0%.5"))
      end)

      it("connects to the resolved address of public responder hostnames", function()
        mock_dns({ "1.1.1.1" })
        responder_url = "http://public-ocsp.example.com./ocsp"

        assert.has_no.errors(certificate.call)

        assert.are.equal(1, #requests)
        assert.are.equal("http://1.1.1.1:80/ocsp", requests[1].uri)
        assert.are.equal("public-ocsp.example.com.", requests[1].params.headers["Host"])
      end)

      it("allows responders in ocsp-responder-allowed-cidrs", function()
        assert.is_nil(certificate.set_ocsp_responder_allowed_cidrs({ "10.0.0.0/8" }))
        responder_url = "http://10.0.0.5:8080/ocsp"

        assert.has_no.errors(certificate.call)

        assert.are.equal(1, #requests)
        assert.are.equal("http://10.0.0.5:8080/ocsp", requests[1].uri)
      end)

      it("rejects invalid ocsp-responder-allowed-cidrs", function()
        assert.are.equal("invalid CIDR nope",
          certificate.set_ocsp_responder_allowed_cidrs({ "10.0.0.0/8", "nope" }))
      end)
    end)
  end)

  describe("configured_for_current_request", function()
    before_each(function()
      local _ngx = { var = { host = "hostname" } }
      setmetatable(_ngx, {__index = _G.ngx})
      _G.ngx = _ngx
      ngx.ctx.cert_configured_for_current_request = nil

      package.loaded["certificate"] = nil
      certificate = require("certificate")

      set_certificate("hostname", EXAMPLE_CERT, UUID)
    end)

    it("returns true when certificate exists for given server", function()
      assert.is_true(certificate.configured_for_current_request())
    end)

    it("returns false when certificate does not exist for given server", function()
      ngx.var.host = "hostname.xyz"
      assert.is_false(certificate.configured_for_current_request())
    end)

    it("returns cached value from ngx.ctx", function()
      ngx.ctx.cert_configured_for_current_request = false
      assert.is_false(certificate.configured_for_current_request())
    end)
  end)
end)
