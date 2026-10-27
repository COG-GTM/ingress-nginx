local original_ngx = ngx
local function reset_ngx()
  _G.ngx = original_ngx
end

local function mock_ngx(mock)
  setmetatable(mock, { __index = original_ngx })
  _G.ngx = mock
end

describe("lua_ingress", function()
  it("patches math.randomseed to not be called more than once per worker", function()
    local s = spy.on(ngx, "log")

    math.randomseed(100)
    assert.spy(s).was_called_with(ngx.WARN,
      string.format("ignoring math.randomseed(%d) since PRNG is already seeded for worker %d", 100, ngx.worker.pid()))
  end)

  describe("rewrite()", function()
    local lua_ingress
    local redirect_spy
    local ngx_mock
    local var

    local function request(overrides)
      var = {
        scheme = "http",
        http_host = "app.acme.example",
        host = "app.acme.example",
        request_uri = "/password-reset",
        server_port = "80",
        pass_server_port = "80",
        force_ssl_redirect = "false",
        ssl_redirect = "false",
        force_no_ssl_redirect = "false",
        preserve_trailing_slash = "false",
        use_port_in_redirects = "false",
        http_x_forwarded_host = "evil.example",
        http_x_forwarded_proto = "https",
        http_x_forwarded_port = "8443",
      }
      for k, v in pairs(overrides or {}) do
        var[k] = v
      end
      ngx_mock.var = var
    end

    before_each(function()
      redirect_spy = spy.new(function() end)
      -- lua_ingress captures ngx and ngx.redirect when it is loaded
      ngx_mock = { redirect = redirect_spy, var = {} }
      mock_ngx(ngx_mock)
      local randomseed = math.randomseed
      lua_ingress = require_without_cache("lua_ingress")
      math.randomseed = randomseed
      lua_ingress.set_config({
        use_forwarded_headers = true,
        use_proxy_protocol = false,
        is_ssl_passthrough_enabled = false,
        http_redirect_code = 308,
        listen_ports = { ssl_proxy = "442", https = "443" },
      })
    end)

    after_each(function()
      reset_ngx()
      package.loaded["lua_ingress"] = nil
    end)

    it("honors X-Forwarded-* from a trusted proxy", function()
      request({ forwarded_headers_trusted = "1" })
      lua_ingress.rewrite()

      assert.are.equal("evil.example", var.best_http_host)
      assert.are.equal("https", var.pass_access_scheme)
      assert.are.equal("8443", var.pass_server_port)
    end)

    it("ignores X-Forwarded-* from an untrusted client", function()
      request({ forwarded_headers_trusted = "0" })
      lua_ingress.rewrite()

      assert.are.equal("app.acme.example", var.best_http_host)
      assert.are.equal("http", var.pass_access_scheme)
      assert.are.equal("80", var.pass_server_port)
    end)

    it("ignores X-Forwarded-* when the trust variable is not defined", function()
      request()
      lua_ingress.rewrite()

      assert.are.equal("app.acme.example", var.best_http_host)
      assert.are.equal("http", var.pass_access_scheme)
    end)

    it("ignores X-Forwarded-* when use-forwarded-headers is disabled", function()
      lua_ingress.set_config({
        use_forwarded_headers = false,
        http_redirect_code = 308,
        listen_ports = { ssl_proxy = "442", https = "443" },
      })
      request({ forwarded_headers_trusted = "1" })
      lua_ingress.rewrite()

      assert.are.equal("app.acme.example", var.best_http_host)
      assert.are.equal("http", var.pass_access_scheme)
    end)

    it("ignores invalid X-Forwarded-* values from a trusted proxy", function()
      request({
        forwarded_headers_trusted = "1",
        http_x_forwarded_host = "evil.example/@x",
        http_x_forwarded_proto = "myproto",
        http_x_forwarded_port = "99999",
      })
      lua_ingress.rewrite()

      assert.are.equal("app.acme.example", var.best_http_host)
      assert.are.equal("http", var.pass_access_scheme)
      assert.are.equal("80", var.pass_server_port)
    end)

    it("redirects untrusted clients to the original host", function()
      request({
        forwarded_headers_trusted = "0",
        force_ssl_redirect = "true",
        http_x_forwarded_proto = "http",
      })
      lua_ingress.rewrite()

      assert.spy(redirect_spy).was_called_with("https://app.acme.example/password-reset", 308)
    end)

    it("redirects trusted proxies to the forwarded host", function()
      request({
        forwarded_headers_trusted = "1",
        force_ssl_redirect = "true",
        http_x_forwarded_host = "public.acme.example",
        http_x_forwarded_proto = "http",
      })
      lua_ingress.rewrite()

      assert.spy(redirect_spy).was_called_with("https://public.acme.example/password-reset", 308)
    end)
  end)
end)
