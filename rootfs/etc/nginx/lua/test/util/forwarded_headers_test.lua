local original_ngx = ngx
local function reset_ngx()
  _G.ngx = original_ngx
end

local function mock_ngx_var(var)
  local _ngx = { var = var }
  setmetatable(_ngx, { __index = original_ngx })
  _G.ngx = _ngx
end

describe("forwarded_headers", function()
  local forwarded_headers = require("util.forwarded_headers")

  after_each(function()
    reset_ngx()
  end)

  describe("trusted()", function()
    it("is true only when the connection comes from proxy-real-ip-cidr", function()
      mock_ngx_var({ forwarded_headers_trusted = "1" })
      assert.is_true(forwarded_headers.trusted())

      mock_ngx_var({ forwarded_headers_trusted = "0" })
      assert.is_false(forwarded_headers.trusted())

      mock_ngx_var({})
      assert.is_false(forwarded_headers.trusted())
    end)
  end)

  describe("host()", function()
    it("returns the first valid X-Forwarded-Host entry", function()
      local cases = {
        ["myhost.com"] = "myhost.com",
        ["myhost.com, another.host,example.net"] = "myhost.com",
        ["  myhost.com:8443 "] = "myhost.com:8443",
        ["10.0.0.1:80"] = "10.0.0.1:80",
        ["[2001:db8::1]:443"] = "[2001:db8::1]:443",
      }
      for header, expected in pairs(cases) do
        mock_ngx_var({ http_x_forwarded_host = header })
        assert.are.equal(expected, forwarded_headers.host())
      end
    end)

    it("rejects values that are not a host[:port]", function()
      local cases = {
        "evil.example/path",
        "user@evil.example",
        "evil.example:port",
        "evil example",
        "evil.example\r\nX-Injected: 1",
        "",
        " , evil.example",
        "-evil.example",
        string.rep("a", 300),
      }
      for _, header in ipairs(cases) do
        mock_ngx_var({ http_x_forwarded_host = header })
        assert.is_nil(forwarded_headers.host(), header)
      end

      mock_ngx_var({})
      assert.is_nil(forwarded_headers.host())
    end)
  end)

  describe("proto()", function()
    it("accepts only http and https", function()
      mock_ngx_var({ http_x_forwarded_proto = "https" })
      assert.are.equal("https", forwarded_headers.proto())

      mock_ngx_var({ http_x_forwarded_proto = "HTTP" })
      assert.are.equal("http", forwarded_headers.proto())

      mock_ngx_var({ http_x_forwarded_proto = "https, http" })
      assert.are.equal("https", forwarded_headers.proto())

      for _, header in ipairs({ "myproto", "javascript", "https://evil", "" }) do
        mock_ngx_var({ http_x_forwarded_proto = header })
        assert.is_nil(forwarded_headers.proto(), header)
      end
    end)
  end)

  describe("port()", function()
    it("accepts only numeric ports between 1 and 65535", function()
      mock_ngx_var({ http_x_forwarded_port = "1234" })
      assert.are.equal("1234", forwarded_headers.port())

      mock_ngx_var({ http_x_forwarded_port = "443, 80" })
      assert.are.equal("443", forwarded_headers.port())

      for _, header in ipairs({ "0", "65536", "80abc", "-1", "" }) do
        mock_ngx_var({ http_x_forwarded_port = header })
        assert.is_nil(forwarded_headers.port(), header)
      end
    end)
  end)
end)
