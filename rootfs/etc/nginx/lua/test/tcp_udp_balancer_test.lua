local ngx_balancer = require("ngx.balancer")

local tcp_udp_balancer
local original_ngx = ngx

local function mock_upstream(name)
  local _ngx = { var = { proxy_upstream_name = name } }
  setmetatable(_ngx, { __index = original_ngx })
  _G.ngx = _ngx
  package.loaded["tcp_udp_balancer"] = nil
  tcp_udp_balancer = require("tcp_udp_balancer")
end

describe("TCP/UDP Balancer", function()
  before_each(function()
    stub(ngx_balancer, "set_current_peer", function() return true end)
    stub(ngx_balancer, "set_more_tries")
  end)

  after_each(function()
    ngx_balancer.set_current_peer:revert()
    ngx_balancer.set_more_tries:revert()
    _G.ngx = original_ngx
  end)

  describe("balance()", function()
    local function balance_to(address, port)
      local name = "tcp-test-" .. address .. "-" .. port
      mock_upstream(name)
      -- the first sync only creates the balancer, the second one formats endpoints
      for _ = 1, 2 do
        tcp_udp_balancer.sync_backend({
          name = name,
          endpoints = { { address = address, port = port } },
        })
      end
      tcp_udp_balancer.balance()
    end

    it("refuses loopback, unspecified and IPv4-mapped loopback peers on any port", function()
      for _, case in ipairs({
        { "127.0.0.1", "10246" },
        { "127.0.0.1", "10247" },
        { "0.0.0.0", "10246" },
        { "0.0.0.0", "10247" },
        { "::1", "10247" },
        { "::", "10247" },
        { "::ffff:127.0.0.1", "10246" },
        { "::ffff:7f00:1", "10246" },
      }) do
        balance_to(case[1], case[2])
      end
      assert.stub(ngx_balancer.set_current_peer).was_not_called()
    end)

    it("proxies to remote peers", function()
      balance_to("10.184.7.40", "5432")
      assert.stub(ngx_balancer.set_current_peer).was_called_with("10.184.7.40:5432")

      balance_to("2001:db8::1", "5432")
      assert.stub(ngx_balancer.set_current_peer).was_called_with("[2001:db8::1]:5432")
    end)
  end)
end)
