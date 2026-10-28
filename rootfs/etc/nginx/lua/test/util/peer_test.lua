local peer = require("util.peer")

describe("util.peer", function()
  describe("split()", function()
    it("splits IPv4, bracketed IPv6 and host peers", function()
      for _, case in ipairs({
        { "10.0.0.1:8080", "10.0.0.1", "8080" },
        { "[::ffff:7f00:1]:10246", "::ffff:7f00:1", "10246" },
        { "[2001:db8::1]:443", "2001:db8::1", "443" },
        { "example.com:80", "example.com", "80" },
        { "10.0.0.1", "10.0.0.1", nil },
      }) do
        local address, port = peer.split(case[1])
        assert.are.equal(case[2], address)
        assert.are.equal(case[3], port)
      end
    end)
  end)

  describe("is_local()", function()
    it("rejects loopback, unspecified and IPv4-mapped loopback peers on any port", function()
      for _, p in ipairs({
        "127.0.0.1:10246",
        "127.0.0.1:10247",
        "127.0.0.1:80",
        "127.1.2.3:10247",
        "127.000.000.001:10247",
        "0.0.0.0:10246",
        "0.0.0.0:10247",
        "0.1.2.3:10247",
        "[::1]:10246",
        "[::]:10247",
        "[0:0:0:0:0:0:0:1]:10247",
        "[::ffff:127.0.0.1]:10246",
        "[::ffff:7f00:1]:10246",
        "[::FFFF:7F00:1]:10247",
        "[0:0:0:0:0:ffff:7f00:1]:10247",
        "[::ffff:0.0.0.0]:10247",
        "[::ffff:0:0]:10247",
        "[::127.0.0.1]:10247",
        "[::1%eth0]:10247",
        "localhost:10247",
        "LocalHost.:10246",
        "foo.localhost:10247",
        "::1:10247",
        "",
      }) do
        assert.is_true(peer.is_local(p), p)
      end
    end)

    it("allows non-local peers", function()
      for _, p in ipairs({
        "10.184.7.40:8080",
        "192.168.1.1:10246",
        "1.27.0.1:10247",
        "128.0.0.1:10246",
        "[2001:db8::1]:10246",
        "[::ffff:10.0.0.1]:10247",
        "[::ffff:8.8.8.8]:53",
        "[fe80::1]:10247",
        "[64:ff9b::7f00:1]:10247",
        "example.com:10247",
        "notlocalhost:10247",
        "2001:db8::1:443",
      }) do
        assert.is_false(peer.is_local(p), p)
      end
    end)
  end)
end)
