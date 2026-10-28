local peer = require("util.peer")

describe("util.peer", function()

  describe("special_address_kind()", function()
    it("classifies loopback, unspecified and link-local addresses", function()
      for _, case in ipairs({
        { "127.0.0.1", "loopback", false },
        { "127.8.9.10", "loopback", false },
        { "0.0.0.0", "unspecified", false },
        { "0.1.2.3", "unspecified", false },
        { "169.254.169.254", "link-local", false },
        { "::1", "loopback", false },
        { "[::1]", "loopback", false },
        { "0:0:0:0:0:0:0:1", "loopback", false },
        { "::", "unspecified", false },
        { "[::]", "unspecified", false },
        { "fe80::1", "link-local", false },
        { "FEBF::abcd", "link-local", false },
        { "::ffff:127.0.0.1", "loopback", true },
        { "[::ffff:7f00:1]", "loopback", true },
        { "::FFFF:7F00:0001", "loopback", true },
        { "::ffff:0.0.0.0", "unspecified", true },
        { "::ffff:169.254.169.254", "link-local", true },
        { "::127.0.0.1", "loopback", true },
        { "0:0:0:0:0:ffff:127.0.0.1", "loopback", true },
      }) do
        local kind, embedded = peer.special_address_kind(case[1])
        assert.are.equal(case[2], kind, case[1])
        assert.are.equal(case[3], embedded, case[1])
      end
    end)

    it("does not flag regular addresses, hostnames or invalid input", function()
      for _, address in ipairs({
        "10.0.0.1", "192.168.1.1", "1.2.3.4", "128.0.0.1", "169.255.0.1",
        "2001:db8::1", "[2001:db8::1]", "fec0::1", "::ffff:10.0.0.1", "::ffff:1:7f00:1",
        "example.com", "localhost", "256.0.0.1", "1::2::3", ":::1", "12345::", "",
      }) do
        assert.is_nil(peer.special_address_kind(address), address)
      end
      assert.is_nil(peer.special_address_kind(nil))
    end)
  end)

  describe("split_host_port()", function()
    it("splits IPv4, bracketed IPv6 and hostname peers", function()
      for _, case in ipairs({
        { "10.0.0.1:80", "10.0.0.1", "80" },
        { "[::1]:10246", "::1", "10246" },
        { "[::ffff:7f00:1]:10246", "::ffff:7f00:1", "10246" },
        { "example.com:443", "example.com", "443" },
        { "10.0.0.1", "10.0.0.1", nil },
      }) do
        local host, port = peer.split_host_port(case[1])
        assert.are.equal(case[2], host)
        assert.are.equal(case[3], port)
      end
    end)
  end)

  describe("forbidden_reason()", function()
    local internal_ports = { ["10246"] = true, ["10247"] = true }

    it("refuses peers that reach the controller itself", function()
      for _, p in ipairs({
        "127.0.0.1:10246", "127.1.2.3:10246", "127.0.0.1:10247", "[::1]:10246",
        "0.0.0.0:10246", "0.0.0.0:80", "[::]:10246", "[::ffff:127.0.0.1]:10246",
        "[::ffff:7f00:1]:10246", "[::ffff:7f00:1]:8181", "[::127.0.0.1]:80",
        "169.254.169.254:80", "[fe80::1]:80",
      }) do
        assert.is_not_nil(peer.forbidden_reason(p, internal_ports), p)
      end
    end)

    it("allows the default backend and regular peers", function()
      for _, p in ipairs({
        "127.0.0.1:8181", "10.0.0.1:10246", "[2001:db8::1]:10246", "example.com:80",
      }) do
        assert.is_nil(peer.forbidden_reason(p, internal_ports), p)
      end
    end)
  end)
end)
