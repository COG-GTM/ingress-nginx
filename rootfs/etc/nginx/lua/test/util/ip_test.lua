local ip = require("util.ip")

describe("util.ip", function()
  describe("is_ip", function()
    it("recognizes IPv4 and IPv6 literals", function()
      for _, address in ipairs({ "1.2.3.4", "255.255.255.255", "::1", "::", "2001:db8::1",
          "fe80::1:2:3:4", "1:2:3:4:5:6:7:8", "::ffff:10.0.0.1", "64:ff9b::1.2.3.4" }) do
        assert.is_true(ip.is_ip(address), address)
      end
    end)

    it("rejects anything else", function()
      for _, address in ipairs({ "", "example.com", "1.2.3", "1.2.3.4.5", "256.1.1.1",
          "010.0.0.1", "0x7f.0.0.1", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::1", "[::1]",
          ":::1", "1:2:3:4:5:6:7:1.2.3.4" }) do
        assert.is_false(ip.is_ip(address), address)
      end
      assert.is_false(ip.is_ip(nil))
    end)
  end)

  describe("is_public", function()
    it("returns true for globally routable unicast addresses", function()
      for _, address in ipairs({ "1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1",
          "2606:4700:4700::1111", "2a00:1450:4001::200e", "::ffff:8.8.8.8",
          "64:ff9b::808:808", "2002:808:808::1" }) do
        assert.is_true(ip.is_public(address), address)
      end
    end)

    it("returns false for loopback, private, link-local, metadata and reserved addresses",
      function()
      for _, address in ipairs({ "0.0.0.0", "127.0.0.1", "127.255.255.254", "10.0.0.5",
          "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1",
          "100.100.100.200", "192.0.0.192", "198.18.0.1", "224.0.0.1", "255.255.255.255",
          "::", "::1", "fd00::1", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1",
          "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:a00:1", "::10.0.0.1",
          "64:ff9b::a00:1", "64:ff9b:1::1", "2002:a00:1::1", "2001:db8::1" }) do
        assert.is_false(ip.is_public(address), address)
      end
    end)

    it("returns false for non IP input", function()
      assert.is_false(ip.is_public("localhost"))
      assert.is_false(ip.is_public(nil))
    end)
  end)

  describe("parse_cidrs and in_cidrs", function()
    it("matches addresses in the given networks", function()
      local cidrs = assert(ip.parse_cidrs({ "10.96.0.0/12", "192.168.1.7", "fd00::/8" }))

      assert.is_true(ip.in_cidrs("10.96.0.1", cidrs))
      assert.is_true(ip.in_cidrs("10.111.255.255", cidrs))
      assert.is_false(ip.in_cidrs("10.112.0.0", cidrs))
      assert.is_true(ip.in_cidrs("192.168.1.7", cidrs))
      assert.is_false(ip.in_cidrs("192.168.1.8", cidrs))
      assert.is_true(ip.in_cidrs("fd12::1", cidrs))
      assert.is_false(ip.in_cidrs("fe80::1", cidrs))
      assert.is_false(ip.in_cidrs("example.com", cidrs))
      assert.is_false(ip.in_cidrs("10.96.0.1", nil))
    end)

    it("returns an error for invalid entries", function()
      local cidrs, err = ip.parse_cidrs({ "10.0.0.0/8", "not-a-cidr" })
      assert.is_nil(cidrs)
      assert.are.equal("invalid CIDR not-a-cidr", err)

      cidrs, err = ip.parse_cidrs({ "10.0.0.0/33" })
      assert.is_nil(cidrs)
      assert.are.equal("invalid CIDR 10.0.0.0/33", err)
    end)
  end)
end)
