collectgarbage("collect")
-- init modules
local ok, res
ok, res = pcall(require, "configuration")
if not ok then
  error("require failed: " .. tostring(res))
else
  configuration = res
end
ok, res = pcall(require, "tcp_udp_configuration")
if not ok then
  error("require failed: " .. tostring(res))
else
  tcp_udp_configuration = res
end
ok, res = pcall(require, "tcp_udp_balancer")
if not ok then
  error("require failed: " .. tostring(res))
else
  tcp_udp_balancer = res
end
