-- Copyright 2018 Nick Peng (pymumu@gmail.com)

module("luci.controller.smartdns", package.seeall)
local smartdns = require "luci.model.smartdns"

function index()
	if not nixio.fs.access("/etc/config/smartdns") then
		return
	end

	local page
	page = entry({"admin", "services", "smartdns"}, cbi("smartdns"), _("SmartDNS"), 60)
	page.dependent = true
	page = entry({"admin", "services", "smartdns", "status"}, call("act_status"))
	page.leaf = true
end

local function is_running()
	return luci.sys.call("pidof smartdns >/dev/null") == 0
end

function act_status()
	local e={}
	e.ipv6_works = 2;
	e.ipv4_works = 2;
	e.redirect = smartdns.get_config_option("smartdns", "smartdns", "redirect", nil);
	e.local_port = smartdns.get_config_option("smartdns", "smartdns", "port", nil);
	if e.redirect == "1" then 
		if e.local_port ~= nil and e.local_port ~= "53" then
			e.ipv4_works = luci.sys.call("iptables -t nat -nL PREROUTING | grep REDIRECT | grep dpt:53 | grep %q >/dev/null 2>&1" % e.local_port) == 0
			e.ipv6_works = luci.sys.call("ip6tables -t nat -nL PREROUTING | grep REDIRECT | grep dpt:53 | grep %q >/dev/null 2>&1" % e.local_port) == 0
		else
			e.redirect = 0
		end
	end
	e.running = is_running()

	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
