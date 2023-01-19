--
-- Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
--
-- smartdns is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- smartdns is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

module("luci.controller.smartdns", package.seeall)
local smartdns = require "luci.model.smartdns"

function index()
	if not nixio.fs.access("/etc/config/smartdns") then
		return
	end

	local page
	page = entry({"admin", "services", "smartdns"}, cbi("smartdns/smartdns"), _("SmartDNS"), 60)
	page.dependent = true
	page = entry({"admin", "services", "smartdns", "status"}, call("act_status"))
	page.leaf = true
	page = entry({"admin", "services", "smartdns", "upstream"}, cbi("smartdns/upstream"), nil)
	page.leaf = true
end

local function is_running()
	return luci.sys.call("pidof smartdns >/dev/null") == 0
end

function act_status()
	local e={}
	local ipv6_server;
	local dnsmasq_server = smartdns.get_config_option("dhcp", "dnsmasq", "server", {nil})[1]
	local auto_set_dnsmasq = smartdns.get_config_option("smartdns", "smartdns", "auto_set_dnsmasq", nil);
	
	e.auto_set_dnsmasq = auto_set_dnsmasq
	e.dnsmasq_server = dnsmasq_server
	e.local_port = smartdns.get_config_option("smartdns", "smartdns", "port", nil);
	if e.local_port ~= nil and e.local_port ~= "53" and auto_set_dnsmasq ~= nil and auto_set_dnsmasq == "1" then
		local str;
		str = "127.0.0.1#" .. e.local_port 
		if dnsmasq_server ~= str then
			e.dnsmasq_redirect_failure = 1
		end
	end
	e.running = is_running()
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
