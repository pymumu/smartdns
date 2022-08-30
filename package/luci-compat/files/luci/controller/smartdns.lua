--
-- Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
	e.running = is_running()
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
