-- Copyright 2018 Nick Peng (pymumu@gmail.com)

module("luci.controller.smartdns", package.seeall)

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
	e.running = is_running()
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
