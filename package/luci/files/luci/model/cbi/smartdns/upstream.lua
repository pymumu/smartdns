local sid = arg[1]

m = Map("smartdns", "%s - %s" %{translate("SmartDNS Server"), translate("Upstream DNS Server Configuration")})
m.redirect = luci.dispatcher.build_url("admin/services/smartdns")

if m.uci:get("smartdns", sid) ~= "server" then
	luci.http.redirect(m.redirect)
	return
end

-- [[ Edit Server ]]--
s = m:section(NamedSection, sid, "server")
s.anonymous = true
s.addremove   = false

---- blacklist_ip
o = s:option(Flag, "blacklist_ip", translate("IP Blacklist Filtering"), translate("Filtering IP with blacklist"))
o.rmempty     = false
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

return m