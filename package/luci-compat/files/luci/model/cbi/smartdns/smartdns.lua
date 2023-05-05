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

require ("nixio.fs")
require ("luci.http")
require ("luci.dispatcher")
require ("nixio.fs")

local uci = require "luci.model.uci".cursor()

m = Map("smartdns")
m.title	= translate("SmartDNS Server")
m.description = translate("SmartDNS is a local high-performance DNS server, supports finding fastest IP, supports ad filtering, and supports avoiding DNS poisoning.")

m:section(SimpleSection).template  = "smartdns/smartdns_status"

-- Basic
s = m:section(TypedSection, "smartdns", translate("Settings"), translate("General Settings"))
s.anonymous = true

s:tab("settings", translate("General Settings"))
s:tab("advanced", translate('Advanced Settings'))
s:tab("seconddns", translate("Second Server Settings"))
s:tab("dns64", translate("DNS64 Server Settings"))
s:tab("proxy", translate("Proxy Server Settings"))
s:tab("custom", translate("Custom Settings"))

---- Eanble
o = s:taboption("settings", Flag, "enabled", translate("Enable"), translate("Enable or disable smartdns server"))
o.default     = o.disabled
o.rempty      = false

---- server name
o = s:taboption("settings", Value, "server_name", translate("Server Name"), translate("Smartdns server name"))
o.default     = "smartdns"
o.datatype    = "hostname"
o.rempty      = false

---- Port
o = s:taboption("settings", Value, "port", translate("Local Port"), 
    translate("Smartdns local server port, smartdns will be automatically set as main dns when the port is 53."))
o.placeholder = 53
o.default     = 53
o.datatype    = "port"
o.rempty      = false

-- Automatically Set Dnsmasq
o = s:taboption("settings", Flag, "auto_set_dnsmasq", translate("Automatically Set Dnsmasq"), translate("Automatically set as upstream of dnsmasq when port changes."))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- Speed check mode;
o = s:taboption("advanced", Value, "speed_check_mode", translate("Speed Check Mode"), translate("Smartdns speed check mode."));
o.rmempty = true;
o.placeholder = "default";
o.default = o.enabled;
o:value("", translate("default"))
o:value("ping,tcp:80,tcp:443");
o:value("ping,tcp:443,tcp:80");
o:value("tcp:80,tcp:443,ping");
o:value("tcp:443,tcp:80,ping");
o:value("none", translate("None"));
function o.validate (section_id, value) 
    if value == "" then
        return value
    end

    if value == nil then
        return nil, translate("Speed check mode is invalid.")
    end

    if value == "none" then
        return value
    end

    local mode = value:split(",");
    for _, v in ipairs(mode) do repeat
        if v == "ping" then
            break
        end

        if v == nil then
            return nil, translate("Speed check mode is invalid.")
        end
        
        local port = v:split(":");
        if "tcp" == port[1] then
            if tonumber(port[2]) then
                break
            end
        end
        
        return nil, translate("Speed check mode is invalid.")
    until true end

    return value
end

---- response mode;
o = s:taboption("advanced", ListValue, "response_mode", translate("Response Mode"), 
    translate("Smartdns response mode, First Ping: return the first ping IP, Fastest IP: return the fastest IP, Fastest Response: return the fastest DNS response."))
o.rmempty     = true
o.placeholder = "default"
o:value("", translate("default"))
o:value("first-ping", translate("First Ping"))
o:value("fastest-ip", translate("Fastest IP"))
o:value("fastest-response", translate("Fastest Response"))

---- Enable TCP server
o = s:taboption("advanced", Flag, "tcp_server", translate("TCP Server"), translate("Enable TCP DNS Server"))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

---- Support IPV6
o = s:taboption("advanced", Flag, "ipv6_server", translate("IPV6 Server"), translate("Enable IPV6 DNS Server"))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

---- bind to device;
o = s:taboption("advanced", Flag, "bind_device", translate("Bind Device"), translate("Listen only on the specified interfaces."))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

---- bind device name;
o = s:taboption("advanced", Value, "bind_device_name", translate("Bind Device Name"), translate("Name of device name listen on."))
o.placeholder = "default"
o.rempty      = true
o.datatype    = "string"

---- Support DualStack ip selection
o = s:taboption("advanced", Flag, "dualstack_ip_selection", translate("Dual-stack IP Selection"), translate("Enable IP selection between IPV4 and IPV6"))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- Domain prefetch load 
o = s:taboption("advanced", Flag, "prefetch_domain", translate("Domain prefetch"), translate("Enable domain prefetch, accelerate domain response speed."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- Domain Serve expired
o = s:taboption("advanced", Flag, "serve_expired", translate("Serve expired"), 
	translate("Attempts to serve old responses from cache with a TTL of 0 in the response without waiting for the actual resolution to finish."))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- cache-size
o = s:taboption("advanced", Value, "cache_size", translate("Cache Size"), translate("DNS domain result cache size"))
o.rempty      = true

---- cache-persist;
o = s:taboption("advanced", Flag, "cache_persist", translate("Cache Persist"), translate("Write cache to disk on exit and load on startup."))
o.rmempty      = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

-- cache-size
o = s:taboption("advanced", Flag, "resolve_local_hostnames", translate("Resolve Local Hostnames"), translate("Resolve local hostnames by reading Dnsmasq lease file."))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

-- Force AAAA SOA
o = s:taboption("advanced", Flag, "force_aaaa_soa", translate("Force AAAA SOA"), translate("Force AAAA SOA."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

-- Force HTTPS SOA
o = s:taboption("advanced", Flag, "force_https_soa", translate("Force HTTPS SOA"), translate("Force HTTPS SOA."))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

---- Ipset no speed.
o = s:taboption("advanced", Value, "ipset_no_speed", translate("No Speed IPset Name"), 
    translate("Ipset name, Add domain result to ipset when speed check fails."));
o.rmempty = true;
o.datatype = "hostname";
o.rempty = true;

---- NFTset no speed.
o = s:taboption("advanced", Value, "nftset_no_speed", translate("No Speed NFTset Name"), 
    translate("Nftset name, Add domain result to nftset when speed check fails, format: [#[4|6]:[family#table#set]]"));
o.rmempty    = true;
o.datatype   = "string";
o.rempty     = true;
function o.validate(self, value) 
    if (value == "") then
        return value
    end

    if (value:match("#[4|6]:[a-zA-Z0-9%-_]+#[a-zA-Z0-9%-_]+#[a-zA-Z0-9%-_]+$")) then
        return value
    end

    return nil, translate("NFTset name format error, format: [#[4|6]:[family#table#set]]")
end

---- rr-ttl
o = s:taboption("advanced", Value, "rr_ttl", translate("Domain TTL"), translate("TTL for all domain result."))
o.rempty      = true

---- rr-ttl-min
o = s:taboption("advanced", Value, "rr_ttl_min", translate("Domain TTL Min"), translate("Minimum TTL for all domain result."))
o.rempty      = true
o.placeholder = "600"
o.default     = 600
o.optional    = true

---- rr-ttl-max
o = s:taboption("advanced", Value, "rr_ttl_max", translate("Domain TTL Max"), translate("Maximum TTL for all domain result."))
o.rempty      = true

---- rr-ttl-reply-max
o = s:taboption("advanced", Value, "rr_ttl_reply_max", translate("Reply Domain TTL Max"), translate("Reply maximum TTL for all domain result."))
o.rempty      = true

o = s:taboption("advanced", DynamicList, "conf_files", translate("Include Config Files<br>/etc/smartdns/conf.d"),
    translate("Include other config files from /etc/smartdns/conf.d or custom path, can be downloaded from the download page."));
uci:foreach("smartdns", "download-file", function(section)
    local filetype = section.type
    if (filetype ~= 'config') then
        return
    end

    o:value(section.name);
end)

---- other args
o = s:taboption("advanced", Value, "server_flags", translate("Additional Server Args"), translate("Additional server args, refer to the help description of the bind option."))
o.default     = ""
o.rempty      = true
o.optional    = true

---- second dns server
---- Eanble
o = s:taboption("seconddns", Flag, "seconddns_enabled", translate("Enable"), translate("Enable or disable second DNS server."))
o.default     = o.disabled
o.rempty      = false

---- Port
o = s:taboption("seconddns", Value, "seconddns_port", translate("Local Port"), translate("Smartdns local server port"))
o.placeholder = 6553
o.default     = 6553
o.datatype    = "port"
o.rempty      = false

---- Enable TCP server
o = s:taboption("seconddns", Flag, "seconddns_tcp_server", translate("TCP Server"), translate("Enable TCP DNS Server"))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

---- dns server group
o = s:taboption("seconddns", Value, "seconddns_server_group", translate("Server Group"), translate("Query DNS through specific dns server group, such as office, home."))
o.rmempty     = true
o.placeholder = "default"
o.datatype    = "hostname"
o.rempty      = true

o = s:taboption("seconddns", Flag, "seconddns_no_speed_check", translate("Skip Speed Check"), translate("Do not check speed."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- skip address rules
o = s:taboption("seconddns", Flag, "seconddns_no_rule_addr", translate("Skip Address Rules"), translate("Skip address rules."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- skip name server rules
o = s:taboption("seconddns", Flag, "seconddns_no_rule_nameserver", translate("Skip Nameserver Rule"), translate("Skip nameserver rules."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- skip ipset rules
o = s:taboption("seconddns", Flag, "seconddns_no_rule_ipset", translate("Skip Ipset Rule"), translate("Skip ipset rules."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- skip soa address rule
o = s:taboption("seconddns", Flag, "seconddns_no_rule_soa", translate("Skip SOA Address Rule"), translate("Skip SOA address rules."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

o = s:taboption("seconddns", Flag, "seconddns_no_dualstack_selection", translate("Skip Dualstack Selection"), translate("Skip Dualstack Selection."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- skip cache
o = s:taboption("seconddns", Flag, "seconddns_no_cache", translate("Skip Cache"), translate("Skip Cache."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

---- Force AAAA SOA
o = s:taboption("seconddns", Flag, "seconddns_force_aaaa_soa", translate("Force AAAA SOA"), translate("Force AAAA SOA."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

o = s:taboption("seconddns", Value, "seconddns_ipset_name", translate("IPset Name"), translate("IPset name."))
o.rmempty = true
o.datatype = "hostname"
o.rempty = true

o = s:taboption("seconddns", Value, "seconddns_nftset_name", translate("NFTset Name"), translate("NFTset name, format: [#[4|6]:[family#table#set]]"))
o.rmempty = true
o.datatype = "string"
o.rempty = true
function o.validate(self, value) 
    if (value == "") then
        return value
    end

    if (value:match("#[4|6]:[a-zA-Z0-9%-_]+#[a-zA-Z0-9%-_]+#[a-zA-Z0-9%-_]+$")) then
        return value
    end

    return nil, translate("NFTset name format error, format: [#[4|6]:[family#table#set]]")
end

---- other args
o = s:taboption("seconddns", Value, "seconddns_server_flags", translate("Additional Server Args"),  translate("Additional server args, refer to the help description of the bind option."))
o.default     = ""
o.rempty      = true
o.optional    = true

----- Proxy server settings
o = s:taboption("proxy", Value, "proxy_server", translate("Proxy Server"), translate("Proxy Server URL, format: [socks5|http]://user:pass@ip:port."));
o.datatype = 'string';
function o.validate(self, value)
    if (value == "") then
        return true
    end

    if (not value:match("^http://") and not value:match("^socks5://")) then
        return nil, translate("Proxy server URL format error, format: [socks5|http]://user:pass@ip:port.")
    end

    return value
end

----- dns64 server settings
o = s:taboption("dns64", Value, "dns64", translate("DNS64"));
o.placeholder = "64:ff9b::/96"
o.datatype = 'ip6addr'
o.rmempty = true

----- custom settings
custom = s:taboption("custom", Value, "Custom Settings",
	translate(""), 
	translate("smartdns custom settings"))

custom.template = "cbi/tvalue"
custom.rows = 20

function custom.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/smartdns/custom.conf")
end

function custom.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("/etc/smartdns/custom.conf", value)
end

o = s:taboption("custom", Flag, "coredump", translate("Generate Coredump"), translate("Generate Coredump file when smartdns crash, coredump file is located at /tmp/smartdns.xxx.core."))
o.rmempty     = true
o.default     = o.disabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "0"
end

o = s:taboption("custom", Value, "log_size", translate("Log Size"))
o.rmempty = true
o.placeholder = "default"

o = s:taboption("custom", ListValue, "log_level", translate("Log Level"))
o.rmempty     = true
o.placeholder = "default"
o:value("", translate("default"))
o:value("debug")
o:value("info")
o:value("notice")
o:value("warn")
o:value("error")
o:value("fatal")
o:value("off")

o = s:taboption("custom", Value, "log_num", translate("Log Number"))
o.rmempty = true
o.placeholder = "default"

o = s:taboption("custom", Value, "log_file", translate("Log File"))
o.rmempty = true
o.placeholder = "/var/log/smartdns/smartdns.log"

-- Upstream servers
s = m:section(TypedSection, "server", translate("Upstream Servers"), translate("Upstream Servers, support UDP, TCP protocol. " ..
	"Please configure multiple DNS servers, including multiple foreign DNS servers."))
	
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
s.extedit  = luci.dispatcher.build_url("admin/services/smartdns/upstream/%s")

---- enable flag
o = s:option(Flag, "enabled", translate("Enable"), translate("Enable"))
o.rmempty     = false
o.default     = o.enabled
o.cfgvalue    = function(...)
    return Flag.cfgvalue(...) or "1"
end

---- name
s:option(Value, "name", translate("DNS Server Name"), translate("DNS Server Name"))

---- IP address
o = s:option(Value, "ip", translate("ip"), translate("DNS Server ip"))
o.datatype = "or(ipaddr, string)"
o.rmempty = false 
---- port
o = s:option(Value, "port", translate("port"), translate("DNS Server port"))
o.placeholder = "default"
o.datatype    = "port"
o.rempty      = true
o:depends("type", "udp")
o:depends("type", "tcp")
o:depends("type", "tls")

---- type
o = s:option(ListValue, "type", translate("type"), translate("DNS Server type"))
o.placeholder = "udp"
o:value("udp", translate("udp"))
o:value("tcp", translate("tcp"))
o:value("tls", translate("tls"))
o:value("https", translate("https"))
o.default     = "udp"
o.rempty      = false

---- domain rules;
s = m:section(TypedSection, "domain-rule", translate("Domain Rules"), translate("Domain Rules Settings"))
s.anonymous = true
s.nodescriptions = true

s:tab("forwarding", translate('DNS Forwarding Setting'))
s:tab("block", translate("DNS Block Setting"))
s:tab("domain-address", translate("Domain Address"), translate("Set Specific domain ip address."))
s:tab("blackip-list", translate("IP Blacklist"), translate("Set Specific ip blacklist."))

---- domain forwarding;
o = s:taboption("forwarding", Value, "server_group", translate("Server Group"), translate("DNS Server group belongs to, such as office, home."))
o.rmempty = true
o.placeholder = "default"
o.datatype = "hostname"
o.rempty = true
uci:foreach("smartdns", "server", function(section)
    local server_group = section.server_group
    if server_group == nil then
        return
    end
    o:value(server_group);
end)

function o.validate (section_id, value) 
    if value == "" then
        return value
    end

    if value == nil then
        return nil, translate('Server Group not exists')
    end

    local exists = false
    uci:foreach("smartdns", "server", function(section)
        local server_group = section.server_group
        if (exists == true) then
            return
        end

        if (value == server_group) then
            exists = true
        end
    end)

    if exists == false then
        return nil, translate('Server Group not exists')
    end

    return value;

end

o = s:taboption("forwarding", Flag, "no_speed_check", translate("Skip Speed Check"),
    translate("Do not check speed."))
o.rmempty = true
o.default = o.disabled

o = s:taboption("forwarding", Flag, "force_aaaa_soa", translate("Force AAAA SOA"), translate("Force AAAA SOA."))
o.rmempty = true
o.default = o.disabled

o = s:taboption("forwarding", Value, "ipset_name", translate("IPset Name"), translate("IPset name."))
o.rmempty = true
o.datatype = "hostname"
o.rempty = true

o = s:taboption("forwarding", Value, "nftset_name", translate("NFTset Name"), translate("NFTset name, format: [#[4|6]:[family#table#set]]"))
o.rmempty = true
o.datatype = "string"
o.rempty = true
function o.validate(self, value) 
    if (value == "") then
        return value
    end

    if (value:match("#[4|6]:[a-zA-Z0-9%-_]+#[a-zA-Z0-9%-_]+#[a-zA-Z0-9%-_]+$")) then
        return value
    end

    return nil, translate("NFTset name format error, format: [#[4|6]:[family#table#set]]")
end

---- other args
o = s:taboption("forwarding", Value, "addition_flag", translate("Additional Rule Flag"), translate("Additional Flags for rules, read help on domain-rule for more information."))
o.default = ""
o.rempty = true
o.modalonly = true;

o = s:taboption("forwarding", FileUpload, "forwarding_domain_set_file", translate("Domain List File"),
    translate("Upload domain list file, or configure auto download from Download File Setting page."))
o.rmempty = true
o.datatype = "file"
o.rempty = true
o.editable = true
o.root_directory = "/etc/smartdns/domain-set"

o = s:taboption("forwarding", TextValue, "domain_forwarding_list",
    translate("Domain List"), translate("Configure forwarding domain name list."))
o.rows = 10
o.cols = 64
o.monospace = true
function o.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/smartdns/domain-forwarding.list")
end
function o.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("/etc/smartdns/domain-forwarding.list", value)
end

---- domain block;
o = s:taboption("block", FileUpload, "block_domain_set_file", translate("Domain List File"), translate("Upload domain list file."))
o.rmempty = true
o.datatype = "file"
o.rempty = true
o.editable = true
o.root_directory = "/etc/smartdns/domain-set"

o = s:taboption("block", TextValue, "domain_block_list",
    translate("Domain List"), translate("Configure block domain list."))
o.rows = 10
o.cols = 64
function o.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/smartdns/domain-block.list")
end
function o.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("/etc/smartdns/domain-block.list", value)
end

-- Doman addresss
addr = s:taboption("domain-address", Value, "address",
	translate(""), 
	translate("Specify an IP address to return for any host in the given domains, Queries in the domains are never forwarded and always replied to with the specified IP address which may be IPv4 or IPv6."))

addr.template = "cbi/tvalue"
addr.rows = 20

function addr.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/smartdns/address.conf")
end

function addr.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("/etc/smartdns/address.conf", value)
end

-- IP Blacklist
addr = s:taboption("blackip-list", Value, "blacklist_ip",
	translate(""), 
	translate("Configure IP blacklists that will be filtered from the results of specific DNS server."))

addr.template = "cbi/tvalue"
addr.rows = 20

function addr.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/smartdns/blacklist-ip.conf")
end

function addr.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("/etc/smartdns/blacklist-ip.conf", value)
end

s = m:section(TypedSection, "smartdns", translate("Download Files Setting"), translate("Download domain list files for domain-rule and include config files, please refresh the page after download to take effect."))
s.anonymous = true

---- download Files Settings
o = s:option(Flag, "enable_auto_update", translate("Enable Auto Update"), translate("Enable daily auto update."))
o.rmempty = true
o.default = o.disabled
o.rempty = true

o = s:option(FileUpload, "upload_conf_file", translate("Upload Config File"),
    translate("Upload smartdns config file to /etc/smartdns/conf.d"))
o.rmempty = true
o.datatype = "file"
o.rempty = true
o.editable = true
o.root_directory = "/etc/smartdns/conf.d"

o = s:option(FileUpload, "upload_list_file", translate("Upload Domain List File"),
    translate("Upload domain list file to /etc/smartdns/domain-set"))
o.rmempty = true
o.datatype = "file"
o.rempty = true
o.editable = true
o.root_directory = "/etc/smartdns/domain-set"

o = s:option(Button, "_updateate")
o.title = translate("Update Files")
o.inputtitle = translate("Update Files")
o.inputstyle = "apply"
o.write = function()
	luci.sys.call("/etc/init.d/smartdns updatefiles >/dev/null 2>&1")
end

s = m:section(TypedSection, "download-file", translate("Download Files"), translate("List of files to download."))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Value, 'name', translate('File Name'), translate('File Name'))
o.rmempty = true
o.datatype = 'string'

o = s:option(Value, 'url', translate('URL'), translate('URL'))
o.rmempty = true
o.datatype = 'string'
function o.validate(self, value, section)
    if value == "" then
        return nil, translate("URL format error, format: http:// or https://")
    end

    if value == nil then
        return nil, translate("URL format error, format: http:// or https://")
    end

    if value.find(value, "http://") then
        return value
    end

    if value.find(value, "https://") then
        return value
    end

    return nil, translate("URL format error, format: http:// or https://")
end

o = s:option(ListValue, "type", translate("type"), translate("File Type"))
o:value("list", translate("domain list (/etc/smartdns/domain-set)"))
o:value("config", translate("smartdns config (/etc/smartdns/conf.d)"))
o.default = "list"
o.rempty = false

o = s:option(Value, 'desc', translate('Description'), translate('Description'))
o.rmempty = true
o.datatype = 'string'

-- Technical Support
s = m:section(TypedSection, "smartdns", translate("Technical Support"), 
	translate("If you like this software, please buy me a cup of coffee."))
s.anonymous = true

o = s:option(Button, "web")
o.title = translate("SmartDNS official website")
o.inputtitle = translate("open website")
o.inputstyle = "apply"
o.write = function()
	luci.http.redirect("https://pymumu.github.io/smartdns")
end

o = s:option(Button, "report")
o.title = translate("Report bugs")
o.inputtitle = translate("Report bugs")
o.inputstyle = "apply"
o.write = function()
	luci.http.redirect("https://github.com/pymumu/smartdns/issues")
end

o = s:option(Button, "Donate")
o.title = translate("Donate to smartdns")
o.inputtitle = translate("Donate")
o.inputstyle = "apply"
o.write = function()
	luci.http.redirect("https://pymumu.github.io/smartdns/#donate")
end

o = s:option(Button, "Restart")
o.title = translate("Restart Service")
o.inputtitle = translate("Restart")
o.inputstyle = "apply"
o.write = function()
	luci.sys.call("/etc/init.d/smartdns restart >/dev/null 2>&1")
end

return m

