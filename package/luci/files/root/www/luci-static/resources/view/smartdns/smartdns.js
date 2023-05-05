/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


'use strict';
'require fs';
'require uci';
'require form';
'require view';
'require poll';
'require rpc';
'require ui';

var conf = 'smartdns';
var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});
var pollAdded = false;

function getServiceStatus() {
	return L.resolveDefault(callServiceList(conf), {})
		.then(function (res) {
			var is_running = false;
			try {
				is_running = res[conf]['instances']['smartdns']['running'];
			} catch (e) { }
			return is_running;
		});
}

function smartdnsServiceStatus() {
	return Promise.all([
		getServiceStatus()
	]);
}

function smartdnsRenderStatus(res) {
	var renderHTML = "";
	var isRunning = res[0];

	var autoSetDnsmasq = uci.get_first('smartdns', 'smartdns', 'auto_set_dnsmasq');
	var smartdnsPort = uci.get_first('smartdns', 'smartdns', 'port');
	var dnsmasqServer = uci.get_first('dhcp', 'dnsmasq', 'server');

	if (isRunning) {
		renderHTML += "<span style=\"color:green;font-weight:bold\">SmartDNS - " + _("RUNNING") + "</span>";
	} else {
		renderHTML += "<span style=\"color:red;font-weight:bold\">SmartDNS - " + _("NOT RUNNING") + "</span>";
		return renderHTML;
	}

	if (autoSetDnsmasq === '1' && smartdnsPort != '53') {
		var matchLine = "127.0.0.1#" + smartdnsPort;

		uci.unload('dhcp');
		uci.load('dhcp');
		if (dnsmasqServer == undefined || dnsmasqServer.indexOf(matchLine) < 0) {
			renderHTML += "<br /><span style=\"color:red;font-weight:bold\">" + _("Dnsmasq Forwarded To Smartdns Failure") + "</span>";
		}
	}

	return renderHTML;
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load('dhcp'),
			uci.load('smartdns'),
		]);
	},
	render: function (stats) {
		var m, s, o;
		var ss, so;
		var servers, download_files;

		m = new form.Map('smartdns', _('SmartDNS'));
		m.title = _("SmartDNS Server");
		m.description = _("SmartDNS is a local high-performance DNS server, supports finding fastest IP, "
			+ "supports ad filtering, and supports avoiding DNS poisoning.");

		s = m.section(form.NamedSection, '_status');
		s.anonymous = true;
		s.render = function (section_id) {
			var renderStatus = function () {
				return L.resolveDefault(smartdnsServiceStatus()).then(function (res) {
					var view = document.getElementById("service_status");
					if (view == null) {
						return;
					}

					view.innerHTML = smartdnsRenderStatus(res);
				});
			}

			if (pollAdded == false) {
				poll.add(renderStatus, 1);
				pollAdded = true;
			}

			return E('div', { class: 'cbi-section' }, [
				E('div', { id: 'service_status' },
					_('Collecting data ...'))
			]);
		}

		////////////////
		// Basic;
		////////////////
		s = m.section(form.TypedSection, "smartdns", _("Settings"), _("General Settings"));
		s.anonymous = true;

		s.tab("settings", _("General Settings"));
		s.tab("advanced", _('Advanced Settings'));
		s.tab("seconddns", _("Second Server Settings"));
		s.tab("dns64", _("DNS64 Server Settings"));
		s.tab("files", _("Download Files Setting"), _("Download domain list files for domain-rule and include config files, please refresh the page after download to take effect."));
		s.tab("proxy", _("Proxy Server Settings"));
		s.tab("custom", _("Custom Settings"));

		///////////////////////////////////////
		// Basic Settings
		///////////////////////////////////////
		o = s.taboption("settings", form.Flag, "enabled", _("Enable"), _("Enable or disable smartdns server"));
		o.rmempty = false;
		o.default = o.disabled;

		// server name;
		o = s.taboption("settings", form.Value, "server_name", _("Server Name"), _("Smartdns server name"));
		o.default = "smartdns";
		o.datatype = "hostname";
		o.rempty = false;

		// Port;
		o = s.taboption("settings", form.Value, "port", _("Local Port"),
			_("Smartdns local server port, smartdns will be automatically set as main dns when the port is 53."));
		o.placeholder = 53;
		o.default = 53;
		o.datatype = "port";
		o.rempty = false;
		
		// auto-conf-dnsmasq;
		o = s.taboption("settings", form.Flag, "auto_set_dnsmasq", _("Automatically Set Dnsmasq"), _("Automatically set as upstream of dnsmasq when port changes."));
		o.rmempty = false;
		o.default = o.enabled;

		///////////////////////////////////////
		// advanced settings;
		///////////////////////////////////////
		// Speed check mode;
		o = s.taboption("advanced", form.Value, "speed_check_mode", _("Speed Check Mode"), _("Smartdns speed check mode."));
		o.rmempty = true;
		o.placeholder = "default";
		o.value("", _("default"));
		o.value("ping,tcp:80,tcp:443");
		o.value("ping,tcp:443,tcp:80");
		o.value("tcp:80,tcp:443,ping");
		o.value("tcp:443,tcp:80,ping");
		o.value("none", _("None"));
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			if (value == "none") {
				return true;
			}

			var check_mode = value.split(",")
			for (var i = 0; i < check_mode.length; i++) {
				if (check_mode[i] == "ping") {
					continue;
				}

				if (check_mode[i].indexOf("tcp:") == 0) {
					var port = check_mode[i].split(":")[1];
					if (port == "") {
						return _("TCP port is empty");
					}

					continue;
				}

				return _("Speed check mode is invalid.");
			}

			return true;
		}

		// response mode;
		o = s.taboption("advanced", form.ListValue, "response_mode", _("Response Mode"),
			_("Smartdns response mode, First Ping: return the first ping IP, Fastest IP: return the fastest IP, Fastest Response: return the fastest DNS response."));
		o.rmempty = true;
		o.placeholder = "default";
		o.value("", _("default"));
		o.value("first-ping", _("First Ping"));
		o.value("fastest-ip", _("Fastest IP"));
		o.value("fastest-response", _("Fastest Response"));

		// Enable TCP server;
		o = s.taboption("advanced", form.Flag, "tcp_server", _("TCP Server"), _("Enable TCP DNS Server"));
		o.rmempty = false;
		o.default = o.enabled;

		// Support IPV6;
		o = s.taboption("advanced", form.Flag, "ipv6_server", _("IPV6 Server"), _("Enable IPV6 DNS Server"));
		o.rmempty = false;
		o.default = o.enabled;

		// bind to device;
		o = s.taboption("advanced", form.Flag, "bind_device", _("Bind Device"), _("Listen only on the specified interfaces."));
		o.rmempty = false;
		o.default = o.enabled;

		// bind device name;
		o = s.taboption("advanced", form.Value, "bind_device_name", _("Bind Device Name"), _("Name of device name listen on."));
		o.placeholder = "default";
		o.rempty = true;
		o.datatype = "string";

		// Support DualStack ip selection;
		o = s.taboption("advanced", form.Flag, "dualstack_ip_selection", _("Dual-stack IP Selection"),
			_("Enable IP selection between IPV4 and IPV6"));
		o.rmempty = false;
		o.default = o.enabled;

		// Domain prefetch load ;
		o = s.taboption("advanced", form.Flag, "prefetch_domain", _("Domain prefetch"),
			_("Enable domain prefetch, accelerate domain response speed."));
		o.rmempty = true;
		o.default = o.disabled;

		// Domain Serve expired
		o = s.taboption("advanced", form.Flag, "serve_expired", _("Serve expired"),
			_("Attempts to serve old responses from cache with a TTL of 0 in the response without waiting for the actual resolution to finish."));
		o.rmempty = false;
		o.default = o.enabled;

		// cache-size;
		o = s.taboption("advanced", form.Value, "cache_size", _("Cache Size"), _("DNS domain result cache size"));
		o.rempty = true;

		// cache-persist;
		o = s.taboption("advanced", form.Flag, "cache_persist", _("Cache Persist"), _("Write cache to disk on exit and load on startup."));
		o.rmempty = false;
		o.default = o.enabled;

		// cache-size;
		o = s.taboption("advanced", form.Flag, "resolve_local_hostnames", _("Resolve Local Hostnames"), _("Resolve local hostnames by reading Dnsmasq lease file."));
		o.rmempty = false;
		o.default = o.enabled;

		// Force AAAA SOA
		o = s.taboption("advanced", form.Flag, "force_aaaa_soa", _("Force AAAA SOA"), _("Force AAAA SOA."));
		o.rmempty = true;
		o.default = o.disabled;

		// Force HTTPS SOA
		o = s.taboption("advanced", form.Flag, "force_https_soa", _("Force HTTPS SOA"), _("Force HTTPS SOA."));
		o.rmempty = false;
		o.default = o.enabled;

		// Ipset no speed.
		o = s.taboption("advanced", form.Value, "ipset_no_speed", _("No Speed IPset Name"), 
			_("Ipset name, Add domain result to ipset when speed check fails."));
		o.rmempty = true;
		o.datatype = "string";
		o.rempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var ipset = value.split(",")
			for (var i = 0; i < ipset.length; i++) {
				if (!ipset[i].match(/^(#[4|6]:)?[a-zA-Z0-9\-_]+$/)) {
					return _("ipset name format error, format: [#[4|6]:]ipsetname");
				}
			}

			return true;
		}

		// NFTset no speed.
		o = s.taboption("advanced", form.Value, "nftset_no_speed", _("No Speed NFTset Name"), 
			_("Nftset name, Add domain result to nftset when speed check fails, format: [#[4|6]:[family#table#set]]"));
		o.rmempty = true;
		o.datatype = "string";
		o.rempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var nftset = value.split(",")
			for (var i = 0; i < nftset.length; i++) {
				if (!nftset[i].match(/^#[4|6]:[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+$/)) {
					return _("NFTset name format error, format: [#[4|6]:[family#table#set]]");
				}
			}

			return true;
		}

		// rr-ttl;
		o = s.taboption("advanced", form.Value, "rr_ttl", _("Domain TTL"), _("TTL for all domain result."));
		o.rempty = true;

		// rr-ttl-min;
		o = s.taboption("advanced", form.Value, "rr_ttl_min", _("Domain TTL Min"),
			_("Minimum TTL for all domain result."));
		o.rempty = true;
		o.placeholder = "600";
		o.default = 600;
		o.optional = true;

		// rr-ttl-max;
		o = s.taboption("advanced", form.Value, "rr_ttl_max", _("Domain TTL Max"),
			_("Maximum TTL for all domain result."));
		o.rempty = true;

		// rr-ttl-reply-max;
		o = s.taboption("advanced", form.Value, "rr_ttl_reply_max", _("Reply Domain TTL Max"),
			_("Reply maximum TTL for all domain result."));
		o.rempty = true;

		// other args
		o = s.taboption("advanced", form.Value, "server_flags", _("Additional Server Args"), 
			_("Additional server args, refer to the help description of the bind option."))
		o.default = ""
		o.rempty = true

		// include config
		download_files = uci.sections('smartdns', 'download-file');
		o = s.taboption("advanced", form.DynamicList, "conf_files", _("Include Config Files<br>/etc/smartdns/conf.d"),
			_("Include other config files from /etc/smartdns/conf.d or custom path, can be downloaded from the download page."));
		for (var i = 0; i < download_files.length; i++) {
			if (download_files[i].type == undefined) {
				continue;
			}

			if (download_files[i].type != 'config') {
				continue
			}

			o.value(download_files[i].name);
		}

		///////////////////////////////////////
		// second dns server;
		///////////////////////////////////////
		// Enable;
		o = s.taboption("seconddns", form.Flag, "seconddns_enabled", _("Enable"),
			_("Enable or disable second DNS server."));
		o.default = o.disabled;
		o.rempty = true;

		// Port;
		o = s.taboption("seconddns", form.Value, "seconddns_port", _("Local Port"), _("Smartdns local server port"));
		o.placeholder = 6553;
		o.default = 6553;
		o.datatype = "port";
		o.rempty = false;

		// Enable TCP server;
		o = s.taboption("seconddns", form.Flag, "seconddns_tcp_server", _("TCP Server"), _("Enable TCP DNS Server"));
		o.rmempty = false;
		o.default = o.enabled;

		// dns server group;
		o = s.taboption("seconddns", form.Value, "seconddns_server_group", _("Server Group"),
			_("Query DNS through specific dns server group, such as office, home."));
		o.rmempty = true;
		o.placeholder = "default";
		o.datatype = "hostname";
		o.rempty = true;

		o = s.taboption("seconddns", form.Flag, "seconddns_no_speed_check", _("Skip Speed Check"),
			_("Do not check speed."));
		o.rmempty = true;
		o.default = o.disabled;

		// skip address rules;
		o = s.taboption("seconddns", form.Flag, "seconddns_no_rule_addr", _("Skip Address Rules"),
			_("Skip address rules."));
		o.rmempty = true;
		o.default = o.disabled;

		// skip name server rules;
		o = s.taboption("seconddns", form.Flag, "seconddns_no_rule_nameserver", _("Skip Nameserver Rule"),
			_("Skip nameserver rules."));
		o.rmempty = true;
		o.default = o.disabled;

		// skip ipset rules;
		o = s.taboption("seconddns", form.Flag, "seconddns_no_rule_ipset", _("Skip Ipset Rule"),
			_("Skip ipset rules."));
		o.rmempty = true;
		o.default = o.disabled;

		// skip soa address rule;
		o = s.taboption("seconddns", form.Flag, "seconddns_no_rule_soa", _("Skip SOA Address Rule"),
			_("Skip SOA address rules."));
		o.rmempty = true;
		o.default = o.disabled;

		o = s.taboption("seconddns", form.Flag, "seconddns_no_dualstack_selection", _("Skip Dualstack Selection"),
			_("Skip Dualstack Selection."));
		o.rmempty = true;
		o.default = o.disabled;

		// skip cache;
		o = s.taboption("seconddns", form.Flag, "seconddns_no_cache", _("Skip Cache"), _("Skip Cache."));
		o.rmempty = true;
		o.default = o.disabled;

		// Force AAAA SOA
		o = s.taboption("seconddns", form.Flag, "seconddns_force_aaaa_soa", _("Force AAAA SOA"), _("Force AAAA SOA."));
		o.rmempty = true;
		o.default = o.disabled;

		o = s.taboption("seconddns", form.Value, "seconddns_ipset_name", _("IPset Name"), _("IPset name."));
		o.rmempty = true;
		o.datatype = "string";
		o.rempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var ipset = value.split(",")
			for (var i = 0; i < ipset.length; i++) {
				if (!ipset[i].match(/^(#[4|6]:)?[a-zA-Z0-9\-_]+$/)) {
					return _("ipset name format error, format: [#[4|6]:]ipsetname");
				}
			}

			return true;
		}

		o = s.taboption("seconddns", form.Value, "seconddns_nftset_name", _("NFTset Name"), _("NFTset name, format: [#[4|6]:[family#table#set]]"));
		o.rmempty = true;
		o.datatype = "string";
		o.rempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var nftset = value.split(",")
			for (var i = 0; i < nftset.length; i++) {
				if (!nftset[i].match(/^#[4|6]:[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+$/)) {
					return _("NFTset name format error, format: [#[4|6]:[family#table#set]]");
				}
			}

			return true;
		}

		// other args
		o = s.taboption("seconddns", form.Value, "seconddns_server_flags", _("Additional Server Args"), 
			_("Additional server args, refer to the help description of the bind option."))
		o.default = ""
		o.rempty = true

		///////////////////////////////////////
		// DNS64 Settings
		///////////////////////////////////////
		o = s.taboption("dns64", form.Value, "dns64", _("DNS64"));
		o.placeholder = "64:ff9b::/96";
		o.datatype = "ip6addr";
		o.rempty = true;

		///////////////////////////////////////
		// download Files Settings
		///////////////////////////////////////
		o = s.taboption("files", form.Flag, "enable_auto_update", _("Enable Auto Update"), _("Enable daily auto update."));
		o.rmempty = true;
		o.default = o.disabled;
		o.rempty = true;

		o = s.taboption("files", form.FileUpload, "upload_conf_file", _("Upload Config File"),
			_("Upload smartdns config file to /etc/smartdns/conf.d"));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.root_directory = "/etc/smartdns/conf.d"

		o = s.taboption("files", form.FileUpload, "upload_list_file", _("Upload Domain List File"),
			_("Upload domain list file to /etc/smartdns/domain-set"));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.root_directory = "/etc/smartdns/domain-set"

		o = s.taboption('files', form.DummyValue, "_update", _("Update Files"));
		o.renderWidget = function () {
			return E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'id': 'btn_update',
				'click': ui.createHandlerFn(this, function () {
					return fs.exec('/etc/init.d/smartdns', ['updatefiles'])
						.catch(function (e) { ui.addNotification(null, E('p', e.message), 'error') });
				})
			}, [_("Update")]);
		}

		o = s.taboption('files', form.SectionValue, '__files__', form.GridSection, 'download-file', _('Download Files'),
			_('List of files to download.'));

		ss = o.subsection;

		ss.addremove = true;
		ss.anonymous = true;
		ss.sortable = true;

		so = ss.option(form.Value, 'name', _('File Name'), _('File Name'));
		so.rmempty = true;
		so.datatype = 'file';

		so = ss.option(form.Value, 'url', _('URL'), _('URL'));
		so.rmempty = true;
		so.datatype = 'string';
		so.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			if (!value.match(/^(http|https|ftp|sftp):\/\//)) {
				return _("URL format error, format: http:// or https://");
			}

			return true;
		}

		so = ss.option(form.ListValue, "type", _("type"), _("File Type"));
		so.value("list", _("domain list (/etc/smartdns/domain-set)"));
		so.value("config", _("smartdns config (/etc/smartdns/conf.d)"));
		so.default = "list";
		so.rempty = false;

		so = ss.option(form.Value, 'desc', _('Description'), _('Description'));
		so.rmempty = true;
		so.datatype = 'string';

		///////////////////////////////////////
		// Proxy server settings;
		///////////////////////////////////////
		o = s.taboption("proxy", form.Value, "proxy_server", _("Proxy Server"), _("Proxy Server URL, format: [socks5|http]://user:pass@ip:port."));
		o.datatype = 'string';
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			if (!value.match(/^(socks5|http):\/\//)) {
				return _("Proxy server URL format error, format: [socks5|http]://user:pass@ip:port.");
			}

			return true;
		}

		///////////////////////////////////////
		// custom settings;
		///////////////////////////////////////
		o = s.taboption("custom", form.TextValue, "custom_conf",
			"", _("smartdns custom settings"));
		o.rows = 20;
		o.cfgvalue = function (section_id) {
			return fs.trimmed('/etc/smartdns/custom.conf');
		};
		o.write = function (section_id, formvalue) {
			return this.cfgvalue(section_id).then(function (value) {
				if (value == formvalue) {
					return
				}
				return fs.write('/etc/smartdns/custom.conf', formvalue.trim().replace(/\r\n/g, '\n') + '\n');
			});
		};

		o = s.taboption("custom", form.Flag, "coredump", _("Generate Coredump"),
			_("Generate Coredump file when smartdns crash, coredump file is located at /tmp/smartdns.xxx.core."));
		o.rmempty = true;
		o.default = o.disabled;

		o = s.taboption("custom", form.Value, "log_size", _("Log Size"));
		o.rmempty = true;
		o.placeholder = "default";

		o = s.taboption("custom", form.ListValue, "log_level", _("Log Level"));
		o.rmempty = true;
		o.placeholder = "default";
		o.value("", _("default"));
		o.value("debug");
		o.value("info");
		o.value("notice");
		o.value("warn");
		o.value("error");
		o.value("fatal");
		o.value("off");

		o = s.taboption("custom", form.Value, "log_num", _("Log Number"));
		o.rmempty = true;
		o.placeholder = "default";

		o = s.taboption("custom", form.Value, "log_file", _("Log File"))
		o.rmempty = true
		o.placeholder = "/var/log/smartdns/smartdns.log"

		////////////////
		// Upstream servers;
		////////////////
		s = m.section(form.GridSection, "server", _("Upstream Servers"),
			_("Upstream Servers, support UDP, TCP protocol. Please configure multiple DNS servers, "
				+ "including multiple foreign DNS servers."));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;

		s.tab('general', _('General Settings'));
		s.tab('advanced', _('Advanced Settings'));

		// enable flag;
		o = s.taboption("general", form.Flag, "enabled", _("Enable"), _("Enable"));
		o.rmempty = false;
		o.default = o.enabled;
		o.editable = true;

		// name;
		o = s.taboption("general", form.Value, "name", _("DNS Server Name"), _("DNS Server Name"));

		// IP address;
		o = s.taboption("general", form.Value, "ip", _("ip"), _("DNS Server ip"));
		o.datatype = "or(ipaddr, string)";
		o.rmempty = false;

		// port;
		o = s.taboption("general", form.Value, "port", _("port"), _("DNS Server port"));
		o.placeholder = "default";
		o.datatype = "port";
		o.rempty = true;
		o.depends("type", "udp");
		o.depends("type", "tcp");
		o.depends("type", "tls");

		// type;
		o = s.taboption("general", form.ListValue, "type", _("type"), _("DNS Server type"));
		o.placeholder = "udp";
		o.value("udp", _("udp"));
		o.value("tcp", _("tcp"));
		o.value("tls", _("tls"));
		o.value("https", _("https"));
		o.default = "udp";
		o.rempty = false;

		// server group
		o = s.taboption("general", form.Value, "server_group", _("Server Group"), _("DNS Server group"))
		o.rmempty = true;
		o.placeholder = "default";
		o.datatype = "hostname";
		o.rempty = true;
		servers = uci.sections('smartdns', 'server');
		var groupnames = new Set();
		for (var i = 0; i < servers.length; i++) {
			if (servers[i].server_group == undefined) {
				continue;
			}
			groupnames.add(servers[i].server_group);
		}

		for (const groupname of groupnames) {
			o.value(groupname);
		}

		// Advanced Options
		o = s.taboption("advanced", form.Flag, "exclude_default_group", _("Exclude Default Group"), _("Exclude DNS Server from default group."))
		o.rmempty = true;
		o.default = o.disabled;
		o.editable = true;
		o.modalonly = true;

		// blacklist_ip
		o = s.taboption("advanced", form.Flag, "blacklist_ip", _("IP Blacklist Filtering"),
			_("Filtering IP with blacklist"))
		o.rmempty = true
		o.default = o.disabled
		o.modalonly = true;

		// TLS host verify
		o = s.taboption("advanced", form.Value, "tls_host_verify", _("TLS Hostname Verify"),
			_("Set TLS hostname to verify."))
		o.default = ""
		o.datatype = "string"
		o.rempty = true
		o.modalonly = true;
		o.depends("type", "tls")
		o.depends("type", "https")

		// certificate verify
		o = s.taboption("advanced", form.Flag, "no_check_certificate", _("No check certificate"),
			_("Do not check certificate."))
		o.rmempty = true
		o.default = o.disabled
		o.modalonly = true;
		o.depends("type", "tls")
		o.depends("type", "https")

		// SNI host name
		o = s.taboption("advanced", form.Value, "host_name", _("TLS SNI name"),
			_("Sets the server name indication for query. '-' for disable SNI name."))
		o.default = ""
		o.datatype = "hostname"
		o.rempty = true
		o.modalonly = true;
		o.depends("type", "tls")
		o.depends("type", "https")

		// http host
		o = s.taboption("advanced", form.Value, "http_host", _("HTTP Host"),
			_("Set the HTTP host used for the query. Use this parameter when the host of the URL address is an IP address."))
		o.default = ""
		o.datatype = "hostname"
		o.rempty = true
		o.modalonly = true;
		o.depends("type", "https")

		// SPKI pin
		o = s.taboption("advanced", form.Value, "spki_pin", _("TLS SPKI Pinning"),
			_("Used to verify the validity of the TLS server, The value is Base64 encoded SPKI fingerprint, "
				+ "leaving blank to indicate that the validity of TLS is not verified."))
		o.default = ""
		o.datatype = "string"
		o.rempty = true
		o.modalonly = true;
		o.depends("type", "tls")
		o.depends("type", "https")

		// mark
		o = s.taboption("advanced", form.Value, "set_mark", _("Marking Packets"),
			_("Set mark on packets."))
		o.default = ""
		o.rempty = true
		o.datatype = "uinteger"
		o.modalonly = true;

		// use proxy
		o = s.taboption("advanced", form.Flag, "use_proxy", _("Use Proxy"),
			_("Use proxy to connect to upstream DNS server."))
		o.default = o.disabled
		o.modalonly = true;
		o.optional = true;
		o.rempty = true;
		o.validate = function (section_id, value) {
			var flag = this.formvalue(section_id);
			if (flag == "0") {
				return true;
			}

			var proxy_server = uci.sections("smartdns", "smartdns")[0].proxy_server;
			var server_type = this.section.formvalue(section_id, "type");
			if (proxy_server == "" || proxy_server == undefined) {
				return _("Please set proxy server first.");
			}

			if (server_type == "udp" && !proxy_server.match(/^(socks5):\/\//)) {
				return _("Only socks5 proxy support udp server.");
			}

			return true;
		}

		// other args
		o = s.taboption("advanced", form.Value, "addition_arg", _("Additional Server Args"),
			_("Additional Args for upstream dns servers"))
		o.default = ""
		o.rempty = true
		o.modalonly = true;

		////////////////
		// domain rules;
		////////////////
		s = m.section(form.TypedSection, "domain-rule", _("Domain Rules"), _("Domain Rules Settings"));
		s.anonymous = true;
		s.nodescriptions = true;

		s.tab("forwarding", _('DNS Forwarding Setting'));
		s.tab("block", _("DNS Block Setting"));
		s.tab("domain-rule-list", _("Domain Rule List"), _("Set Specific domain rule list."));
		s.tab("domain-address", _("Domain Address"), _("Set Specific domain ip address."));
		s.tab("blackip-list", _("IP Blacklist"), _("Set Specific ip blacklist."));

		///////////////////////////////////////
		// domain forwarding;
		///////////////////////////////////////
		o = s.taboption("forwarding", form.Value, "server_group", _("Server Group"), _("DNS Server group belongs to, such as office, home."))
		o.rmempty = true
		o.placeholder = "default"
		o.datatype = "hostname"
		o.rempty = true
		for (const groupname of groupnames) {
			o.value(groupname);
		}
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var val = uci.sections('smartdns', 'server');
			for (var i = 0; i < val.length; i++) {
				if (value == val[i].server_group) {
					return true;
				}
			}

			return _('Server Group %s not exists').format(value);

		}

		o = s.taboption("forwarding", form.Flag, "no_speed_check", _("Skip Speed Check"),
			_("Do not check speed."));
		o.rmempty = true;
		o.default = o.disabled;

		o = s.taboption("forwarding", form.Flag, "force_aaaa_soa", _("Force AAAA SOA"), _("Force AAAA SOA."));
		o.rmempty = true;
		o.default = o.disabled;

		o = s.taboption("forwarding", form.Value, "ipset_name", _("IPset Name"), _("IPset name."));
		o.rmempty = true;
		o.datatype = "string";
		o.rempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var ipset = value.split(",")
			for (var i = 0; i < ipset.length; i++) {
				if (!ipset[i].match(/^(#[4|6]:)?[a-zA-Z0-9\-_]+$/)) {
					return _("ipset name format error, format: [#[4|6]:]ipsetname");
				}
			}

			return true;
		}

		o = s.taboption("forwarding", form.Value, "nftset_name", _("NFTset Name"), _("NFTset name, format: [#[4|6]:[family#table#set]]"));
		o.rmempty = true;
		o.datatype = "string";
		o.rempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var nftset = value.split(",")
			for (var i = 0; i < nftset.length; i++) {
				if (!nftset[i].match(/^#[4|6]:[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+$/)) {
					return _("NFTset name format error, format: [#[4|6]:[family#table#set]]");
				}
			}

			return true;
		}

		// other args
		o = s.taboption("forwarding", form.Value, "addition_flag", _("Additional Rule Flag"),
			_("Additional Flags for rules, read help on domain-rule for more information."))
		o.default = ""
		o.rempty = true
		o.modalonly = true;

		o = s.taboption("forwarding", form.FileUpload, "forwarding_domain_set_file", _("Domain List File"),
			_("Upload domain list file, or configure auto download from Download File Setting page."));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.editable = true
		o.root_directory = "/etc/smartdns/domain-set"

		o = s.taboption("forwarding", form.TextValue, "domain_forwarding_list",
			_("Domain List"), _("Configure forwarding domain name list."));
		o.rows = 10;
		o.cols = 64;
		o.monospace = true;
		o.cfgvalue = function (section_id) {
			return fs.trimmed('/etc/smartdns/domain-forwarding.list').catch(function (e) {
				return "";
			});
		};
		o.write = function (section_id, formvalue) {
			return this.cfgvalue(section_id).then(function (value) {
				if (value == formvalue) {
					return
				}
				return fs.write('/etc/smartdns/domain-forwarding.list', formvalue.trim().replace(/\r\n/g, '\n') + '\n');
			});
		};

		///////////////////////////////////////
		// domain block;
		///////////////////////////////////////
		o = s.taboption("block", form.FileUpload, "block_domain_set_file", _("Domain List File"), _("Upload domain list file."));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.editable = true
		o.root_directory = "/etc/smartdns/domain-set"

		o = s.taboption("block", form.TextValue, "domain_block_list",
			_("Domain List"), _("Configure block domain list."));
		o.rows = 10;
		o.cols = 64;
		o.cfgvalue = function (section_id) {
			return fs.trimmed('/etc/smartdns/domain-block.list').catch(function (e) {
				return "";
			});
		};
		o.write = function (section_id, formvalue) {
			return this.cfgvalue(section_id).then(function (value) {
				if (value == formvalue) {
					return
				}
				return fs.write('/etc/smartdns/domain-block.list', formvalue.trim().replace(/\r\n/g, '\n') + '\n');
			});
		};

		///////////////////////////////////////
		// domain rule list;
		///////////////////////////////////////
		o = s.taboption('domain-rule-list', form.SectionValue, '__domain-rule-list__', form.GridSection, 'domain-rule-list', _('Domain Rule List'),
			_('Configure domain rule list.'));

		ss = o.subsection;

		ss.addremove = true;
		ss.anonymous = true;
		ss.sortable = true;

		// enable flag;
		so = ss.option(form.Flag, "enabled", _("Enable"), _("Enable"));
		so.rmempty = false;
		so.default = so.enabled;
		so.editable = true;

		// name;
		so = ss.option(form.Value, "name", _("Domain Rule Name"), _("Domain Rule Name"));

		so = ss.option(form.Value, "server_group", _("Server Group"), _("DNS Server group belongs to, such as office, home."))
		so.rmempty = true
		so.placeholder = "default"
		so.datatype = "hostname"
		so.rempty = true
		for (const groupname of groupnames) {
			so.value(groupname);
		}
		so.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var val = uci.sections('smartdns', 'server');
			for (var i = 0; i < val.length; i++) {
				if (value == val[i].server_group) {
					return true;
				}
			}

			return _('Server Group %s not exists').format(value);

		}

		so = ss.option(form.FileUpload, "domain_list_file", _("Domain List File"),
			_("Upload domain list file, or configure auto download from Download File Setting page."));
		so.rmempty = true
		so.datatype = "file"
		so.rempty = true
		so.root_directory = "/etc/smartdns/domain-set"

		so = ss.option(form.ListValue, "block_domain_type", _("Block domain"), _("Block domain."));
		so.rmempty = true;
		so.value("none", _("None"));
		so.value("all", "IPv4/IPv6");
		so.value("ipv4", "IPv4");
		so.value("ipv6", "IPv6");
		so.modalonly = true;

		// Support DualStack ip selection;
		so = ss.option(form.ListValue, "dualstack_ip_selection", _("Dual-stack IP Selection"),
			_("Enable IP selection between IPV4 and IPV6"));
		so.rmempty = true;
		so.default = "default";
		so.modalonly = true;
		so.value("", _("default"));
		so.value("yes", _("Yes"));
		so.value("no", _("No"));

		so = ss.option(form.Value, "speed_check_mode", _("Speed Check Mode"), _("Smartdns speed check mode."));
		so.rmempty = true;
		so.placeholder = "default";
		so.modalonly = true;
		so.value("", _("default"));
		so.value("ping,tcp:80,tcp:443");
		so.value("ping,tcp:443,tcp:80");
		so.value("tcp:80,tcp:443,ping");
		so.value("tcp:443,tcp:80,ping");
		so.value("none", _("None"));
		so.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			if (value == "none") {
				return true;
			}

			var check_mode = value.split(",")
			for (var i = 0; i < check_mode.length; i++) {
				if (check_mode[i] == "ping") {
					continue;
				}

				if (check_mode[i].indexOf("tcp:") == 0) {
					var port = check_mode[i].split(":")[1];
					if (port == "") {
						return _("TCP port is empty");
					}

					continue;
				}

				return _("Speed check mode is invalid.");
			}

			return true;
		}

		so = ss.option(form.Flag, "force_aaaa_soa", _("Force AAAA SOA"), _("Force AAAA SOA."));
		so.rmempty = true;
		so.default = so.disabled;
		so.modalonly = true;


		so = ss.option(form.Value, "ipset_name", _("IPset Name"), _("IPset name."));
		so.rmempty = true;
		so.datatype = "hostname";
		so.rempty = true;
		so.modalonly = true;

		so = ss.option(form.Value, "nftset_name", _("NFTset Name"), _("NFTset name, format: [#[4|6]:[family#table#set]]"));
		so.rmempty = true;
		so.datatype = "string";
		so.rempty = true;
		so.modalonly = true;
		so.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var nftset = value.split(",")
			for (var i = 0; i < nftset.length; i++) {
				if (!nftset[i].match(/#[4|6]:[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+#[a-zA-Z0-9\-_]+$/)) {
					return _("NFTset name format error, format: [#[4|6]:[family#table#set]]");
				}
			}

			return true;
		}

		// other args
		so = ss.option(form.Value, "addition_flag", _("Additional Rule Flag"),
			_("Additional Flags for rules, read help on domain-rule for more information."))
		so.default = ""
		so.rempty = true
		so.modalonly = true;

		///////////////////////////////////////
		// IP Blacklist;
		///////////////////////////////////////
		// blacklist;
		o = s.taboption("blackip-list", form.TextValue, "blackip_ip_conf",
			"", _("Configure IP blacklists that will be filtered from the results of specific DNS server."));
		o.rows = 20;
		o.cfgvalue = function (section_id) {
			return fs.trimmed('/etc/smartdns/blacklist-ip.conf');
		};
		o.write = function (section_id, formvalue) {
			return this.cfgvalue(section_id).then(function (value) {
				if (value == formvalue) {
					return
				}
				return fs.write('/etc/smartdns/blacklist-ip.conf', formvalue.trim().replace(/\r\n/g, '\n') + '\n');
			});
		};

		///////////////////////////////////////
		// domain address
		///////////////////////////////////////
		o = s.taboption("domain-address", form.TextValue, "address_conf",
			"",
			_("Specify an IP address to return for any host in the given domains, Queries in the domains are never "
				+ "forwarded and always replied to with the specified IP address which may be IPv4 or IPv6."));
		o.rows = 20;
		o.cfgvalue = function (section_id) {
			return fs.trimmed('/etc/smartdns/address.conf');
		};
		o.write = function (section_id, formvalue) {
			return this.cfgvalue(section_id).then(function (value) {
				if (value == formvalue) {
					return
				}
				return fs.write('/etc/smartdns/address.conf', formvalue.trim().replace(/\r\n/g, '\n') + '\n');
			});
		};

		////////////////
		// Support
		////////////////
		s = m.section(form.TypedSection, "smartdns", _("Technical Support"),
			_("If you like this software, please buy me a cup of coffee."));
		s.anonymous = true;

		o = s.option(form.Button, "web");
		o.title = _("SmartDNS official website");
		o.inputtitle = _("open website");
		o.inputstyle = "apply";
		o.onclick = function () {
			window.open("https://pymumu.github.io/smartdns", '_blank');
		};

		o = s.option(form.Button, "report");
		o.title = _("Report bugs");
		o.inputtitle = _("Report bugs");
		o.inputstyle = "apply";
		o.onclick = function () {
			window.open("https://github.com/pymumu/smartdns/issues", '_blank');
		};

		o = s.option(form.Button, "Donate");
		o.title = _("Donate to smartdns");
		o.inputtitle = _("Donate");
		o.inputstyle = "apply";
		o.onclick = function () {
			window.open("https://pymumu.github.io/smartdns/#donate", '_blank');
		};

		o = s.option(form.DummyValue, "_restart", _("Restart Service"));
		o.renderWidget = function () {
			return E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'id': 'btn_restart',
				'click': ui.createHandlerFn(this, function () {
					return fs.exec('/etc/init.d/smartdns', ['restart'])
						.catch(function (e) { ui.addNotification(null, E('p', e.message), 'error') });
				})
			}, [_("Restart")]);
		}
		return m.render();
	}
});
