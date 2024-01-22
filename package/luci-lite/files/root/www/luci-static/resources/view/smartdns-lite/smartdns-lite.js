/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
			} catch (e) {

			}
			return is_running;
		})
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
	var smartdnsEnable = uci.get_first('smartdns', 'smartdns', 'enabled');
	var dnsmasqServer = uci.get_first('dhcp', 'dnsmasq', 'server');

	if (isRunning) {
		renderHTML += "<span style=\"color:green;font-weight:bold\">SmartDNS - " + _("RUNNING") + "</span>";
	} else {
		renderHTML += "<span style=\"color:red;font-weight:bold\">SmartDNS - " + _("NOT RUNNING") + "</span>";
		if (smartdnsEnable === '1') {
			renderHTML += "<br /><span style=\"color:red;font-weight:bold\">" + _("Please check the system logs and check if the configuration is valid.");
			renderHTML += "</span>";
		}
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
			uci.load('smartdns-lite'),
		]);
	},
	render: function (stats) {
		var m, s, o;

		m = new form.Map('smartdns-lite', _('SmartDNS Lite'));
		m.title = _("SmartDNS Lite");
		m.description = _("A local SmartDNS server for lite users.");

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
		s = m.section(form.TypedSection, "smartdns-lite", _("Settings"));
		s.anonymous = true;

		s.tab("settings", _("Basic Settings"));
		s.tab("parental", _("Parental Control Settings"));
		s.tab("rules", _("Domain Rules Settings"));
		s.tab("cloudflare", _("CloudFlare CDN IP Settings"), _("Set the IP addresses for accelerating CloudFlare CDN."));
		s.tab("custom", _("Custom Settings"));

		o = s.taboption("settings", form.Flag, "enabled", _("Enable"), _("Enable or disable smartdns server"));
		o.rmempty = false;
		o.default = o.disabled;

		o = s.taboption("settings", form.DynamicList, "servers", _("Upstream Server"),
			_("Upstream servers, format: [udp://|tcp://|tls://|https://][ip]."));
		o.rempty = true
		o.rmempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var values = value.split(/\s+/);
			for (var i = 0; i < values.length; i++) {
				if (!values[i].match(/^(https?|udp|tcp|tls|quic):\/\/[0-9a-zA-Z\.\[\]:]+(\/[^\s]*)?$/)) {
					return _('Invalid server address: %s').format(values[i]);
				}
			}
			return true;
		};

		o = s.taboption("settings", form.FileUpload, "ad_block_file", _("AD Block Domain List File"),
			_("Set the file for blocking ad domain names."));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.editable = true
		o.root_directory = "/etc/smartdns/domain-set"

		o = s.taboption("settings", form.ListValue, "server_mode", _("DNS Server Mode"), _("Smartdns server mode."));
		o.rmempty = false;
		o.value("main", _("Main DNS Server"));
		o.value("upstream", _("Upstream DNS Server"));

		o = s.taboption("settings", form.Value, "port", _("DNS Server Port"), _("Smartdns server port."));
		o.rmempty = true
		o.default = 6053;
		o.datatype = "port";
		o.depends("server_mode", "upstream");

		o = s.taboption("parental", form.Flag, "pc_enabled", _("Enable"), _("Enable or disable smartdns server"));
		o.rmempty = false;
		o.default = o.disabled;
		o.validate = function (section_id, value) {
			var v = this.map.lookupOption('pc_enabled', section_id)[0];
			if (v.formvalue(section_id) == 0) {
				return true;
			}

			var server_mode = this.map.lookupOption('server_mode', section_id)[0];
			if (server_mode.formvalue(section_id) != "main") {
				return _("Parental control feature is only available in Main DNS mode.");
			}

			return true;
		}

		o = s.taboption("parental", form.DynamicList, "pc_client_addr", _("Client Address"),
			_("If a client address is specified, only that client will apply this rule. You can enter an IP address, such as 1.2.3.4, or a MAC address, such as aa:bb:cc:dd:ee:ff."));
		o.rempty = true
		o.rmempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			if (value.match(/^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$/)) {
				return true;
			}

			if (value.match(/^([a-fA-F0-9]*:){1,7}[a-fA-F0-9]*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/)) {
				return true;
			}

			if (value.match(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)) {
				return true;
			}

			return _("Client address format error, please input ip adress or mac address.");
		}

		o = s.taboption("parental", form.DynamicList, "pc_servers", _("Parental Control Upstream Server"),
			_("Upstream server with parental control feature. If not specified, the default server will be used."));
		o.rempty = true
		o.rmempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var values = value.split(/\s+/);
			for (var i = 0; i < values.length; i++) {
				if (!values[i].match(/^(https?|udp|tcp|tls|quic):\/\/[0-9a-zA-Z\.\[\]:]+(\/[^\s]*)?$/)) {
					return _('Invalid server address: %s').format(values[i]);
				}
			}
			return true;
		};

		o = s.taboption("parental", form.FileUpload, "pc_block_file", _("Parental Control Domain File"),
			_("Block Domain List File for Parental Control."));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.editable = true
		o.root_directory = "/etc/smartdns/domain-set"

		o = s.taboption("rules", form.Flag, "rules_enabled", _("Enable"), _("Enable or disable domain rules."));
		o.rmempty = false;
		o.default = o.disabled;

		o = s.taboption("rules", form.FileUpload, "rules_domain_file", _("Domain List File"),
			_("Upload domain list file for matching these rules, if not specified, the rules will be applied to all domains."));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.editable = true
		o.root_directory = "/etc/smartdns/domain-set"

		o = s.taboption("rules", form.DynamicList, "rules_servers", _("Upstream Server"), 
			_("Upstream server for specific domain. If not specified, the default server will be used."));
		o.rempty = true
		o.rmempty = true;
		o.validate = function (section_id, value) {
			if (value == "") {
				return true;
			}

			var values = value.split(/\s+/);
			for (var i = 0; i < values.length; i++) {
				if (!values[i].match(/^(https?|udp|tcp|tls|quic):\/\/[0-9a-zA-Z\.\[\]:]+(\/[^\s]*)?$/)) {
					return _('Invalid server address: %s').format(values[i]);
				}
			}
			return true;
		};

		o = s.taboption("rules", form.Value, "rules_speed_check_mode", _("Speed Check Mode"), _("Speed check mode for matching domains."));
		o.rmempty = true;
		o.placeholder = _("None");
		o.default = "none";
		o.value("none", _("None"));
		o.value("ping,tcp:80,tcp:443");
		o.value("ping,tcp:443,tcp:80");
		o.value("tcp:80,tcp:443,ping");
		o.value("tcp:443,tcp:80,ping");
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

		// Force AAAA SOA
		o = s.taboption("rules", form.Flag, "rules_force_aaaa_soa", _("Force AAAA SOA"), _("Force AAAA SOA."));
		o.rmempty = true;
		o.default = o.disabled;

		// Force HTTPS SOA
		o = s.taboption("rules", form.Flag, "rules_force_https_soa", _("Force HTTPS SOA"), _("Force HTTPS SOA."));
		o.rmempty = true;
		o.default = o.enabled;

		o = s.taboption("rules", form.Flag, "use_internal_rules", _("Use Internal IP Rules"), 
		_("Use internal IP rules to forward data to TPROXY service when the domain matches, avoiding the need to configure IP rules."));
		o.rmempty = true;
		o.default = o.disabled;

		o = s.taboption("rules", form.Value, "rules_ipset_name", _("IPset Name"), _("IPset name."));
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
		o.depends("use_internal_rules", "0");

		o = s.taboption("rules", form.Value, "rules_nftset_name", _("NFTset Name"), _("NFTset name, format: [#[4|6]:[family#table#set]]"));
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
		o.depends("use_internal_rules", "0");

		o = s.taboption("rules", form.Value, "tproxy_server_port", _("TPROXY Server Port"), 
			_("TPROXY server port used for forwarding data requests, please make sure this port has enabled TPROXY service."));
		o.rmempty = false;
		o.datatype = "port";
		o.rempty = false;
		o.depends("use_internal_rules", "1");

		o = s.taboption("cloudflare", form.Flag, "cloudflare_enabled", _("Enable"), 
			_("Enable or disable cloudflare cdn ip accelerating."));
		o.rmempty = false;
		o.default = o.disabled;

		o = s.taboption("cloudflare", form.FileUpload, "cloudflare_cdn_ip_file", _("CloudFlare CDN IP File"),
			_("Upload CloudFlare cdn ip list file, please refer to https://www.cloudflare.com/ips"));
		o.rmempty = true
		o.datatype = "file"
		o.rempty = true
		o.modalonly = true;
		o.root_directory = "/etc/smartdns/ip-set"

		o = s.taboption("cloudflare", form.DynamicList, "cloudflare_ip_alias", _("IP alias"),
		 	_("IP Address Mapping, mapping all CloudFlare CDN IPs to the specified IP, can be used to accelerate CloudFlare's CDN websites."));
		o.rmempty = true;
		o.datatype = 'ipaddr("nomask")';
		o.modalonly = true;

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

		o = s.taboption("custom", form.Button, "web");
		o.title = _("SmartDNS official website");
		o.inputtitle = _("open website");
		o.inputstyle = "apply";
		o.onclick = function () {
			window.open("https://pymumu.github.io/smartdns", '_blank');
		};

		o = s.taboption("custom", form.DummyValue, "_restart", _("Restart Service"));
		o.renderWidget = function () {
			return E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'id': 'btn_restart',
				'click': ui.createHandlerFn(this, function () {
					return fs.exec('/etc/init.d/smartdns-lite', ['restart'])
						.catch(function (e) { ui.addNotification(null, E('p', e.message), 'error') });
				})
			}, [_("Restart")]);
		}
		return m.render();
	}
});
