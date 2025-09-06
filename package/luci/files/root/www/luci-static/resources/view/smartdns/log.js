/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
'require dom';
'require fs';
'require poll';
'require uci';
'require view';
'require form';
'require ui';

return view.extend({
	render: function () {
		var css = `
			#log_textarea {
				margin-top: 10px;
			}
			#log_textarea pre {
				background-color: #f7f7f7;
				color: #333;
				padding: 10px;
				border: 1px solid #ccc;
				border-radius: 4px;
				font-family: Consolas, Menlo, Monaco, monospace;
				font-size: 14px;
				line-height: 1.5;
				white-space: pre-wrap;
				word-wrap: break-word;
				overflow-y: auto;
				max-height: 650px;
			}
			#.description {
				background-color: #33ccff;
			}
			.cbi-button-danger {
				background-color: #fff;
				color: #f00;
				border: 1px solid #f00;
				border-radius: 4px;
				padding: 4px 8px;
				font-size: 14px;
				cursor: pointer;
				margin-top: 10px;
			}
			.cbi-button-danger:hover {
				background-color: #f00;
				color: #fff;
			}
			.cbi-section small {
				margin-left: 10px;
			}
			.cbi-section .cbi-section-actions {
				margin-top: 10px;
			}
			.cbi-section .cbi-section-actions-right {
				text-align: right;
			}
		`;


		var log_textarea = E('div', { 'id': 'log_textarea' },
			E('img', {
				'src': L.resource(['icons/loading.gif']),
				'alt': _('Loading...'),
				'style': 'vertical-align:middle'
			}, _('Collecting data ...'))
		);

		var clear_log_button = E('th', {}, [
			E('button', {
				'class': 'cbi-button cbi-button-remove',
				'click': function (ev) {
					ev.preventDefault();
					var button = ev.target;
					button.disabled = true;
					button.textContent = _('Clear Logs...');
					fs.exec('/usr/libexec/smartdns-call', ['clear_log'])
						.then(function () {
							button.textContent = _('Logs cleared successfully!');
							setTimeout(function () {
								button.disabled = false;
								button.textContent = _('Clear Logs');
							}, 5000);
							// Immediately refresh log display box
							var log = E('pre', { 'wrap': 'pre' }, [_('Log is clean.')]);
							dom.content(log_textarea, log);
						})
						.catch(function () {
							button.textContent = _('Failed to clear log.');
							setTimeout(function () {
								button.disabled = false;
								button.textContent = _('Clear Logs');
							}, 5000);
						});
				}
			}, _('Clear Logs'))
		]);


		poll.add(L.bind(function () {
			return fs.exec('/usr/libexec/smartdns-call', ['tail'])
				.then(function (res) {
					var log = E('pre', { 'wrap': 'pre' }, [res.stdout.trim() || _('Log is clean.')]);

					dom.content(log_textarea, log);
					log.scrollTop = log.scrollHeight;
				}).catch(function (err) {
					var log;

					if (err.toString().includes('NotFoundError')) {
						log = E('pre', { 'wrap': 'pre' }, [_('Log file does not exist.')]);
					} else {
						log = E('pre', { 'wrap': 'pre' }, [_('Unknown error: %s').format(err)]);
					}

					dom.content(log_textarea, log);
				});
		}));

		var back_smartdns_button = E('th', {}, [
			E('button', {
				'class': 'cbi-button cbi-button-apply',
				'click': ui.createHandlerFn(this, function () {
					window.location.href = "/cgi-bin/luci/admin/services/smartdns"
				})
			}, _('Back SmartDNS'))
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('style', [css]),
			E('div', { 'class': 'cbi-section' }, [
				clear_log_button,
				back_smartdns_button,
				log_textarea,
				E('small', {}, _('Refresh every %s seconds.').format(L.env.pollinterval)),
				E('div', { 'class': 'cbi-section-actions cbi-section-actions-right' })
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
