Name:           smartdns
Version:        31
Release:        1%{?dist}
Summary:        smartdns

License:        GPL 3.0
URL:            https://github.com/pymumu/smartdns
Source0:        smartdns-Release31.tar.gz

BuildRequires:  glibc
Requires:       glibc
Requires:       systemd

%description
A local DNS server to obtain the fastest website IP for the best Internet experience.

%prep
%setup -q -n smartdns-Release31

%build
cd src
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

%{__install} -D -m 755 src/smartdns $RPM_BUILD_ROOT%{_sbindir}/smartdns
%{__install} -D -m 644 etc/smartdns/smartdns.conf $RPM_BUILD_ROOT%{_sysconfdir}/smartdns/smartdns.conf
%{__install} -D -m 644 systemd/smartdns.service.in $RPM_BUILD_ROOT%{_unitdir}/smartdns.service


cat > $RPM_BUILD_ROOT%{_unitdir}/smartdns.service <<EOF
[Unit]
Description=smartdns
ConditionFileIsExecutable=/usr/sbin/smartdns
After=syslog.target network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/smartdns -c /etc/smartdns/smartdns.conf -f
PIDFile=/run/smartdns.pid
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF


%files
%defattr(-,root,root,-)
%{_sbindir}/smartdns
%config(noreplace) %{_sysconfdir}/smartdns/smartdns.conf
%{_unitdir}/smartdns.service

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service
