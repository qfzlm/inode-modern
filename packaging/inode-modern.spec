%global debug_package %{nil}

Name:           inode-modern
Version:        0.2.0~beta.1
Release:        1%{?dist}
Summary:        Native campus wired-network authentication client
License:        MIT
URL:            https://github.com/qfzlm/inode-modern
Source0:        inode-modern-%{version}.tar.gz
ExclusiveArch:  x86_64
BuildRequires:  python3
BuildRequires:  python3-rpm-macros
BuildRequires:  python3-pyside6
BuildRequires:  python3-dbus
BuildRequires:  systemd-rpm-macros
BuildRequires:  desktop-file-utils
Requires:       python3
Requires:       python3-pyside6
Requires:       python3-dbus
Requires:       systemd >= 255
Requires:       nftables
Requires:       util-linux
Requires:       iproute
Requires:       NetworkManager
Requires:       hicolor-icon-theme
Requires:       ncurses-compat-libs
Requires:       libnsl
Requires:       libxcrypt-compat
Requires(pre):  systemd
Requires(post): systemd
Requires(preun): systemd

%description
Native Qt frontend, CLI and isolated supervisor/broker for the H3C wired
campus authentication engine. Targeted at SWUFE Fedora 44 x86_64 users.
No proprietary H3C files are included. Run inode-modern-setup after installation
to acquire and verify the supported vendor files from the university website.

%prep
%autosetup -n inode-modern-%{version}

%build
# Python application and SVG resources; no vendored or generated binaries.

%install
mkdir -p %{buildroot}%{python3_sitelib}
cp -a inode_modern %{buildroot}%{python3_sitelib}/
find %{buildroot} -type d -name __pycache__ -prune -exec rm -r {} +
install -d %{buildroot}%{_libexecdir}/inode-modern %{buildroot}%{_bindir}
for file in backend broker invariants identities firewall vendor_setup package_lifecycle; do
    install -m 0644 integration/$file.py %{buildroot}%{_libexecdir}/inode-modern/
done
install -m 0644 tools/vendor_generation.py %{buildroot}%{_libexecdir}/inode-modern/
install -m 0755 tools/firewall_guard.sh %{buildroot}%{_libexecdir}/inode-modern/
printf '#!/usr/bin/python3 -I\nfrom inode_modern.cli import main\nraise SystemExit(main())\n' > %{buildroot}%{_bindir}/inode-modern
printf '#!/usr/bin/python3 -I\nfrom inode_modern.desktop.app import main\nraise SystemExit(main())\n' > %{buildroot}%{_bindir}/inode-modern-gui
printf '#!/bin/sh\nexec /usr/bin/python3 -I -B /usr/libexec/inode-modern/vendor_setup.py "$@"\n' > %{buildroot}%{_bindir}/inode-modern-setup
chmod 0755 %{buildroot}%{_bindir}/inode-modern*
install -Dpm0644 packaging/org.inode_modern.Client.desktop %{buildroot}%{_datadir}/applications/org.inode_modern.Client.desktop
for size in 16 22 24 32 48 64 256; do
    master=inode-modern.svg
    if [ "$size" -le 24 ]; then master=inode-modern-small.svg; fi
    for suffix in '' @2; do
        install -Dpm0644 inode_modern/desktop/$master %{buildroot}%{_datadir}/icons/hicolor/${size}x${size}${suffix}/apps/org.inode_modern.Client.svg
    done
done
install -Dpm0644 inode_modern/desktop/inode-modern.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.inode_modern.Client.svg
install -Dpm0644 packaging/inode-modern-backend.service %{buildroot}%{_unitdir}/inode-modern-backend.service
install -Dpm0644 packaging/inode-modern-firewall.service %{buildroot}%{_unitdir}/inode-modern-firewall.service
install -Dpm0644 packaging/inode-modern.sysusers %{buildroot}%{_sysusersdir}/inode-modern.conf
install -Dpm0644 packaging/inode-modern.tmpfiles %{buildroot}%{_tmpfilesdir}/inode-modern.conf

%check
PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -v
desktop-file-validate packaging/org.inode_modern.Client.desktop

%pre
# A local development unit would shadow the RPM's unit. Refuse ambiguous migration.
for unit in inode-modern-backend.service inode-modern-firewall.service; do
    if [ -e /etc/systemd/system/$unit ]; then
        echo "Local unit /etc/systemd/system/$unit must be migrated explicitly before installing this RPM." >&2
        exit 1
    fi
done

%post
systemd-sysusers %{_sysusersdir}/inode-modern.conf || exit 1
systemd-tmpfiles --create %{_tmpfilesdir}/inode-modern.conf >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
# Services remain disabled until explicit, verified setup. No vendor downloads here.

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    /usr/bin/python3 -I -B %{_libexecdir}/inode-modern/package_lifecycle.py --remove || exit 1
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
# Do not restart an authenticated session on upgrades.

%files
%license LICENSE THIRD_PARTY.md
%doc README.md PRODUCT.md DESIGN.md docs/security.md docs/installation.md docs/building.md
%{_bindir}/inode-modern
%{_bindir}/inode-modern-gui
%{_bindir}/inode-modern-setup
%{python3_sitelib}/inode_modern/
%{_libexecdir}/inode-modern/
%{_unitdir}/inode-modern-backend.service
%{_unitdir}/inode-modern-firewall.service
%{_sysusersdir}/inode-modern.conf
%{_tmpfilesdir}/inode-modern.conf
%{_datadir}/applications/org.inode_modern.Client.desktop
%{_datadir}/icons/hicolor/*/apps/org.inode_modern.Client.svg

%changelog
* Sun Sep 27 2026 inode-modern contributors - 0.2.0~beta.1-1
- First public beta for Fedora 44 x86_64; no proprietary vendor payload.
