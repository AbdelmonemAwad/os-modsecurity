#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-modsecurity have been removed. Apache was stopped in pre-deinstall,
# while the rc script that stops it was there. Kept: the settings in config.xml, and apache24 and
# ap24-mod_security, which pkg keeps as it keeps what any package depends on (pkg autoremove takes them
# and what they brought, where nothing else needs them).
#
# Should pkg run it in an upgrade, where nothing is to go, PKG_UPGRADE is set: what the plugin wrote and
# the menu stay, and the new package's post-install writes the menu again.
if [ -n "${PKG_UPGRADE}" ]; then
	exit 0
fi

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-modsecurity > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# The menu file place-menu.sh wrote is not one of the package's files, so pkg left it, and the model's
# directory with it. The menu is cached by PHP in /var/lib/php/tmp on 26.7, in /tmp before; the page as
# PHP compiled it, in /var/lib/php/cache.
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity/Menu /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity 2>/dev/null || true
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml
find /var/lib/php/cache -maxdepth 1 -iname '*_views_opnsense_modsecurity_*' -delete 2> /dev/null || true

# Nor what the plugin wrote: Apache's configuration, the certificates exported for it and the Core Rule
# Set installed; its logs; ModSecurity's work files; what it last did and what the self-update keeps; the
# runtime files and the pid file; what Python compiles beside a script it imports, which would keep the
# scripts' directory. The plugin's own directories go once empty: pkg removes the files it laid down, and
# not every directory.
rm -rf /usr/local/opnsense/scripts/modsecurity/__pycache__ /usr/local/etc/os-modsecurity /var/log/modsecurity \
    /var/tmp/os-modsecurity /var/db/os-modsecurity /usr/local/share/os-modsecurity /var/run/modsecurity
rm -f /var/run/modsecurity.pid
for d in /usr/local/opnsense/scripts/modsecurity /usr/local/opnsense/mvc/app/library/OPNsense/ModSecurity \
    /usr/local/opnsense/mvc/app/controllers/OPNsense/ModSecurity /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity \
    /usr/local/opnsense/mvc/app/views/OPNsense/ModSecurity /usr/local/opnsense/service/templates/OPNsense/ModSecurity; do
	[ -d "${d}" ] && find "${d}" -depth -type d -empty -delete 2> /dev/null
done

echo "Web Application Firewall removed; its settings stay in config.xml, and apache24 and ap24-mod_security stay installed"
