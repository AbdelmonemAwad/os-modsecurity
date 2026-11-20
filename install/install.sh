#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Install the Web Application Firewall plugin from a copy of this repository on the firewall:
#   sh install/install.sh
# Safe to run again after an update: settings in config.xml are kept, and so is the Core Rule Set
# installed. Off by default: once this has run, no site is published until it is turned on in Settings.
# It needs OPNsense's own Apache and ModSecurity packages, apache24 and ap24-mod_security: a package
# install brings them with it (the Makefile's PLUGIN_DEPENDS), and this installs them from OPNsense's
# repository when they are not there - as XGS: Updates' Plugins tab installs a release, with no shell
# to run pkg in.

set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)

# Syntax first, on the tree about to be copied, so nothing with an error is ever copied - as
# os-blocklists found (2026-10-29). The Python is compiled into a directory of its own, removed after,
# not beside the tree's files.
for f in $(find "${HERE}/src" -name '*.php' -o -name '*.inc'); do
    php -l "$f" > /dev/null
done
PYC=$(mktemp -d -t os-modsecurity-check)
trap 'rm -rf "${PYC}"' EXIT
for f in $(find "${HERE}/src" -name '*.py'); do
    PYTHONPYCACHEPREFIX="${PYC}" python3 -m py_compile "$f"
done
rm -rf "${PYC}"
trap - EXIT

# Apache and ModSecurity next: without them nothing here can run, and the first Apply would fail with
# a missing file and no explanation. Installed here from OPNsense's own repository when they are not
# there, as os-appcontrol installs ndpi, and marked so: the removal takes away again only what this
# installed, and only when no other package needs it. After the syntax check, so a tree that would not
# go on installs no package, and before anything is copied, so a firewall that cannot reach the
# repository is told why and has nothing of the plugin. 1.0.0 stopped here and asked for pkg to
# be run by hand, which XGS: Updates' Plugins tab cannot do (2026-11-20, the second XGS 3300).
# ModSecurity's module is where the package lays it down: libexec/apache24, or lib, where the second
# XGS 3300 had it (phase 0's lab, 2026-11-20).
modsecurity_present() {
    [ -x /usr/local/sbin/httpd ] && { [ -f /usr/local/libexec/apache24/mod_security2.so ] || \
        [ -f /usr/local/lib/mod_security2.so ]; }
}
if ! modsecurity_present; then
    WANT=
    for p in apache24 ap24-mod_security; do
        pkg info -e "$p" > /dev/null 2>&1 || WANT="${WANT} $p"
    done
    if [ -n "${WANT}" ]; then
        echo "Installing OPNsense's packages:${WANT}"
        if ! pkg install -y ${WANT}; then
            echo "The packages${WANT} could not be installed from OPNsense's repository; the plugin was not installed."
            echo "Once the firewall reaches it (System: Firmware), install the plugin again."
            exit 1
        fi
        # added to what an install before this one recorded, never in its place
        install -d -m 0755 /usr/local/share/os-modsecurity
        MARK=/usr/local/share/os-modsecurity/packages-installed
        OLD=$(cat "${MARK}" 2> /dev/null || true)
        NEW="${OLD}${WANT}"
        echo "${NEW# }" > "${MARK}"
        if ! modsecurity_present; then
            echo "Apache or ModSecurity is not there after the packages: /usr/local/sbin/httpd or mod_security2.so is missing."
            exit 1
        fi
    else
        echo "OPNsense's packages apache24 and ap24-mod_security are installed, but /usr/local/sbin/httpd or mod_security2.so is missing."
        echo "Reinstall them in System: Firmware: Packages, then install the plugin again."
        exit 1
    fi
fi

# plugin files: src/ maps to /usr/local
# The public keys a release must be signed with for self-update.py and crs.py to install it (their
# SIGNED RELEASES) are the set this tree holds and no other: the installed ones go first, so a key the
# tree dropped goes with this install.
rm -rf /usr/local/opnsense/scripts/modsecurity/release-keys
cp -R "${HERE}/src/" /usr/local/
chmod 644 /usr/local/opnsense/scripts/modsecurity/release-keys/*.pub
chmod 755 /usr/local/opnsense/scripts/modsecurity/*.py /usr/local/opnsense/scripts/modsecurity/place-menu.sh \
    /usr/local/etc/rc.d/modsecurity
chmod 644 /usr/local/opnsense/scripts/modsecurity/listen.php /usr/local/opnsense/scripts/modsecurity/i18n/ui/source.json \
    /usr/local/opnsense/scripts/modsecurity/menu/*.xml /usr/local/opnsense/service/templates/OPNsense/ModSecurity/*
chmod 644 /usr/local/etc/inc/plugins.inc.d/modsecurity.inc /usr/local/opnsense/service/conf/actions.d/actions_modsecurity.conf \
    /usr/local/etc/cron.d/modsecurity

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Services where it is not.
# place-menu.sh writes the menu file and says which it chose: "xgs" or "own".
WHERE=$(/usr/local/opnsense/scripts/modsecurity/place-menu.sh)

# What Apache reads, the plugin's own: its configuration (each Apply writes it), the Core Rule Set, the
# sites' certificates (root's alone). What the plugin last did, root's alone. Apache's logs, root's alone.
install -d -o root -g wheel -m 0755 /usr/local/etc/os-modsecurity /usr/local/etc/os-modsecurity/crs
install -d -o root -g wheel -m 0700 /usr/local/etc/os-modsecurity/certs
install -d -o root -g wheel -m 0750 /var/db/os-modsecurity /var/log/modsecurity
install -d -m 0755 /usr/local/share/os-modsecurity

# reload configd actions, menu and ACL caches
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were.
# And the page as PHP compiled it, so an update is shown at once.
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
find /var/lib/php/cache -maxdepth 1 -iname '*_views_opnsense_modsecurity_*' -delete 2> /dev/null || true

# On, an Apply - the configuration written again by the code just copied, and Apache reloaded or started
# with it; off, Apache stopped.
if python3 /usr/local/opnsense/scripts/modsecurity/setup.py enabled 2> /dev/null | grep -q '"enabled": true'; then
    configctl modsecurity apply > /dev/null 2>&1 || true
    STATE="on: Apply ran"
else
    configctl modsecurity stop > /dev/null 2>&1 || true
    STATE="off until it is turned on in Settings"
fi

# What this install is, for the self-update: the commit, from a git checkout, or from the
# .source-commit stamp that an xgs-image-builder image or the self-update leaves in the tree.
# Without either it is recorded as unknown, and the self-update takes the latest release once.
REV=; RDATE=; RSRC=unknown
if [ -e "${HERE}/.git" ] && REV=$(git -C "${HERE}" rev-parse HEAD 2>/dev/null); then
    RDATE=$(git -C "${HERE}" log -1 --format=%cI 2>/dev/null); RSRC=git
elif [ -s "${HERE}/.source-commit" ]; then
    read -r REV RDATE _ < "${HERE}/.source-commit"; RSRC=stamp
else
    REV=
fi
case ${REV} in *[!0-9a-f]*) REV=; RDATE=; RSRC=unknown ;; esac
printf '{"commit": "%s", "date": "%s", "source": "%s", "installed_at": %s}\n' \
    "${REV}" "${RDATE}" "${RSRC}" "$(date +%s)" > /usr/local/share/os-modsecurity/installed.json

if [ "${WHERE}" = xgs ]; then
    echo "Web Application Firewall installed: XGS > Web Application Firewall (${STATE})"
else
    echo "Web Application Firewall installed: Services > Web Application Firewall (${STATE})"
fi
