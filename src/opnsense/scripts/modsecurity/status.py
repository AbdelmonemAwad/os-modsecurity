#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The page's question, through configd as root: what the Web Application Firewall is doing. Its pid
file, Apply's last answer and the Core Rule Set's record are root's, so the web GUI reads none of them
itself.

    status.py      one JSON object, and exit 0 whatever it found

state: off (not turned on), packages (apache24 or ap24-mod_security missing), norules (no Core Rule
Set), nosite (on, and no site to publish), failed (the last Apply was refused, and Apache is not
running), stopped (on, Apache not running), running. With it: the sites by mode, where Apache listens,
the web GUI's ports where they meet the plugin's (settled point 8a), the Core Rule Set installed, the
last Apply, and whether this is an XGS appliance (os-xgs-npu installed: the page says where the sites'
traffic is carried, settled point 9a).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import setup  # noqa: E402


def counts(conf, entries, root):
    usable, skipped = common.check_sites(conf, entries, root)
    return {
        'sites': len(entries),
        'enabled': sum(1 for s in entries if s['enabled']),
        'blocking': sum(1 for s in usable if s['mode'] == 'blocking'),
        'detection': sum(1 for s in usable if s['mode'] == 'detection'),
        'tls': sum(1 for s in usable if s['tls']),
        'usable': len(usable),
    }, skipped


def status(config=None):
    try:
        root = common.read_root(config)
    except (OSError, ValueError) as error:
        return {'state': 'unreadable', 'error': {'message': 'config.xml could not be read: %s' % error}}
    conf = common.general(root)
    entries = common.sites(root)
    found, skipped = counts(conf, entries, root)
    last = common.read_json(setup.paths()['apply'])
    crs = setup.crs_installed() or {}
    pid = setup.running_pid()
    packages = os.path.isfile(common.HTTPD) and setup.security2() is not None
    gui = common.webgui(root)
    conflicts = common.gui_conflicts(gui, [conf['http_port'], conf['https_port']], conf['interfaces'])
    if not conf['enabled']:
        state = 'off'
    elif not packages:
        state = 'packages'
    elif not crs:
        state = 'norules'
    elif pid:
        state = 'running'
    elif last.get('state') == 'nosite' or not found['usable']:
        state = 'nosite'
    elif last.get('status') == 'failed':
        state = 'failed'
    else:
        state = 'stopped'
    descr = common.assigned(root)
    return {
        'state': state,
        'enabled': conf['enabled'],
        'pid': pid,
        'counts': found,
        'skipped': skipped if conf['enabled'] else [],
        'ports': {'http': conf['http_port'], 'https': conf['https_port']},
        'interfaces': [{'key': k, 'descr': descr.get(k, {}).get('descr', k.upper())} for k in conf['interfaces']],
        'listen': last.get('listen', []) if pid else [],
        'gui': {'ports': gui['ports'], 'interfaces': [{'key': k, 'descr': descr.get(k, {}).get('descr', k.upper())}
                                                      for k in gui['interfaces']]},
        'conflicts': conflicts if conf['enabled'] else [],
        'crs': {k: crs.get(k) for k in ('version', 'source', 'tag', 'signed_with', 'installed_at', 'rules', 'line',
                                        'tested')} if crs else None,
        'last': {k: last.get(k) for k in ('at', 'status', 'state', 'code', 'detail', 'message', 'sites')} if last else None,
        'xgs': common.xgs(),
    }


def main():
    try:
        print(json.dumps(status()))
    except Exception as error:  # the page always gets an answer it can read
        print(json.dumps({'state': 'unreadable', 'error': {'message': '%s: %s' % (type(error).__name__, error)}}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
