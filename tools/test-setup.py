#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The Web Application Firewall's Apply and status, run against config.xml as OPNsense 26.7 writes it
(tools/fixtures/config.xml), with its certificates and keys made here by OpenSSL at each run, every path
moved into a temporary directory, and stand-ins for what only a firewall has: Apache (httpd -t, its pid),
the rc script, Apache's error log, PHP's interfaces_addresses() for listen.php.

What is checked: a site's host names, wildcards and backend read as the model reads them (one table with
tools/test-model.php: tools/fixtures/cases.json), and the web GUI's listeners and where they meet the
plugin's ports (settled point 8a); the sites Apache is given and those left out, each with its reason; the
certificates exported with their chain, the keys 0600, nothing else kept once Apache took the configuration;
the configuration rendered from the templates - its listeners, the catch-all virtual hosts, each site's
mode, paranoia rule, redirect to HTTPS, backend over HTTPS checked or not, the JSON audit log - and nothing
of config.xml in it that is not checked; Apply's way: off - Apache stopped; refused - Apache left as it
was and why said, by a code the page translates; tested by Apache, and put back when Apache refuses it;
started or reloaded - a reload waited for until Apache's log says it is done - and, when Apache does not run
it, the files before put back with the certificates they name: run again after a reload Apache did not
survive, left stopped after a start that failed; the log files pruned after OPNsense's days;
listen.php's addresses; and the page's status in each of its states.

    python3 tools/test-setup.py"""
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'src/opnsense/scripts/modsecurity')
TEMPLATES = os.path.join(ROOT, 'src/opnsense/service/templates/OPNsense/ModSecurity')
sys.path.insert(0, SCRIPTS)
import common  # noqa: E402
import setup  # noqa: E402
import status  # noqa: E402

OPENSSL = shutil.which('openssl')
PHP = shutil.which('php')
CASES = json.load(open(os.path.join(HERE, 'fixtures', 'cases.json'), encoding='utf-8'))
FIXTURE = open(os.path.join(HERE, 'fixtures', 'config.xml'), encoding='utf-8').read()
failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


if not OPENSSL:
    print('FAIL this needs openssl')
    sys.exit(1)

TOP = tempfile.mkdtemp(prefix='test-setup.')


def openssl(*args):
    subprocess.run([OPENSSL] + list(args), check=True, capture_output=True)


def b64(path):
    return base64.b64encode(open(path, 'rb').read()).decode('ascii')


# a CA and a site certificate it signed, made here: no key is kept in the repository
PKI = os.path.join(TOP, 'pki')
os.makedirs(PKI)
openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout',
        PKI + '/ca.key', '-out', PKI + '/ca.crt', '-days', '2', '-subj', '/CN=Example CA')
openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', PKI + '/site.key',
        '-out', PKI + '/site.csr', '-subj', '/CN=www.example.com')
openssl('x509', '-req', '-in', PKI + '/site.csr', '-CA', PKI + '/ca.crt', '-CAkey', PKI + '/ca.key', '-CAcreateserial',
        '-out', PKI + '/site.crt', '-days', '2')
CONFIG_TEXT = FIXTURE.replace('@CRT@', b64(PKI + '/site.crt')).replace('@PRV@', b64(PKI + '/site.key')) \
    .replace('@CA@', b64(PKI + '/ca.crt')).replace('@NOKEY@', '')
CONFIG = os.path.join(TOP, 'config.xml')


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)
    os.chmod(path, mode)


def config(text=None, change=None):
    """config.xml: the fixture, or text, with change(root) made to it."""
    text = text if text is not None else CONFIG_TEXT
    if change:
        root = ET.fromstring(text)
        change(root)
        text = ET.tostring(root, encoding='unicode')
    write(CONFIG, text)
    return common.read_root(CONFIG)


# every path the scripts use, in the temporary directory
common.CONFIG = CONFIG
common.ETC = TOP + '/etc/os-modsecurity'
common.CRS = common.ETC + '/crs'
common.STATE = TOP + '/db/os-modsecurity'
common.WORK = TOP + '/tmp/os-modsecurity'
common.LOGS = TOP + '/log/modsecurity'
common.RUN = TOP + '/run/modsecurity'
common.PIDFILE = TOP + '/run/modsecurity.pid'
common.SHARE = TOP + '/share/os-modsecurity'
common.HTTPD = TOP + '/sbin/httpd'
common.ROTATELOGS = TOP + '/sbin/rotatelogs'
common.MODULES = TOP + '/libexec/apache24'
common.SECURITY2 = (TOP + '/libexec/apache24/mod_security2.so', TOP + '/lib/mod_security2.so')
common.TRUST = TOP + '/ssl/cert.pem'
common.RC = TOP + '/rc.d/modsecurity'
common.PROJECT = TOP + '/xgs'
setup.TEMPLATES = TEMPLATES
ALL_MODULES = ['mod_mpm_event.so'] + [m[1] for m in setup.ALWAYS + setup.TLS + setup.REDIRECT]


def packages(modules=None, security2=1, httpd=True, rotatelogs=True):
    """apache24 and ap24-mod_security as far as the scripts look: their files."""
    for path in (common.HTTPD, common.ROTATELOGS):
        if os.path.exists(path):
            os.unlink(path)
    shutil.rmtree(TOP + '/libexec', ignore_errors=True)
    shutil.rmtree(TOP + '/lib', ignore_errors=True)
    if httpd:
        write(common.HTTPD, '#!/bin/sh\n', 0o755)
    if rotatelogs:
        write(common.ROTATELOGS, '#!/bin/sh\n', 0o755)
    for name in (ALL_MODULES if modules is None else modules):
        write(os.path.join(common.MODULES, name), '')
    if security2 is not None:
        write(common.SECURITY2[security2], '')


def crs(version='4.25.2'):
    """A Core Rule Set installed as crs.py leaves it."""
    shutil.rmtree(common.CRS, ignore_errors=True)
    os.makedirs(os.path.join(common.CRS, version, 'rules'))
    write(os.path.join(common.CRS, version, 'crs-setup.conf'), '# setup\n')
    os.symlink(version, os.path.join(common.CRS, 'current'))
    common.write_json(os.path.join(common.CRS, 'installed.json'), {'version': version, 'source': 'release',
                                                                     'signed_with': 'xgs-release-key-test.pub',
                                                                     'rules': 27, 'installed_at': 1795000000})


# --- the table both readings share -------------------------------------------------------------------

for name in CASES['names']['taken']:
    check('a host name taken: %r' % name, common.name_ok(name), True)
for name in CASES['names']['refused']:
    check('a host name refused: %r' % name, common.name_ok(name), False)
for raw, want in CASES['normalize']:
    check('names read as kept: %r' % raw, common.names(raw), want)
for wildcard, name, want in CASES['covers']:
    check('%s takes %s: %s' % (wildcard, name, want), common.covers(wildcard, name), want)
for raw, url, tls in CASES['backends']['taken']:
    found = common.backend(raw)
    check('a backend taken: %r' % raw, (found or {}).get('url'), url)
    check('a backend over HTTPS or not: %r' % raw, (found or {}).get('tls'), tls)
for raw in CASES['backends']['refused']:
    check('a backend refused: %r' % raw, common.backend(raw), None)


def webgui_root(fields):
    root = ET.Element('opnsense')
    node = ET.SubElement(ET.SubElement(root, 'system'), 'webgui')
    for key, value in fields.items():
        ET.SubElement(node, key).text = value
    return root


for case in CASES['webgui']:
    gui = common.webgui(webgui_root(case['webgui']))
    check('the web GUI listens on %s' % json.dumps(case['webgui']), [gui['ports'], gui['interfaces']],
          [case['listeners']['ports'], case['listeners']['interfaces']])
    found = common.gui_conflicts(gui, case['ports'], case['interfaces'])
    check('the plugin on %s %s: the GUI holds %s' % (case['ports'], case['interfaces'] or 'every address', case['conflicts']),
          [c['port'] for c in found], case['conflicts'])
check('no web GUI in config.xml: OPNsense\'s default, 443 and 80 everywhere', common.webgui(ET.Element('opnsense'))['ports'],
      [80, 443])

# --- what config.xml says -------------------------------------------------------------------------------

root = config()
conf = common.general(root)
check('the settings as config.xml has them', conf, {'read': True, 'enabled': True, 'interfaces': ['wan'], 'http_port': 80,
                                                    'https_port': 443})
check('no settings in config.xml: off, every address, 80 and 443', common.general(ET.fromstring('<opnsense/>')),
      {'read': True, 'enabled': False, 'interfaces': [], 'http_port': 80, 'https_port': 443})
empty = config(change=lambda r: [setattr(r.find('OPNsense/ModSecurity/general/http_port'), 'text', ''),
                                 setattr(r.find('OPNsense/ModSecurity/general/https_port'), 'text', 'x')])
check('an empty port is none; one that is no port is none', [common.general(empty)['http_port'],
                                                               common.general(empty)['https_port']], [None, None])
entries = common.sites(root)
check('the sites in their order, each as written', [(s['description'], s['names'], s['mode'], s['paranoia'], s['verify'],
                                                     s['enabled']) for s in entries],
      [('Shop', ['www.example.com', 'example.com'], 'blocking', 2, True, True),
       ('Intranet', ['*.intranet.example.org'], 'detection', 1, False, True),
       ('Under the wildcard', ['a.intranet.example.org'], 'detection', 1, True, True),
       ('Off', ['www.example.com'], 'blocking', 4, True, False)])
odd = config(change=lambda r: [setattr(r.find('OPNsense/ModSecurity/sites/site/mode'), 'text', 'panic'),
                               setattr(r.find('OPNsense/ModSecurity/sites/site/paranoia'), 'text', '9')])
check('a mode or a level the model does not have: detection only, level 1', [common.sites(odd)[0]['mode'],
                                                                            common.sites(odd)[0]['paranoia']], ['detection', 1])
check('the interfaces assigned, os-xgs-npu\'s own link left out', sorted(common.assigned(root)),
      ['lan', 'opt2', 'wan'])
check('an interface\'s description and whether it is enabled', [common.assigned(root)['wan'],
                                                                 common.assigned(root)['opt2']['enabled']],
      [{'descr': 'WAN', 'device': 'oxp0', 'enabled': True}, False])

found = common.certificate(root, '6a1b2c3d4e5f6')
site_pem = open(PKI + '/site.crt').read()
ca_pem = open(PKI + '/ca.crt').read()
check('a certificate with its chain: the site\'s, then its authority\'s', found['crt'],
      common.clean_pem(site_pem) + common.clean_pem(ca_pem))
check('its key', found['key'], common.clean_pem(open(PKI + '/site.key').read()))
check('a certificate without its private key: none to serve with', common.certificate(root, '6a1b2c3d4e5f7'), None)
check('a certificate that is not there: none', common.certificate(root, 'nothere'), None)
check('a refid that is no refid: none', common.certificate(root, '../x'), None)

# --- the sites Apache is given ----------------------------------------------------------------------------

usable, skipped = common.check_sites(conf, entries, root)
check('the sites given: the shop and the intranet; the disabled one in neither list', [s['description'] for s in usable],
      ['Shop', 'Intranet'])
check('left out: the one under an earlier site\'s wildcard, named with it', [(s['description'], s['reason'], s['detail'])
                                                                              for s in skipped],
      [('Under the wildcard', 'covered', 'a.intranet.example.org')])
reversed_entries = [entries[2], entries[1]]
check('the earlier site keeps its names: the wildcard that would take an earlier name is left out',
      [(s['description'], s['reason']) for s in common.check_sites(conf, reversed_entries, root)[1]],
      [('Intranet', 'covered')])


def one(**changes):
    site = dict(entries[0], uuid='0d0c3b6e-1a2b-4c3d-8e4f-0a1b2c3d4eff', description='Test')
    site.update(changes)
    return site


cases = [
    ('a name that is no host name', one(names=['www example.com']), conf, 'names'),
    ('no name', one(names=[]), conf, 'names'),
    ('an IP address as a name', one(names=['192.0.2.10']), conf, 'names'),
    ('a uuid that is none', one(uuid='x'), conf, 'names'),
    ('too many names', one(names=['n%d.example.com' % i for i in range(33)]), conf, 'names'),
    ('a backend that is no URL', one(backend='192.0.2.10'), conf, 'backend'),
    ('a backend with a quote', one(backend='http://192.0.2.10/"x'), conf, 'backend'),
    ('a certificate not in System: Trust', one(certificate='6a1b2c3d4e5ff'), conf, 'certificate'),
    ('a certificate without its key', one(certificate='6a1b2c3d4e5f7'), conf, 'certificate'),
    ('a certificate and no HTTPS port', one(), dict(conf, https_port=None), 'nohttps'),
    ('no certificate and no HTTP port', one(certificate=''), dict(conf, http_port=None), 'nohttp'),
]
for name, site, c, reason in cases:
    got = common.check_sites(c, [site], root)
    check('left out, %s: %s' % (name, reason), [got[0], [s['reason'] for s in got[1]]], [[], [reason]])
twice = common.check_sites(conf, [one(), one(uuid='0d0c3b6e-1a2b-4c3d-8e4f-0a1b2c3d4efe', names=['example.com'])], root)
check('a name another site has: the later one left out, the name said', [[s['description'] for s in twice[0]],
                                                                          [(s['reason'], s['detail']) for s in twice[1]]],
      [['Test'], [('duplicate', 'example.com')]])

# the expression the paranoia rules match a request's host name with, against Apache's own matching
rx = __import__('re').compile(common.server_name_rx(['www.example.com', '*.shop.example.org']))
for host, want in (('www.example.com', True), ('a.shop.example.org', True), ('a.b.shop.example.org', True),
                   ('shop.example.org', False), ('wwwxexample.com', False), ('www.example.com.evil', False),
                   ('x.www.example.com', False), ('.shop.example.org', False)):
    check('the paranoia rule takes %s: %s, as Apache\'s ServerName and ServerAlias do' % (host, want),
          bool(rx.match(host)), want)
check('the expression: each name whole, dots escaped, a wildcard any run of characters',
      common.server_name_rx(['www.example.com', '*.shop.example.org', 'a-b.example.com']),
      r'^(?:www\.example\.com|.+\.shop\.example\.org|a-b\.example\.com)$')
check('a site of wildcards alone: a ServerName of the reserved .invalid domain, every name an alias',
      setup.server_names({'names': ['*.example.com', '*.example.org'], 'uuid': '0D0C3B6E-1a2b'}),
      ('site-0d0c3b6e.invalid', ['*.example.com', '*.example.org']))
check('a site with a wildcard first: its first exact name the ServerName',
      setup.server_names({'names': ['*.example.com', 'example.com'], 'uuid': 'x'}), ('example.com', ['*.example.com']))

# --- the configuration Apply writes --------------------------------------------------------------------

packages()
crs()
WHERE = [{'address': '203.0.113.1', 'family': 4}, {'address': '2001:db8::1', 'family': 6}]
facts = setup.plan(root, conf, entries, WHERE)
certs, cert_files = setup.certificate_files(root, facts['usable'], setup.paths()['certs'])
setup.folders()
setup.put(cert_files)
ctx, files = setup.configuration(facts, conf, certs)
httpd = files[setup.paths()['conf']]
msconf = files[setup.paths()['msconf']]
lines = [line.strip() for line in httpd.splitlines()]


def block(text, start, end='</VirtualHost>'):
    """The lines of each block that starts with start, up to its end."""
    out, current = [], None
    for line in text.splitlines():
        line = line.strip()
        if current is None and line == start:
            current = []
        elif current is not None:
            if line == end:
                out.append(current)
                current = None
            else:
                current.append(line)
    return out


check('the certificate written with its chain, the key root\'s alone', [
    open(certs['6a1b2c3d4e5f6']['crt']).read() == common.clean_pem(site_pem) + common.clean_pem(ca_pem),
    oct(os.stat(certs['6a1b2c3d4e5f6']['key']).st_mode & 0o777), oct(os.stat(setup.paths()['certs']).st_mode & 0o777)],
    [True, '0o600', '0o700'])
check('Apache listens on each address of the interfaces chosen, HTTP and HTTPS',
      [line for line in lines if line.startswith('Listen ')],
      ['Listen 203.0.113.1:80 http', 'Listen [2001:db8::1]:80 http', 'Listen 203.0.113.1:443 https',
       'Listen [2001:db8::1]:443 https'])
check('the modules a site with a certificate and one with an HTTPS backend need, and ModSecurity\'s',
      [line.split()[1] for line in lines if line.startswith('LoadModule ')],
      ['mpm_event_module', 'authz_core_module', 'unixd_module', 'unique_id_module', 'headers_module', 'proxy_module',
       'proxy_http_module', 'reqtimeout_module', 'socache_shmcb_module', 'ssl_module', 'rewrite_module',
       'security2_module'])
check('a request read within bounds: the handshake, the headers and the body, as Apache\'s own defaults and more',
      [line for line in lines if line.startswith('RequestReadTimeout')],
      ['RequestReadTimeout handshake=5 header=20-40,MinRate=500 body=20,MinRate=500'])
check('ModSecurity\'s module where the package laid it on the second XGS 3300: lib', 'LoadModule security2_module %s'
      % common.SECURITY2[1] in lines, True)
check('a reverse proxy only, never a forward one', 'ProxyRequests Off' in lines, True)
check('its own pid file and runtime directory, never the package\'s', ['PidFile "%s"' % common.PIDFILE in lines,
                                                                      'DefaultRuntimeDir "%s"' % common.RUN in lines],
      [True, True])
check('the Core Rule Set by its own directory, crs/<version>, never crs/current: a configuration put back keeps its rules',
      'Include "%s/4.25.2/crs-setup.conf"' % os.path.realpath(common.CRS) in lines, True)
check('Apache\'s warnings and its MPM\'s notices, which say when a start or a graceful restart is done',
      'LogLevel warn mpm_event:notice' in lines, True)
check('the Core Rule Set after ModSecurity\'s settings, and each site\'s paranoia rule between its setup and its rules',
      [line.split()[0] + ' ' + line.split()[1].rsplit('/', 2)[-1] for line in lines
       if line.startswith(('Include ', 'SecRule SERVER_NAME', 'IncludeOptional'))],
      ['Include modsecurity.conf"', 'Include crs-setup.conf"', 'SecRule SERVER_NAME', 'SecRule SERVER_NAME',
       'IncludeOptional *-config.conf"', 'IncludeOptional *-before.conf"', 'Include *.conf"', 'IncludeOptional *-after.conf"'])
rules = [line for line in lines if line.startswith('SecRule SERVER_NAME')]
check('the paranoia rules: one a site, its level, ids from 19001, the first that matches the last that runs', rules, [
    'SecRule SERVER_NAME "@rx ^(?:www\\.example\\.com|example\\.com)$" "id:19001,phase:1,pass,nolog,t:none,t:lowercase,'
    'setvar:tx.blocking_paranoia_level=2,skipAfter:OS_MODSECURITY_SITES"',
    'SecRule SERVER_NAME "@rx ^(?:.+\\.intranet\\.example\\.org)$" "id:19002,phase:1,pass,nolog,t:none,t:lowercase,'
    'setvar:tx.blocking_paranoia_level=1,skipAfter:OS_MODSECURITY_SITES"'])
check('the marker the rules skip to, after them', lines.index('SecMarker OS_MODSECURITY_SITES') > lines.index(rules[-1]), True)
http_hosts = block(httpd, '<VirtualHost *:80>')
https_hosts = block(httpd, '<VirtualHost *:443>')
check('the catch-all first on each port: not inspected, refused', [http_hosts[0], https_hosts[0][:1] + https_hosts[0][-4:]], [
    ['ServerName unknown.invalid', 'SecRuleEngine Off', '<Location "/">', 'Require all denied', '</Location>'],
    ['ServerName unknown.invalid', 'SecRuleEngine Off', '<Location "/">', 'Require all denied', '</Location>']])
check('the HTTPS catch-all with the first site\'s certificate', 'SSLCertificateFile "%s"' % certs['6a1b2c3d4e5f6']['crt']
      in https_hosts[0], True)
check('the shop: plain HTTP sent to HTTPS, its own name and port kept', http_hosts[1], [
    'ServerName www.example.com', 'ServerAlias example.com', 'SecRuleEngine On', 'RewriteEngine On',
    'RewriteRule "^" "https://%{SERVER_NAME}%{REQUEST_URI}" [R=301,L]'])
check('the shop over HTTPS: its certificate, Blocking, its backend, the Host passed on, X-Forwarded-Proto https',
      https_hosts[1], [
          'ServerName www.example.com', 'ServerAlias example.com', 'SSLEngine on',
          'SSLCertificateFile "%s"' % certs['6a1b2c3d4e5f6']['crt'], 'SSLCertificateKeyFile "%s"' % certs['6a1b2c3d4e5f6']['key'],
          'SecRuleEngine On', 'ProxyPreserveHost On', 'RequestHeader set X-Forwarded-Proto "https"',
          'ProxyPass "/" "http://192.0.2.10:8080/" retry=5', 'ProxyPassReverse "/" "http://192.0.2.10:8080/"'])
check('the intranet over plain HTTP: a wildcard alias with an .invalid ServerName, Detection only, its HTTPS backend '
      'taken unchecked as asked', http_hosts[2], [
          'ServerName site-0d0c3b6e.invalid', 'ServerAlias *.intranet.example.org', 'SecRuleEngine DetectionOnly',
          'ProxyPreserveHost On', 'SSLProxyEngine on', 'SSLProxyVerify none', 'SSLProxyCheckPeerName off',
          'SSLProxyCheckPeerExpire off', 'RequestHeader set X-Forwarded-Proto "http"',
          'ProxyPass "/" "https://[2001:db8::10]:8443/app/" retry=5', 'ProxyPassReverse "/" "https://[2001:db8::10]:8443/app/"'])
check('no HTTPS virtual host for a site without a certificate', len(https_hosts), 2)
check('the site under the wildcard and the disabled one: nowhere in the configuration',
      [('198.51.100.5' in httpd), ('192.0.2.20' in httpd)], [False, False])
check('TLS as Mozilla\'s intermediate profile', ['SSLProtocol -all +TLSv1.2 +TLSv1.3' in lines,
                                                 'SSLSessionTickets off' in lines], [True, True])

verified = setup.configuration(dict(facts, usable=[dict(facts['usable'][1], verify=True)], tls_front=False,
                                    ports=[(80, 'http')]), conf, {})[1][setup.paths()['conf']]
check('an HTTPS backend checked: required, against the trust store, by its name', [
    'SSLProxyVerify require' in verified, 'SSLProxyCACertificateFile "%s"' % common.TRUST in verified,
    'SSLProxyCheckPeerName on' in verified], [True, True, True])
checked = block(verified, '<VirtualHost *:80>')[1]
form = ET.parse(os.path.join(ROOT, 'src/opnsense/mvc/app/controllers/OPNsense/ModSecurity/forms/dialogSite.xml')).getroot()
helps = {f.findtext('id'): f.findtext('help') for f in form.iter('field')}
check('the browser\'s host name passed on and the backend\'s certificate checked against it - as the dialog\'s help says',
      ['ProxyPreserveHost On' in checked, 'SSLProxyCheckPeerName on' in checked,
       'valid for the site\'s host names, not for the name or address written in Backend' in helps['site.verify'],
       'its certificate is checked against it' in helps['site.backend']], [True, True, True, True])
odd_port = setup.configuration(facts, dict(conf, https_port=8443), certs)[1][setup.paths()['conf']]
check('HTTPS on another port: the redirect names it', 'RewriteRule "^" "https://%{SERVER_NAME}:8443%{REQUEST_URI}" '
      '[R=301,L]' in odd_port, True)

check('ModSecurity off by default, each site\'s own mode in its virtual host', msconf.count('SecRuleEngine Off'), 1)
check('the audit log: JSON, a file a day, the parts kept without the request\'s body', [
    'SecAuditLogFormat JSON' in msconf, 'SecAuditLog "|%s -l -f %s/audit_%%Y%%m%%d.log 86400"' % (common.ROTATELOGS, common.LOGS)
    in msconf, 'SecAuditLogParts ABFHZ' in msconf], [True, True, True])
check('the headers that carry credentials masked in it, by rule 19000', 'id:19000,phase:1,pass,nolog,t:none,'
      'sanitiseRequestHeader:Authorization,sanitiseRequestHeader:Proxy-Authorization,sanitiseRequestHeader:Cookie,'
      'sanitiseResponseHeader:Set-Cookie' in msconf, True)
limits = {line.split()[0]: int(line.split()[1]) for line in msconf.splitlines()
          if line.startswith(('SecRequestBodyLimit ', 'SecRequestBodyNoFilesLimit '))}
check('the request body\'s limits, refused in Blocking: what the Mode\'s help says, 12.5 MiB with files and 128 KiB without',
      [limits['SecRequestBodyLimit'] / (1 << 20), limits['SecRequestBodyNoFilesLimit'] / (1 << 10),
       'SecRequestBodyLimitAction Reject' in msconf,
       'larger than 12.5 MiB with files, or 128 KiB without, is refused with 413' in helps['site.mode'],
       'GET, HEAD, POST and OPTIONS' in helps['site.mode']], [12.5, 128.0, True, True, True])
check('nothing reported to ModSecurity\'s makers', 'SecStatusEngine Off' in msconf, True)
check('ModSecurity\'s work files where Apache\'s children write them', 'SecTmpDir "%s/tmp/"' % common.WORK in msconf, True)

# plain HTTP only, every address - the GUI moved to 4443, its redirect off
moved = config(change=lambda r: [setattr(r.find('system/webgui/port'), 'text', '4443'),
                                 setattr(r.find('system/webgui/interfaces'), 'text', ''),
                                 ET.SubElement(r.find('system/webgui'), 'disablehttpredirect').__setattr__('text', '1')])
plain = dict(conf, interfaces=[], https_port=None)
facts2 = setup.plan(moved, plain, [dict(entries[1]), dict(entries[0], enabled=False)], setup.addresses(plain))
files2 = setup.configuration(facts2, plain, {})[1]
lines2 = [line.strip() for line in files2[setup.paths()['conf']].splitlines()]
check('no interface chosen: every address, IPv4 and IPv6; no HTTPS where no site has a certificate',
      [line for line in lines2 if line.startswith('Listen ')], ['Listen 0.0.0.0:80 http', 'Listen [::]:80 http'])
check('no TLS settings, no redirect module, no HTTPS catch-all where nothing is served over HTTPS', [
    any(line.startswith('SSLProtocol') for line in lines2), 'rewrite_module' in files2[setup.paths()['conf']],
    len(block(files2[setup.paths()['conf']], '<VirtualHost *:443>'))], [False, False, 0])
check('TLS\'s module still, for the HTTPS backend', 'LoadModule ssl_module' in files2[setup.paths()['conf']], True)

# a config.xml that no Save checked: nothing of it reaches Apache unchecked
hostile = [dict(entries[0], uuid='0d0c3b6e-1a2b-4c3d-8e4f-0a1b2c3d4e10', names=['x.example.com\nInclude /etc'],
                backend='http://192.0.2.10'),
           dict(entries[1], uuid='0d0c3b6e-1a2b-4c3d-8e4f-0a1b2c3d4e11', names=['y.example.com'],
                backend='http://192.0.2.10/"\nProxyRequests On')]
got = common.check_sites(conf, hostile, root)
check('host names and backends that would carry a directive: both sites left out', [got[0], [s['reason'] for s in got[1]]],
      [[], ['names', 'backend']])

# --- what is refused, and said --------------------------------------------------------------------------

calls = []
answers = {}


class Done:
    def __init__(self, code=0, out='', err=''):
        self.returncode, self.stdout, self.stderr = code, out, err


def run(args, **kwargs):
    calls.append(list(args))
    key = os.path.basename(args[0]) + ' ' + ' '.join(args[1:2])
    return answers.get(key, Done())


alive = {'pid': None, 'after_start': None, 'after_reload': 'same'}


def fake_running():
    return alive['pid']


def fake_ours(pid):
    return pid is not None and alive['pid'] == pid


def log_line(text):
    """A line of Apache's error log of today, as Apache writes one."""
    with open(setup.error_log(), 'a', encoding='utf-8') as handle:
        handle.write('[Fri Nov 20 12:00:00.000000 2026] %s\n' % text)


RESUMED = '[mpm_event:notice] [pid 4242:tid 1] AH00489: Apache/2.4.70 (FreeBSD) configured -- resuming normal operations'
NOBIND = ('[core:emerg] [pid 4242:tid 1] (48)Address already in use: AH00072: make_sock: could not bind to address '
          '203.0.113.1:443')


def fake_run(args, **kwargs):
    done = run(args, **kwargs)
    if args[0] == common.RC and args[1] == 'onestart':
        alive['pid'] = alive['after_start']
        if alive['pid'] is None:
            log_line(NOBIND)
    if args[0] == common.RC and args[1] == 'onereload':
        if alive['after_reload'] == 'same':
            log_line(RESUMED)
        else:
            alive['pid'] = alive['after_reload']
            log_line(NOBIND)
            log_line('[mpm_event:alert] [pid 4242:tid 1] no listening sockets available, shutting down')
    if args[0] == common.RC and args[1] == 'onestop':
        alive['pid'] = None
    return done


setup.running_pid = fake_running
setup.ours = fake_ours
answers['pgrep -f'] = Done(1)


def apply(change=None, where=WHERE, start=4242, reload='same', pid=None):
    del calls[:]
    alive.update(pid=pid, after_start=start, after_reload=reload)
    config(change=change)
    return setup.apply(CONFIG, run=fake_run, sleep=lambda s: None, listen_found=where)


def rc_calls():
    return [c[1] for c in calls if c[0] == common.RC]


off = apply(change=lambda r: setattr(r.find('OPNsense/ModSecurity/general/enabled'), 'text', '0'), pid=4242)
check('off: Apache stopped, said off', [off['status'], off['state'], rc_calls()], ['ok', 'off', ['onestop']])
check('Apply\'s answer kept for the page', common.read_json(setup.paths()['apply'])['state'], 'off')

packages(httpd=False)
got = apply()
check('apache24 not installed: refused, Apache left as it was', [got['status'], got['code'], rc_calls()],
      ['failed', 'packages', []])
packages(security2=None)
check('ap24-mod_security not installed: refused', apply()['code'], 'packages')
packages(security2=0)
got = apply()
check('ModSecurity\'s module in libexec/apache24, beside Apache\'s own: taken', [got['status'], 'LoadModule security2_module '
      + common.SECURITY2[0] in open(setup.paths()['conf']).read()], ['ok', True])
packages(modules=[m for m in ALL_MODULES if m != 'mod_ssl.so'])
got = apply()
check('a module Apache has not: refused, the module named', [got['code'], got['detail']], ['module', 'mod_ssl.so'])
packages(modules=[m for m in ALL_MODULES if m != 'mod_reqtimeout.so'])
got = apply()
check('no mod_reqtimeout: refused as any module is, never published without it', [got['code'], got['detail'], rc_calls()],
      ['module', 'mod_reqtimeout.so', []])
packages()
shutil.rmtree(common.CRS)
got = apply()
check('no Core Rule Set: refused, Apache left as it was', [got['code'], rc_calls()], ['norules', []])
crs()
got = apply(change=lambda r: setattr(r.find('OPNsense/ModSecurity/general/interfaces'), 'text', ''))
check('the plugin on every address where the GUI is on its LAN: 80 and 443 refused, with where the GUI listens',
      [got['code'], got['detail'], got.get('conflicts')], ['gui', '80,443', [{'port': 80, 'interfaces': ['lan']},
                                                                              {'port': 443, 'interfaces': ['lan']}]])
check('said with what fixes it on the page, Apache left as it was', [got['message'].endswith('Apache was left as it was'),
                                                                     rc_calls()], [True, []])
got = apply(change=lambda r: [r.find('OPNsense/ModSecurity/sites').remove(s) for s in
                              list(r.find('OPNsense/ModSecurity/sites'))])
check('no site to publish: Apache stopped, said', [got['status'], got['state'], rc_calls()], ['ok', 'nosite', ['onestop']])
got = apply(where=None, change=lambda r: setattr(r.find('OPNsense/ModSecurity/general/interfaces'), 'text', 'opt2'))
check('Listen interfaces with no address now: refused', got['code'], 'noaddress')
got = apply(change=lambda r: [setattr(r.find('OPNsense/ModSecurity/general/http_port'), 'text', '080'),
                              setattr(r.find('OPNsense/ModSecurity/general/https_port'), 'text', '80')])
check('one port for both kinds - 080 and 80 written: refused before Apache is asked, as the model refuses it',
      [got['code'], rc_calls(), [c for c in calls if c[0] == common.HTTPD]], ['sameport', [], []])

# --- Apache's test, the start, the reload ---------------------------------------------------------------

answers['httpd -t'] = Done(1, '', 'AH00526: Syntax error on line 9 of httpd.conf')
write(setup.paths()['conf'], '# the one before\n')
write(setup.paths()['msconf'], '# its settings before\n')
got = apply()
check('Apache refuses the configuration: said with its words, the files put back, nothing started',
      [got['code'], got['detail'], open(setup.paths()['conf']).read(), open(setup.paths()['msconf']).read(), rc_calls()],
      ['config', 'AH00526: Syntax error on line 9 of httpd.conf', '# the one before\n', '# its settings before\n', []])
del answers['httpd -t']
os.unlink(setup.paths()['conf'])
os.unlink(setup.paths()['msconf'])
write(os.path.join(setup.paths()['certs'], 'old.crt'), 'x')
answers['httpd -t'] = Done(1, '', 'AH00526')
got = apply()
check('no configuration before: none left after a refused one', [os.path.exists(setup.paths()['conf']),
                                                                 os.path.exists(setup.paths()['msconf'])], [False, False])
check('a refused configuration takes no certificate away: the one Apache runs may name it',
      os.path.exists(os.path.join(setup.paths()['certs'], 'old.crt')), True)
del answers['httpd -t']
got = apply()
check('Apache tested, then started; said with the sites', [got['status'], got['state'], got['sites'], got['crs'],
                                                           rc_calls()[-1:], got['message']],
      ['ok', 'running', 2, '4.25.2', ['onestart'], 'Apache started with 2 sites'])
check('Apache\'s test before the start', [c[1:3] for c in calls if c[0] in (common.HTTPD, common.RC)],
      [['-t', '-f'], ['onestart']])
check('the sites left out said with the answer', [s['reason'] for s in got['skipped']], ['covered'])
check('what Apache listens on, said', got['listen'], ['203.0.113.1:80', '[2001:db8::1]:80', '203.0.113.1:443',
                                                      '[2001:db8::1]:443'])
check('once Apache took it, the certificates no site uses taken away', sorted(os.listdir(setup.paths()['certs'])),
      ['6a1b2c3d4e5f6.crt', '6a1b2c3d4e5f6.key'])
check('the directories made: ModSecurity\'s work files, the logs root\'s alone', [
    os.path.isdir(common.WORK + '/tmp'), oct(os.stat(common.LOGS).st_mode & 0o777)], [True, '0o750'])
got = apply(pid=4242)
check('Apache running: reloaded, not started again', [got['state'], rc_calls(), got['message']],
      ['running', ['onereload'], 'Apache reloaded with 2 sites'])

# a reload Apache does not survive: the files before, and their certificates, put back and run again
CONF, MSCONF, CERTS = setup.paths()['conf'], setup.paths()['msconf'], setup.paths()['certs']
running = {path: open(path, 'rb').read() for path in (CONF, MSCONF)}
crt = os.path.join(CERTS, '6a1b2c3d4e5f6.crt')
write(crt, '-----BEGIN CERTIFICATE-----\nthe one Apache runs\n-----END CERTIFICATE-----\n')
write(os.path.join(CERTS, 'old.crt'), 'a certificate the running configuration names')
write(CONF, running[CONF].decode() + '# the configuration Apache runs\n')
running[CONF] = open(CONF, 'rb').read()
common.write_json(setup.paths()['apply'], {'status': 'ok', 'state': 'running', 'listen': ['203.0.113.1:80'], 'at': 1})
got = apply(pid=4242, reload=None, start=4243)
check('Apache gone after the reload: the configuration before put back and started again, said with Apache\'s words',
      [got['status'], got['state'], got['code'], rc_calls(), 'AH00072' in got['detail']],
      ['failed', 'running', 'restored', ['onereload', 'onestart'], True])
check('the two files Apache ran, back as they were', [open(CONF, 'rb').read() == running[CONF],
                                                      open(MSCONF, 'rb').read() == running[MSCONF]], [True, True])
check('the certificates the configuration before names, back as they were and none taken away',
      [open(crt).read().split('\n')[1], os.path.exists(os.path.join(CERTS, 'old.crt')),
       oct(os.stat(crt).st_mode & 0o777)], ['the one Apache runs', True, '0o644'])
check('where Apache listens, said as the configuration before has it', got['listen'], ['203.0.113.1:80'])
check('said so on the page: the one before runs again', got['message'].endswith('the one before runs again'), True)
got = apply(pid=4242, reload=None, start=None)
check('Apache gone after the reload, and the configuration before not started either: stopped, both said',
      [got['state'], got['code'], rc_calls(), got['detail'].count('AH00072'), got['listen']],
      ['stopped', 'start', ['onereload', 'onestart'], 2, []])
check('the files before put back all the same', open(CONF, 'rb').read() == running[CONF], True)

# a start that fails: the files before put back, Apache left stopped as it was - nothing older started
got = apply(start=None)
check('Apache not there after the start: said with its log, the files before put back, nothing else started',
      [got['status'], got['state'], got['code'], 'Address already in use' in got['message'], rc_calls(),
       open(CONF, 'rb').read() == running[CONF], os.path.exists(os.path.join(CERTS, 'old.crt'))],
      ['failed', 'stopped', 'start', True, ['onestart', 'onestop'], True, True])
alive.update(pid=None, after_start=None)
slept = []
check('the start command failing: not waited for', [setup.wait_started(setup.log_mark(), False, sleep=slept.append),
                                                    len(slept)], [None, 0])
mark = setup.log_mark()
log_line('[ssl:emerg] [pid 1:tid 1] AH02312: Fatal error initialising mod_ssl, exiting.')
check('Apache\'s log saying it ends: the start not waited for longer', [setup.wait_started(mark, True, sleep=slept.append),
                                                                        len(slept)], [None, 0])
check('without either, the start waited for as long as START_WAIT', [setup.wait_started(setup.log_mark(), True,
                                                                                         sleep=slept.append),
                                                                      len(slept) == int(setup.START_WAIT / setup.STEP)],
      [None, True])

# the reload waited for until Apache's own log says it is done, never by a fixed time
alive['pid'] = 4242
del slept[:]
log_line(RESUMED)
mark = setup.log_mark()


def resume_later(seconds):
    slept.append(seconds)
    if len(slept) == 3:
        log_line(RESUMED)


check('a graceful restart: done once Apache\'s log since the mark says so, not by its line before',
      [setup.wait_reloaded(4242, mark, sleep=resume_later), len(slept)], [4242, 3])
del slept[:]
check('no word in its log, Apache still there: waited for as long as RELOAD_WAIT, then taken as running',
      [setup.wait_reloaded(4242, setup.log_mark(), sleep=slept.append), len(slept) == int(setup.RELOAD_WAIT / setup.STEP)],
      [4242, True])
check('Apache gone: said at once', setup.wait_reloaded(4241, setup.log_mark(), sleep=slept.append), None)
yesterday = datetime.date.today() - datetime.timedelta(days=1)
write(setup.error_log(yesterday), 'one\n')
check('the log read across midnight: the rest of the day before, then today\'s',
      setup.log_since((setup.error_log(yesterday), 0)).split('\n')[0], 'one')
os.unlink(setup.error_log(yesterday))
check('what says why Apache would not run: its fatal lines alone, not the notices', setup.said_since(mark),
      '')
mark = setup.log_mark()
log_line(RESUMED)
log_line(NOBIND)
check('its fatal lines since the mark', setup.said_since(mark).endswith('could not bind to address 203.0.113.1:443'), True)

# the files put and put back with their modes, and a file that was not there taken away again
spot = os.path.join(TOP, 'put')
write(os.path.join(spot, 'a'), 'before', 0o600)
before = setup.put({os.path.join(spot, 'a'): ('after', 0o644), os.path.join(spot, 'b'): 'new'})
check('put: the files written, what they were kept', [open(os.path.join(spot, 'a')).read(), before[os.path.join(spot, 'b')]],
      ['after', None])
setup.put_back(before)
check('put back: the file as it was, its mode too, and the new one gone', [open(os.path.join(spot, 'a')).read(),
                                                                          oct(os.stat(os.path.join(spot, 'a')).st_mode & 0o777),
                                                                          os.path.exists(os.path.join(spot, 'b'))],
      ['before', '0o600', False])

# the certificates Apache serves, taken again each day as System: Trust has them (renewed in place)
got = apply()
CRT = os.path.join(CERTS, '6a1b2c3d4e5f6.crt')
served = open(CRT).read()
del calls[:]
check('each day, nothing renewed: nothing written, nothing reloaded', [setup.renewed(CONFIG, run=fake_run,
                                                                                     sleep=lambda s: None), rc_calls()],
      [{'status': 'ok', 'renewed': []}, []])


def renewal(name):
    """A certificate of www.example.com issued again by the same authority, as an ACME client renews one."""
    openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout',
            PKI + '/%s.key' % name, '-out', PKI + '/%s.csr' % name, '-subj', '/CN=www.example.com')
    openssl('x509', '-req', '-in', PKI + '/%s.csr' % name, '-CA', PKI + '/ca.crt', '-CAkey', PKI + '/ca.key',
            '-CAcreateserial', '-out', PKI + '/%s.crt' % name, '-days', '2')
    return FIXTURE.replace('@CRT@', b64(PKI + '/%s.crt' % name)).replace('@PRV@', b64(PKI + '/%s.key' % name)) \
        .replace('@CA@', b64(PKI + '/ca.crt')).replace('@NOKEY@', '')


config(text=renewal('renewed'))
with open(CONF, 'rb') as handle:
    conf_before = handle.read()
del calls[:]
alive.update(pid=4242, after_reload='same')
got = setup.renewed(CONFIG, run=fake_run, sleep=lambda s: None)
check('a certificate renewed in System: Trust: written again with its chain and its key, Apache reloaded gracefully',
      [got['status'], got['renewed'], rc_calls(), open(CRT).read() == common.clean_pem(open(PKI + '/renewed.crt').read()) +
       common.clean_pem(ca_pem), open(CRT.replace('.crt', '.key')).read() == common.clean_pem(open(PKI + '/renewed.key').read()),
       oct(os.stat(CRT.replace('.crt', '.key')).st_mode & 0o777)],
      ['ok', ['6a1b2c3d4e5f6'], ['onereload'], True, True, '0o600'])
check('nothing else of the configuration written: a setting saved and not applied still waits for Apply',
      open(CONF, 'rb').read() == conf_before, True)
check('said with the last Apply\'s answer, which it keeps', [common.read_json(setup.paths()['apply'])['renewed'],
                                                             common.read_json(setup.paths()['apply'])['status']],
      [['6a1b2c3d4e5f6'], 'ok'])
served = open(CRT).read()
config(text=renewal('again'))
del calls[:]
alive.update(pid=4242, after_reload=None, after_start=4243)
got = setup.renewed(CONFIG, run=fake_run, sleep=lambda s: None)
check('Apache gone after the reload with a renewed certificate: the ones before put back and run again, said',
      [got['code'], got['state'], rc_calls(), open(CRT).read() == served, common.read_json(setup.paths()['apply'])['code']],
      ['restored', 'running', ['onereload', 'onestart'], True, 'restored'])
del calls[:]
alive.update(pid=None)
check('Apache not running: nothing done - its next start is an Apply, which exports them all',
      [setup.renewed(CONFIG, run=fake_run, sleep=lambda s: None)['renewed'], rc_calls(), open(CRT).read() == served],
      [[], [], True])
config(text=renewal('again'), change=lambda r: setattr(r.find('OPNsense/ModSecurity/general/enabled'), 'text', '0'))
alive.update(pid=4243)
check('the plugin off: nothing done', [setup.renewed(CONFIG, run=fake_run, sleep=lambda s: None)['renewed'], rc_calls()],
      [[], []])
config()
alive.update(pid=None)
printed = __import__('io').StringIO()
real_stdout, sys.stdout = sys.stdout, printed
setup.main(['setup.py', 'daily'])
sys.stdout = real_stdout
check('setup.py daily, cron.d\'s: the logs pruned, then the certificates', sorted(json.loads(printed.getvalue())),
      ['certificates', 'pruned'])
check('cron.d runs it each day', open(os.path.join(ROOT, 'src/etc/cron.d/modsecurity')).read().strip().splitlines()[-1],
      '17 4 * * * root /usr/local/opnsense/scripts/modsecurity/setup.py daily > /dev/null 2>&1')

# one Apply at a time
os.makedirs(common.STATE, exist_ok=True)
holder = open(setup.paths()['lock'], 'w')
__import__('fcntl').flock(holder, __import__('fcntl').LOCK_EX)
got = setup.apply(CONFIG, run=fake_run, sleep=lambda s: None, listen_found=WHERE)
check('another Apply running: this one says so and changes nothing', [got['code'], got.get('state')], ['busy', None])
holder.close()

# --- the logs' days -------------------------------------------------------------------------------------

today = datetime.date(2026, 11, 20)
shutil.rmtree(common.LOGS)
for day in ('20261109', '20261110', '20261111', '20261120'):
    for kind in ('audit', 'error'):
        write(os.path.join(common.LOGS, '%s_%s.log' % (kind, day)), '')
write(os.path.join(common.LOGS, 'modsecurity_20261101.log'), '')
gone = setup.prune(config(), today)
check('the day files older than OPNsense\'s 10 days taken away, the rest kept, nothing else touched',
      [gone, sorted(os.listdir(common.LOGS))],
      [['audit_20261109.log', 'error_20261109.log'],
       ['audit_20261110.log', 'audit_20261111.log', 'audit_20261120.log', 'error_20261110.log', 'error_20261111.log',
        'error_20261120.log', 'modsecurity_20261101.log']])
check('no setting of its days: 31, as OPNsense\'s', setup.preserve(ET.fromstring('<opnsense/>')), 31)

# --- listen.php: the interfaces' addresses as the web GUI takes its own ----------------------------------

if PHP:
    stub = os.path.join(TOP, 'php')
    write(os.path.join(stub, 'config.inc'), '<?php\n')
    write(os.path.join(stub, 'util.inc'), '<?php\n')
    write(os.path.join(stub, 'interfaces.inc'), '<?php\nfunction interfaces_addresses($keys) {\n'
          '    file_put_contents(getenv("ASKED"), implode(",", $keys));\n    return json_decode(getenv("ADDRESSES"), true);\n}\n')
    addresses = {
        '203.0.113.1': {'address': '203.0.113.1', 'family': 'inet', 'bind': True, 'scope': False, 'tentative': False,
                        'interface': 'wan'},
        '203.0.113.9': {'address': '203.0.113.9', 'family': 'inet', 'bind': False, 'scope': False, 'tentative': False,
                        'interface': 'wan'},
        'fe80::1%oxp0': {'address': 'fe80::1', 'family': 'inet6', 'bind': True, 'scope': True, 'tentative': False,
                         'interface': 'wan'},
        '2001:db8::1': {'address': '2001:db8::1', 'family': 'inet6', 'bind': True, 'scope': False, 'tentative': False,
                        'interface': 'wan'},
        '2001:db8::2': {'address': '2001:db8::2', 'family': 'inet6', 'bind': True, 'scope': False, 'tentative': True,
                        'interface': 'wan'},
    }
    asked = os.path.join(TOP, 'asked')
    done = subprocess.run([PHP, '-d', 'include_path=' + stub, os.path.join(SCRIPTS, 'listen.php'), ' wan, lan ,'],
                          capture_output=True, text=True, env=dict(os.environ, ADDRESSES=json.dumps(addresses), ASKED=asked))
    check('listen.php: the bound addresses, not one a virtual IP keeps unbound, not a link-local or tentative one',
          json.loads(done.stdout or '{}'), {'addresses': [
              {'address': '203.0.113.1', 'family': 'inet', 'interface': 'wan'},
              {'address': '2001:db8::1', 'family': 'inet6', 'interface': 'wan'}]})
    check('listen.php: the interfaces asked for, as OPNsense keys them', open(asked).read(), 'wan,lan')
    done = subprocess.run([PHP, '-d', 'include_path=' + stub, os.path.join(SCRIPTS, 'listen.php')],
                          capture_output=True, text=True, env=dict(os.environ, ADDRESSES='{}', ASKED=asked))
    check('listen.php with no interface: none', json.loads(done.stdout), {'addresses': []})
    # setup.py asks it, through PHP
    setup.PHP = PHP
    real = subprocess.run

    def with_stub(args, **kwargs):
        if args[0] == PHP:
            args = [PHP, '-d', 'include_path=' + stub] + args[1:]
            kwargs['env'] = dict(os.environ, ADDRESSES=json.dumps(addresses), ASKED=asked)
        return real(args, **kwargs)
    check('the addresses Apache listens on, from listen.php', setup.addresses(conf, run=with_stub), [
        {'address': '203.0.113.1', 'family': 4}, {'address': '2001:db8::1', 'family': 6}])
else:
    print('skip listen.php: no php here')


def answer(out):
    return lambda args, **kwargs: Done(0, out, '')


check('listen.php\'s answer: a link-local or unspecified address left out, each once', setup.addresses(
    conf, run=answer(json.dumps({'addresses': [{'address': 'fe80::1'}, {'address': '0.0.0.0'}, {'address': '203.0.113.1'},
                                               {'address': '203.0.113.1'}, {'address': 'x'}, 'x']}))),
    [{'address': '203.0.113.1', 'family': 4}])
try:
    setup.addresses(conf, run=answer('PHP Fatal error'))
    check('listen.php not answering: no address', 'none refused', 'refused')
except setup.Refused as refused:
    check('listen.php not answering: no address', refused.code, 'noaddress')

# --- the page's status ----------------------------------------------------------------------------------

common.write_json(setup.paths()['apply'], {'status': 'ok', 'state': 'running', 'listen': ['203.0.113.1:443'], 'at': 1})
alive['pid'] = 4242
got = status.status(CONFIG)
check('running: the sites by mode, where Apache listens, the Core Rule Set', [got['state'], got['pid'], got['counts'],
                                                                             got['listen'], got['crs']['version']],
      ['running', 4242, {'sites': 4, 'enabled': 3, 'blocking': 1, 'detection': 1, 'tls': 1, 'usable': 2},
       ['203.0.113.1:443'], '4.25.2'])
check('a site left out, said with its reason; the interfaces by their descriptions', [
    [s['reason'] for s in got['skipped']], got['interfaces'], got['ports']],
    [['covered'], [{'key': 'wan', 'descr': 'WAN'}], {'http': 80, 'https': 443}])
check('no conflict with the GUI on its LAN; not an XGS appliance', [got['conflicts'], got['xgs']], [[], False])
os.makedirs(common.PROJECT)
check('os-xgs-npu installed: an XGS appliance', status.status(CONFIG)['xgs'], True)
alive['pid'] = None
check('on, Apache not running: stopped', status.status(CONFIG)['state'], 'stopped')
common.write_json(setup.paths()['apply'], {'status': 'failed', 'code': 'config', 'detail': 'AH00526', 'at': 1})
got = status.status(CONFIG)
check('the last Apply refused, Apache not running: failed, with its code', [got['state'], got['last']['code']],
      ['failed', 'config'])
config(change=lambda r: setattr(r.find('OPNsense/ModSecurity/general/interfaces'), 'text', ''))
got = status.status(CONFIG)
check('the GUI on a port chosen here: said', [c['port'] for c in got['conflicts']], [80, 443])
config(change=lambda r: [setattr(r.find('OPNsense/ModSecurity/general/interfaces'), 'text', ''),
                         setattr(r.find('interfaces/lan/descr'), 'text', 'Office')])
check('the GUI\'s interfaces named by their descriptions, as the page names them', status.status(CONFIG)['conflicts'][0],
      {'port': 80, 'interfaces': ['Office']})
config(change=lambda r: setattr(r.find('OPNsense/ModSecurity/general/enabled'), 'text', '0'))
got = status.status(CONFIG)
check('off: nothing to say of sites left out or conflicts', [got['state'], got['skipped'], got['conflicts']], ['off', [], []])
config()
shutil.rmtree(common.CRS)
check('no Core Rule Set: norules', status.status(CONFIG)['state'], 'norules')
crs()
packages(httpd=False)
check('apache24 missing: packages', status.status(CONFIG)['state'], 'packages')
packages()
write(CONFIG, '<opnsense>')
check('a config.xml that does not parse: unreadable, said', status.status(CONFIG)['state'], 'unreadable')

shutil.rmtree(TOP, ignore_errors=True)
print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
