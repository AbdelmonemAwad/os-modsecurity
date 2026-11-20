#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the Web Application Firewall's scripts share: where its files are, its settings read straight
out of config.xml by element name (models/OPNsense/ModSecurity/ModSecurity.xml - the names here are
not free), the web GUI's listeners, and the checks a site passes before Apache is given it.

config.xml is read as OPNsense's own reader reads it (Config::loadFromStream): under a shared lock, and
once more after waiting for the writer when what was read does not parse. Nothing here writes but
write_file() and write_json(), each a whole file written beside its place and renamed over it.

The checks are the model's (ModSecurity.php, library OPNsense\\ModSecurity\\Site and WebGui), made again
here because config.xml can hold what no Save checked - a restore, a hand edit: a site that fails one is
left out of Apache's configuration and named, and never written into it.
"""

import ipaddress
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET

try:
    import fcntl
except ImportError:                                 # not on a firewall: the tests' machines
    fcntl = None

CONFIG = '/conf/config.xml'

# What Apache reads, the plugin's own and never the package's (apache24 keeps its own in
# /usr/local/etc/apache24, ap24-mod_security its samples in /usr/local/etc/modsecurity): the
# configuration setup.py writes, the certificates it exports from System: Trust, the Core Rule Set.
ETC = '/usr/local/etc/os-modsecurity'
CRS = ETC + '/crs'
# What the plugin keeps of its own: the last Apply - root's alone.
STATE = '/var/db/os-modsecurity'
# ModSecurity's temporary and data files, written by Apache's children, which run as www.
WORK = '/var/tmp/os-modsecurity'
# The audit log's day files (JSON, settled point 7a), and Apache's error log's beside them: each written by
# Apache through rotatelogs (httpd.conf, modsecurity.conf), a file a day.
LOGS = '/var/log/modsecurity'
# Apache's runtime files - its TLS session cache, its locks - and its pid file.
RUN = '/var/run/modsecurity'
PIDFILE = '/var/run/modsecurity.pid'
SHARE = '/usr/local/share/os-modsecurity'

# apache24 and ap24-mod_security, OPNsense's own packages (settled point 1). The module's path is
# looked for in both places it may be: libexec/apache24, where Apache's modules are, and lib, where
# the package put it on the second XGS 3300 (phase 0's lab, 2026-11-20).
HTTPD = '/usr/local/sbin/httpd'
ROTATELOGS = '/usr/local/sbin/rotatelogs'
MODULES = '/usr/local/libexec/apache24'
SECURITY2 = ('/usr/local/libexec/apache24/mod_security2.so', '/usr/local/lib/mod_security2.so')
# The CA bundle an HTTPS backend's certificate is checked against: the trust store OPNsense keeps.
TRUST = '/usr/local/etc/ssl/cert.pem'
RC = '/usr/local/etc/rc.d/modsecurity'
CONFIGCTL = '/usr/local/sbin/configctl'

PROJECT = '/usr/local/opnsense/scripts/xgs'     # os-xgs-npu's scripts: there when it is installed

# os-xgs-npu's own links, never a place to listen on: the inspector's port and the management link to
# the coprocessor. The model's InterfaceField leaves them out by the same pattern (ModSecurity.xml).
INTERNAL = re.compile(r'^(oxips|oxmgmt|mvmgmt)[0-9]+$')

# The ports where the model has no value yet: a site's own ports, as OPNsense's other proxies take them.
HTTP_PORT = 80
HTTPS_PORT = 443
# The paranoia levels the Core Rule Set has (settled point 6), and each site's first one.
PARANOIA = (1, 2, 3, 4)
# Detection only for a new site (settled point 5): its requests are inspected and logged, and passed.
MODES = {'detection': 'DetectionOnly', 'blocking': 'On'}
# A site is a few host names: Apache's ServerName and its aliases.
NAMES_MAX = 32

LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
NAME = re.compile(r'(?:\*\.)?(?:' + LABEL + r'\.)*' + LABEL + r'\Z')
UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')
REFID = re.compile(r'[A-Za-z0-9._-]{1,64}\Z')
# A backend: http or https, a host name, an IPv4 address or an IPv6 one in brackets, a port, a path -
# nothing Apache's ProxyPass could read as a second argument, no user, no query, no fragment.
BACKEND = re.compile(r'(https?)://(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?'
                     r'(/[A-Za-z0-9._~%/-]*)?\Z')


def read_root(path=None):
    """config.xml's root, read under a shared lock, and once more after waiting for a writer when what
    was read does not parse. Opened read-only."""
    with open(path or CONFIG, 'rb') as handle:
        failure = None
        for wait in (False, True):
            locked = False
            if fcntl is not None:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_SH | (0 if wait else fcntl.LOCK_NB))
                    locked = True
                except OSError:
                    pass
            try:
                handle.seek(0)
                data = handle.read()
            finally:
                if locked:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            try:
                return ET.fromstring(data)
            except ET.ParseError as exc:
                failure = exc
        # a ValueError, which every caller takes as config.xml not read (ParseError is a SyntaxError)
        raise ValueError('config.xml does not parse: %s' % failure) from failure


def text(node, tag, default=''):
    if node is None:
        return default
    found = node.findtext(tag)
    return default if found is None else found.strip()


def port(node, tag, default):
    """A port from the model: the default where the element is absent (the model never saved), None
    where it is empty (no listener of that kind), or a number from 1 to 65535; anything else None."""
    if node is None or node.find(tag) is None:
        return default
    value = text(node, tag)
    if not re.fullmatch(r'[0-9]{1,5}', value):
        return None
    number = int(value)
    return number if 1 <= number <= 65535 else None


def name_ok(name):
    """A host name a site may have, written as it is kept: lower case, no dot at its end. A wildcard
    only as the whole first label (*.example.com), never an IP address (the model's IpAllowed N)."""
    if not isinstance(name, str) or len(name) > 253 or not NAME.match(name):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


def names(raw):
    """The host names of a site as the model keeps them - a comma-separated list - lower case, the dot
    at an end taken off, each once, in their order."""
    out = []
    for item in (raw or '').split(','):
        item = item.strip().lower().rstrip('.')
        if item and item not in out:
            out.append(item)
    return out


def covers(wildcard, name):
    """Whether the wildcard *.d takes the name: Apache's ServerAlias matches * with any run of
    characters, dots too, so *.example.com takes a.b.example.com - and a wildcard below it,
    *.shop.example.com, whose every name it takes. Never example.com itself."""
    if not wildcard.startswith('*.') or wildcard == name:
        return False
    bare = name[2:] if name.startswith('*.') else name
    return bare.endswith(wildcard[1:])


def backend(raw):
    """A site's backend, as Apache is given it: {'url', 'scheme', 'host', 'port', 'tls'}, its path
    ending in '/', or None when it is no URL Apache may proxy to."""
    found = BACKEND.match((raw or '').strip())
    if not found:
        return None
    scheme, host, digits, path = found.group(1), found.group(2), found.group(3), found.group(4) or '/'
    if host.startswith('['):
        try:
            if ipaddress.ip_address(host[1:-1]).version != 6:
                return None
        except ValueError:
            return None
    else:
        try:
            if ipaddress.ip_address(host).version != 4:
                return None
        except ValueError:
            # a name - not digits and dots, which would be an IPv4 address that is not one
            if not re.fullmatch(r'(?:' + LABEL + r'\.)*' + LABEL, host.lower()) or re.fullmatch(r'[0-9.]+', host):
                return None
        host = host.lower()
    number = None
    if digits is not None:
        number = int(digits)
        if not 1 <= number <= 65535:
            return None
    if not path.endswith('/'):
        path += '/'
    if '//' in path or '/../' in path or '/./' in path:
        return None
    url = '%s://%s%s%s' % (scheme, host, ':%d' % number if number else '', path)
    return {'url': url, 'scheme': scheme, 'host': host, 'port': number, 'tls': scheme == 'https'}


def general(root):
    """The plugin's own settings: {'read', 'enabled', 'interfaces', 'http_port', 'https_port'}. With
    no plugin settings in config.xml yet: off, every address, ports 80 and 443."""
    node = root.find('OPNsense/ModSecurity/general') if root is not None else None
    return {
        'read': root is not None,
        'enabled': text(node, 'enabled', '0') == '1',
        'interfaces': [k for k in (x.strip() for x in text(node, 'interfaces').split(',')) if k],
        'http_port': port(node, 'http_port', HTTP_PORT),
        'https_port': port(node, 'https_port', HTTPS_PORT),
    }


def sites(root):
    """Each site of the Sites tab in config.xml's order, as it is written there: {'uuid', 'enabled',
    'description', 'names', 'backend' (the text), 'certificate', 'mode', 'paranoia', 'verify'}. A mode
    or a paranoia level the model does not have is taken as its first one: detection only, level 1."""
    out = []
    parent = root.find('OPNsense/ModSecurity/sites') if root is not None else None
    for node in (parent.findall('site') if parent is not None else []):
        mode = text(node, 'mode', 'detection')
        level = text(node, 'paranoia', '1')
        out.append({
            'uuid': node.get('uuid', ''),
            'enabled': text(node, 'enabled', '1') == '1',
            'description': text(node, 'description'),
            'names': names(text(node, 'hostnames')),
            'backend': text(node, 'backend'),
            'certificate': text(node, 'certificate'),
            'mode': mode if mode in MODES else 'detection',
            'paranoia': int(level) if level in ('1', '2', '3', '4') else 1,
            'verify': text(node, 'verify', '1') != '0',
        })
    return out


def assigned(root):
    """The interfaces OPNsense has assigned, by key: {'descr', 'device', 'enabled'} - os-xgs-npu's own
    links left out."""
    out = {}
    parent = root.find('interfaces') if root is not None else None
    for node in (list(parent) if parent is not None else []):
        device = text(node, 'if')
        if INTERNAL.match(device):
            continue
        enable = node.find('enable')
        out[node.tag] = {'descr': text(node, 'descr') or node.tag.upper(), 'device': device,
                         'enabled': enable is not None and (enable.text or '').strip() != '0'}
    return out


def webgui(root):
    """Where the web GUI listens, as plugins.inc.d/webgui.inc binds it: its port - 443 for HTTPS, 80 for
    HTTP where none is set - and 80 for its redirect to HTTPS unless that is turned off; on every address,
    or on its Listen interfaces' addresses and the loopback's. {'ports', 'interfaces', 'protocol'}."""
    node = root.find('system/webgui') if root is not None else None
    protocol = text(node, 'protocol', 'https') or 'https'
    given = text(node, 'port')
    ports = set()
    if re.fullmatch(r'[0-9]{1,5}', given) and 1 <= int(given) <= 65535:
        ports.add(int(given))
    else:
        ports.add(443 if protocol == 'https' else 80)
    if protocol == 'https' and (node is None or node.find('disablehttpredirect') is None):
        ports.add(80)
    listen = [k for k in (x.strip() for x in text(node, 'interfaces').split(',')) if k]
    return {'ports': sorted(ports), 'interfaces': listen, 'protocol': protocol}


def gui_conflicts(gui, ports, interfaces):
    """The ports the web GUI holds where the plugin would listen (settled point 8a: refused, never
    moved): [{'port', 'interfaces'}], 'interfaces' the GUI's Listen interfaces, [] for every address.
    A GUI on every address holds its port everywhere; one bound to its Listen interfaces holds it there
    and on the loopback, which the plugin listening on every address takes too."""
    out = []
    for number in sorted({p for p in ports if p}):
        if number not in gui['ports']:
            continue
        if not gui['interfaces'] or not interfaces or set(gui['interfaces']) & set(interfaces):
            out.append({'port': number, 'interfaces': list(gui['interfaces'])})
    return out


def certificate(root, refid):
    """A certificate of System: Trust by its refid, as Apache is given it: {'crt': the certificate and
    the chain of its authorities, PEM; 'key': its private key, PEM; 'descr'} - or None when there is
    no such certificate or it has no private key."""
    import base64
    if root is None or not REFID.match(refid or ''):
        return None
    for node in root.findall('cert'):
        if text(node, 'refid') != refid:
            continue
        try:
            crt = base64.b64decode(text(node, 'crt'), validate=False).decode('ascii')
            key = base64.b64decode(text(node, 'prv'), validate=False).decode('ascii')
        except (ValueError, UnicodeDecodeError):
            return None
        if 'BEGIN CERTIFICATE' not in crt or 'PRIVATE KEY' not in key:
            return None
        chain, seen, caref = [], set(), text(node, 'caref')
        while caref and caref not in seen:
            seen.add(caref)
            ca = next((c for c in root.findall('ca') if text(c, 'refid') == caref), None)
            if ca is None:
                break
            try:
                pem = base64.b64decode(text(ca, 'crt'), validate=False).decode('ascii')
            except (ValueError, UnicodeDecodeError):
                break
            if 'BEGIN CERTIFICATE' in pem:
                chain.append(pem)
            caref = text(ca, 'caref')
        clean = [clean_pem(p) for p in [crt] + chain]
        return {'crt': ''.join(clean), 'key': clean_pem(key), 'descr': text(node, 'descr')}
    return None


def clean_pem(pem):
    """A PEM text with one line ending a line and no empty line, as Store::cleanCert() writes it."""
    return ''.join(line + '\n' for line in pem.replace('\r', '').split('\n') if line.strip())


def check_sites(conf, entries, root=None):
    """The sites Apache is given and those it is not: (usable, skipped). Each usable one gains
    'parsed' (its backend) and 'tls' (has a certificate); each skipped one is named with a reason: its
    names (none a host name), duplicate (a name another site has), covered (a name another site's
    wildcard takes), backend, certificate (not in System: Trust, or without its private key), nohttps
    (a certificate, and Settings has no HTTPS port), nohttp (none, and no HTTP port). Disabled sites
    are in neither. Earlier sites keep their names: the one that comes later is left out."""
    usable, skipped, taken = [], [], {}

    def skip(site, reason, detail=''):
        skipped.append({'uuid': site['uuid'], 'description': site['description'], 'names': site['names'],
                        'reason': reason, 'detail': detail})

    for site in entries:
        if not site['enabled']:
            continue
        good = [n for n in site['names'] if name_ok(n)]
        if not good or len(good) != len(site['names']) or len(good) > NAMES_MAX or not UUID.match(site['uuid']):
            skip(site, 'names', ', '.join(n for n in site['names'] if not name_ok(n)))
            continue
        clash = next(((n, taken[n]) for n in good if n in taken), None)
        if clash:
            skip(site, 'duplicate', clash[0])
            continue
        over = next((n for n in good for w in taken if covers(w, n) or covers(n, w)), None)
        if over:
            skip(site, 'covered', over)
            continue
        parsed = backend(site['backend'])
        if parsed is None:
            skip(site, 'backend', site['backend'])
            continue
        tls = bool(site['certificate'])
        if tls and certificate(root, site['certificate']) is None:
            skip(site, 'certificate', site['certificate'])
            continue
        if tls and not conf['https_port']:
            skip(site, 'nohttps')
            continue
        if not tls and not conf['http_port']:
            skip(site, 'nohttp')
            continue
        for n in good:
            taken[n] = site['uuid']
        usable.append(dict(site, names=good, parsed=parsed, tls=tls))
    return usable, skipped


def server_name_rx(entries):
    """A PCRE that matches exactly the host names given, as Apache matches a ServerName or ServerAlias:
    case aside, each name whole, * of a wildcard any run of characters."""
    parts = []
    for name in entries:
        if name.startswith('*.'):
            parts.append('.+' + re.escape(name[1:]).replace('\\-', '-'))
        else:
            parts.append(re.escape(name).replace('\\-', '-'))
    return '^(?:%s)$' % '|'.join(parts)


def xgs():
    """Whether os-xgs-npu is installed: then this is an XGS appliance, and the page says where the
    sites' traffic is carried."""
    return os.path.isdir(PROJECT)


def write_file(path, data, mode=0o644):
    """A whole file, written beside its place and renamed over it: a reader never sees half of it."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data.encode('utf-8') if isinstance(data, str) else data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path, value, mode=0o640):
    write_file(path, json.dumps(value, sort_keys=True) + '\n', mode)


def read_json(path):
    try:
        with open(path, encoding='utf-8') as handle:
            found = json.load(handle)
        return found if isinstance(found, dict) else {}
    except (OSError, ValueError):
        return {}
