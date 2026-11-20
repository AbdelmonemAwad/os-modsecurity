#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The Web Application Firewall's Apply: its own Apache, given the sites of its Sites tab.

    setup.py apply     the page's Apply, and the boot's: off - Apache stopped; on - the configuration
                       written from config.xml, tested by Apache, and Apache started or reloaded with
                       it; a JSON answer, kept in /var/db/os-modsecurity/apply.json for the page
    setup.py render    the configuration Apply would write, printed; nothing written, nothing run
    setup.py prune     the log files older than OPNsense keeps its own logs (System: Settings: Logging,
                       31 days by default) taken away - each day by cron, and at each Apply
    setup.py enabled   {"enabled": ..., "read": ...} - for the installer and the package's scripts

What Apply writes, in /usr/local/etc/os-modsecurity: httpd.conf and modsecurity.conf, rendered from the
plugin's templates (templates/OPNsense/ModSecurity) with Jinja2 as configd renders OPNsense's own, and
each site's certificate of System: Trust with its chain and key (certs/). Apache runs it as its own
instance - its pid file /var/run/modsecurity.pid - never the apache24 package's configuration. Before
Apache reads it, `httpd -t` tests it: what it refuses is put back as it was, and Apache goes on with what
it had. `httpd -t` parses; it does not bind or load a certificate. So the files before - the two and the
certificates - are kept until Apache runs the new ones: a graceful restart Apache does not survive (a port
another program holds) puts them back and starts Apache with them again; a start that fails puts them
back and leaves Apache stopped, as it was. A setting that cannot be served is refused and said, never
changed: the web GUI on a port chosen here (settled point 8a: how to move the GUI is said, and the plugin
never moves it), no Core Rule Set, no address to listen on. A site that fails its checks
(common.check_sites) is left out and named.

Nothing here changes the firewall's rules: a site reached from another network needs a rule there that
passes its port to this firewall, which the owner makes.
"""

import datetime
import fcntl
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = '/usr/local/opnsense/service/templates/OPNsense/ModSecurity'
LISTEN_PHP = os.path.join(HERE, 'listen.php')
PHP = '/usr/local/bin/php'

# Apache's modules this configuration loads, each from its file in libexec/apache24 - by need: TLS only
# where a site has a certificate or an HTTPS backend, the redirect to HTTPS only where a site has one.
# mod_reqtimeout always, as Apache's own httpd.conf loads it: a request's headers and body read within
# bounds, or a client sending a header line a minute keeps a worker as long as it likes.
ALWAYS = (('authz_core_module', 'mod_authz_core.so'), ('unixd_module', 'mod_unixd.so'),
          ('unique_id_module', 'mod_unique_id.so'), ('headers_module', 'mod_headers.so'),
          ('proxy_module', 'mod_proxy.so'), ('proxy_http_module', 'mod_proxy_http.so'),
          ('reqtimeout_module', 'mod_reqtimeout.so'))
TLS = (('socache_shmcb_module', 'mod_socache_shmcb.so'), ('ssl_module', 'mod_ssl.so'))
REDIRECT = (('rewrite_module', 'mod_rewrite.so'),)
# The MPM: event where there is one, as phase 0's lab found it, else worker, else prefork.
MPMS = (('mpm_event_module', 'mod_mpm_event.so', 'event'), ('mpm_worker_module', 'mod_mpm_worker.so', 'worker'),
        ('mpm_prefork_module', 'mod_mpm_prefork.so', 'prefork'))

# The site rules' ids: 19001 for the first site (httpd.conf; 19000 is modsecurity.conf's), 19899 at most.
RULE_BASE = 19000
SITES_MAX = 899

# How long Apache is given to come up after a start, and to finish a graceful restart after a reload. Each
# wait ends as soon as Apache shows it is done - its pid file written after it bound; its MPM's "resuming
# normal operations" in its log after the mark - or that it is not: gone, or a fatal line in its log. The
# Core Rule Set is parsed again at either; how long that takes on the XGS 136 is not measured yet.
START_WAIT = 30.0
RELOAD_WAIT = 30.0
STEP = 0.25
# A start or a graceful restart done: the MPM's notice (httpd.conf's LogLevel asks for the MPM's notices);
# what says why Apache would not run; and what says it is ending now.
RESUMED = re.compile(r'configured -- resuming normal operations')
FATAL = re.compile(r':(emerg|alert|crit|error)\]')
ENDING = re.compile(r':(emerg|alert)\]')
# Old children of a graceful restart Apache did not survive may hold its ports a moment: waited for before
# the configuration before is started again.
GONE_WAIT = 10.0

LOG_DAY = re.compile(r'(audit|error)_([0-9]{8})\.log\Z')
KEEP_DAYS = 31

MESSAGES = {
    'packages': 'apache24 and ap24-mod_security are not installed',
    'norules': 'the Core Rule Set is not installed',
    'gui': 'the web GUI listens on a port chosen here',
    'noaddress': 'the interfaces chosen have no address to listen on now',
    'module': 'Apache has no module the configuration needs',
    'certificate': "a site's certificate is not in System: Trust with its private key",
}


def paths():
    """The files Apply writes, by the module values of common (the tests point them elsewhere)."""
    return {'conf': common.ETC + '/httpd.conf', 'msconf': common.ETC + '/modsecurity.conf',
            'certs': common.ETC + '/certs', 'apply': common.STATE + '/apply.json',
            'lock': common.STATE + '/apply.lock', 'crs': common.CRS + '/current',
            'crs_state': common.CRS + '/installed.json'}


class Refused(Exception):
    """What stops an Apply, by a code the page says in its own language, and the detail after it."""

    def __init__(self, code, detail='', **more):
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.more = more


def render(name, context, templates=None):
    """A template of the plugin, rendered with the context given (Jinja2, as configd renders OPNsense's
    own: blocks trimmed, nothing escaped - every value is checked before it is here)."""
    import jinja2
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(templates or TEMPLATES), trim_blocks=True,
                             lstrip_blocks=True, keep_trailing_newline=True, autoescape=False,
                             undefined=jinja2.StrictUndefined)
    return env.get_template(name).render(**context)


def security2():
    """ModSecurity's module where the package laid it down, or None."""
    return next((path for path in common.SECURITY2 if os.path.isfile(path)), None)


def modules(needed):
    """[{name, path}] of the modules asked for, and the files of those Apache does not have."""
    found, missing = [], []
    for name, filename in needed:
        path = os.path.join(common.MODULES, filename)
        if os.path.isfile(path):
            found.append({'name': name, 'path': path})
        else:
            missing.append(filename)
    return found, missing


def mpm():
    for name, filename, kind in MPMS:
        path = os.path.join(common.MODULES, filename)
        if os.path.isfile(path):
            return {'name': name, 'path': path, 'kind': kind}
    return None


def crs_folder():
    """The Core Rule Set's own directory, crs/<version>, as crs/current points at it: Apache's configuration
    names that, never current, so the configuration before - put back when Apache does not run a new one -
    keeps the rules it ran with, whatever an install made current since (crs.py keeps every version a
    configuration on disk names)."""
    return os.path.realpath(paths()['crs'])


def crs_installed():
    """The Core Rule Set in use - its installed.json, written by crs.py - when its directory is there
    with its setup and its rules; else None."""
    found = common.read_json(paths()['crs_state'])
    folder = paths()['crs']
    if not found.get('version') or not os.path.isfile(os.path.join(folder, 'crs-setup.conf')) or \
            not os.path.isdir(os.path.join(folder, 'rules')):
        return None
    return found


def addresses(conf, run=subprocess.run):
    """Where Apache listens: every address (0.0.0.0 and ::) where no interface is chosen; else each
    chosen interface's addresses as OPNsense's web GUI takes its own (listen.php: interfaces_addresses(),
    an address marked not to be bound left out, and a tentative or link-local IPv6 one). [{'address',
    'family'}]; Refused('noaddress') when the interfaces chosen have none now."""
    if not conf['interfaces']:
        return [{'address': '0.0.0.0', 'family': 4}, {'address': '::', 'family': 6}]
    try:
        done = run([PHP, LISTEN_PHP, ','.join(conf['interfaces'])], capture_output=True, text=True,
                   timeout=30, check=False)
        found = json.loads(done.stdout or '{}')
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise Refused('noaddress', str(error)) from error
    out = []
    for item in found.get('addresses', []) if isinstance(found, dict) else []:
        try:
            ip = ipaddress.ip_address(str(item.get('address', '') if isinstance(item, dict) else ''))
        except ValueError:
            continue
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            continue
        entry = {'address': ip.compressed, 'family': ip.version}
        if entry not in out:
            out.append(entry)
    if not out:
        raise Refused('noaddress', ','.join(conf['interfaces']))
    return out


def listen_lines(found, ports):
    """[{text, proto}] for each port and address: 192.0.2.1:443, [2001:db8::1]:443."""
    out = []
    for number, proto in ports:
        for item in found:
            host = item['address'] if item['family'] == 4 else '[%s]' % item['address']
            out.append({'text': '%s:%d' % (host, number), 'proto': proto})
    return out


def cert_paths(folder, refid):
    return {'crt': os.path.join(folder, refid + '.crt'), 'key': os.path.join(folder, refid + '.key')}


def server_names(site):
    """(ServerName, [ServerAlias]) of a site: Apache takes a wildcard in ServerAlias only, so the
    ServerName is its first name that is none - or, where every name is one, a name of the reserved
    .invalid domain no request asks for - and every other name an alias."""
    exact = [n for n in site['names'] if not n.startswith('*.')]
    first = exact[0] if exact else 'site-%s.invalid' % site['uuid'][:8].lower()
    return first, [n for n in site['names'] if n != first]


def site_context(usable, conf, certs):
    """Each usable site as the template takes it, in the order of the Sites tab."""
    out = []
    for index, site in enumerate(usable, start=1):
        names = site['names']
        servername, aliases = server_names(site)
        cert = certs.get(site['certificate']) if site['tls'] else None
        http = None
        if conf['http_port']:
            http = 'redirect' if site['tls'] else 'serve'
        out.append({
            'uuid': site['uuid'], 'rule': RULE_BASE + index, 'servername': servername, 'aliases': aliases,
            'rx': common.server_name_rx(names), 'engine': common.MODES[site['mode']],
            'paranoia': site['paranoia'], 'http': http, 'https': bool(cert),
            'crt': cert['crt'] if cert else '', 'key': cert['key'] if cert else '',
            'url': site['parsed']['url'], 'tls_backend': site['parsed']['tls'], 'verify': site['verify'],
            'https_suffix': '' if conf['https_port'] == 443 else ':%d' % (conf['https_port'] or 0),
        })
    return out


def plan(root, conf, entries, listen_found=None, run=subprocess.run):
    """Everything Apply needs before it writes: a dict of the facts, or Refused when a setting cannot be
    served. listen_found: the addresses, where the caller has them already."""
    if not os.path.isfile(common.HTTPD) or security2() is None or not os.path.isfile(common.ROTATELOGS):
        raise Refused('packages')
    crs = crs_installed()
    if crs is None:
        raise Refused('norules')
    conflicts = common.gui_conflicts(common.webgui(root), [conf['http_port'], conf['https_port']],
                                     conf['interfaces'])
    if conflicts:
        raise Refused('gui', ','.join(str(c['port']) for c in conflicts), conflicts=conflicts)
    usable, skipped = common.check_sites(conf, entries, root)
    if len(usable) > SITES_MAX:
        skipped.extend({'uuid': s['uuid'], 'description': s['description'], 'names': s['names'],
                        'reason': 'many', 'detail': ''} for s in usable[SITES_MAX:])
        usable = usable[:SITES_MAX]
    if not usable:
        raise Refused('nosite', skipped=skipped)
    tls_front = any(s['tls'] for s in usable)
    tls_back = any(s['parsed']['tls'] for s in usable)
    redirect = tls_front and bool(conf['http_port'])
    http_used = bool(conf['http_port']) and (redirect or any(not s['tls'] for s in usable))
    needed = list(ALWAYS) + (list(TLS) if tls_front or tls_back else []) + (list(REDIRECT) if redirect else [])
    found, missing = modules(needed)
    the_mpm = mpm()
    if missing or the_mpm is None:
        raise Refused('module', ', '.join(missing + ([] if the_mpm else ['an MPM'])))
    ports = ([(conf['http_port'], 'http')] if http_used else []) + \
        ([(conf['https_port'], 'https')] if tls_front else [])
    where = listen_found if listen_found is not None else addresses(conf, run)
    return {'modules': found, 'mpm': the_mpm, 'usable': usable, 'skipped': skipped, 'crs': crs, 'ports': ports,
            'where': where, 'tls_front': tls_front, 'http_used': http_used}


def context(facts, sites):
    """The templates' context."""
    default_cert = None
    if facts['tls_front']:
        first = next(s for s in sites if s['https'])
        default_cert = {'crt': first['crt'], 'key': first['key']}
    ports = facts['ports']
    return {
        'modules': facts['modules'], 'mpm': facts['mpm'], 'security2': security2(),
        'listen': listen_lines(facts['where'], ports),
        'http_port': next((p for p, proto in ports if proto == 'http'), None),
        'https_port': next((p for p, proto in ports if proto == 'https'), None),
        'default_cert': default_cert, 'sites': sites, 'crs': crs_folder(), 'etc': common.ETC,
        'run': common.RUN, 'logs': common.LOGS, 'work': common.WORK, 'pidfile': common.PIDFILE,
        'rotatelogs': common.ROTATELOGS, 'trust': common.TRUST,
    }


def configuration(facts, conf, certs):
    """(the context, {path: text}) of the two files Apply writes."""
    ctx = context(facts, site_context(facts['usable'], conf, certs))
    p = paths()
    return ctx, {p['conf']: render('httpd.conf', ctx), p['msconf']: render('modsecurity.conf', ctx)}


def certificate_files(root, usable, folder):
    """Each certificate a site uses, as Apache is given it: ({refid: {crt, key}}, {path: (text, mode)}) -
    <refid>.crt, it and its chain (0644), and <refid>.key (0600), in a directory only root reads (folders()).
    Refused('certificate') for one System: Trust does not give with its key. Written with the two files
    (put()), and put back with them; what else is there is taken away only once Apache runs the new
    configuration (tidy_certificates): the one it runs may still name it."""
    certs, files = {}, {}
    for site in usable:
        refid = site['certificate']
        if not site['tls'] or refid in certs:
            continue
        found = common.certificate(root, refid)
        if found is None:
            raise Refused('certificate', refid)
        where = cert_paths(folder, refid)
        files[where['crt']] = (found['crt'], 0o644)
        files[where['key']] = (found['key'], 0o600)
        certs[refid] = where
    return certs, files


def tidy_certificates(folder, certs):
    keep = {os.path.basename(p) for item in certs.values() for p in item.values()}
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for name in names:
        if name not in keep:
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass


def httpd_test(conf_path, run=subprocess.run):
    """Apache's own test of a configuration: (passed, what it said)."""
    try:
        done = run([common.HTTPD, '-t', '-f', conf_path], capture_output=True, text=True, timeout=120,
                   check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error)
    said = ' '.join(((done.stderr or '') + ' ' + (done.stdout or '')).split())
    return done.returncode == 0, said[:600]


def ours(pid):
    """Whether pid is the plugin's Apache: alive, and httpd with this configuration."""
    if not pid or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        args = subprocess.run(['ps', '-ww', '-o', 'args=', '-p', str(pid)], capture_output=True, text=True,
                              timeout=10, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return 'httpd' in args and common.ETC + '/httpd.conf' in args


def running_pid():
    """The pid of the plugin's Apache, from its pid file, when it is alive and is that Apache."""
    try:
        with open(common.PIDFILE, encoding='ascii') as handle:
            pid = int(handle.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    return pid if ours(pid) else None


def rc(action, run=subprocess.run):
    """The plugin's rc script, with the "one" prefix: config.xml decides whether Apache runs, not rc.conf."""
    try:
        done = run([common.RC, 'one' + action], capture_output=True, text=True, timeout=60, check=False)
        return done.returncode, ' '.join(((done.stdout or '') + ' ' + (done.stderr or '')).split())[:600]
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)


def error_log(day=None):
    """Apache's error log of a day (rotatelogs -l: local time, as datetime's)."""
    return os.path.join(common.LOGS, 'error_%s.log' % (day or datetime.date.today()).strftime('%Y%m%d'))


def log_mark():
    """Where Apache's error log ends now: what it writes after, log_since() reads."""
    path = error_log()
    try:
        return path, os.path.getsize(path)
    except OSError:
        return path, 0


def log_since(mark, limit=1 << 16):
    """What Apache's error log gained since the mark - across midnight too, when the day's file changed."""
    path, size = mark
    parts = [(path, size)] + ([(error_log(), 0)] if error_log() != path else [])
    out = ''
    for name, start in parts:
        try:
            with open(name, 'rb') as handle:
                handle.seek(start)
                out += handle.read(limit).decode('utf-8', 'replace')
        except OSError:
            pass
    return out


def said_since(mark, limit=3):
    """The lines of Apache's error log since the mark that say why it would not run."""
    lines = [line.strip() for line in log_since(mark).splitlines() if line.strip()]
    return ' '.join([line for line in lines if FATAL.search(line)][-limit:])[:600]


def wait_started(mark, started, sleep=time.sleep):
    """After a start: the pid as soon as Apache is there (it writes its pid file once it has bound); None when
    the start command failed, when Apache's log since the mark says it is ending, or after START_WAIT."""
    waited = 0.0
    while True:
        pid = running_pid()
        if pid:
            return pid
        if not started or waited >= START_WAIT or ENDING.search(log_since(mark)):
            return None
        sleep(STEP)
        waited += STEP


def wait_reloaded(pid, mark, sleep=time.sleep):
    """After a graceful restart of pid: pid as soon as its log since the mark says it runs the configuration
    again ("resuming normal operations"); None as soon as it is gone; at RELOAD_WAIT with neither, pid -
    still there, its restart said done by nothing."""
    waited = 0.0
    while True:
        if not ours(pid):
            return None
        if RESUMED.search(log_since(mark)):
            return pid
        if waited >= RELOAD_WAIT:
            return pid
        sleep(STEP)
        waited += STEP


def wait_gone(run=subprocess.run, sleep=time.sleep):
    """Until no process runs this configuration any more - the children a parent that ended leaves finish
    their requests and go - or GONE_WAIT passed."""
    waited = 0.0
    while waited < GONE_WAIT:
        try:
            left = run(['pgrep', '-f', 'httpd -f ' + common.ETC + '/httpd.conf'], capture_output=True, text=True,
                       timeout=10, check=False).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return
        if not left:
            return
        sleep(STEP)
        waited += STEP


def take(previous, run=subprocess.run, sleep=time.sleep):
    """Apache given the files just written - reloaded where it runs, else started - and the files before
    (previous, from put()) put back where it does not run them: (how it ended, what Apache said).
    'reloaded', 'started'; 'restored': it did not survive the reload, and the files before, put back, run
    again; 'stopped': it did not survive the reload, and the files before did not start either;
    'notstarted': it did not start, the files before are put back and Apache is stopped, as it was - an
    older configuration Apache was not running is never started in its place: it would publish what was
    stopped since, sites taken away or the plugin turned off."""
    pid = running_pid()
    mark = log_mark()
    if pid:
        code, out = rc('reload', run)
        if wait_reloaded(pid, mark, sleep):
            return 'reloaded', ''
        said = said_since(mark) or out
        put_back(previous)
        wait_gone(run, sleep)
        mark = log_mark()
        code, out = rc('start', run)
        if wait_started(mark, code == 0, sleep):
            return 'restored', said
        return 'stopped', '%s; %s' % (said, said_since(mark) or out)
    code, out = rc('start', run)
    if wait_started(mark, code == 0, sleep):
        return 'started', ''
    said = said_since(mark) or out
    rc('stop', run)
    put_back(previous)
    return 'notstarted', said


def put(files):
    """The files written - {path: text} at 0644, or {path: (text, mode)} - and what each was before, to be
    put back: {path: (bytes, mode) or None}. Where one cannot be written, those written are put back first."""
    previous = {}
    try:
        for path, item in files.items():
            data, mode = item if isinstance(item, tuple) else (item, 0o644)
            previous[path] = None
            if os.path.isfile(path):
                with open(path, 'rb') as handle:
                    previous[path] = (handle.read(), stat.S_IMODE(os.stat(path).st_mode))
            common.write_file(path, data, mode)
    except OSError:
        put_back(previous)
        raise
    return previous


def put_back(previous):
    for path, item in previous.items():
        try:
            if item is None:
                if os.path.lexists(path):
                    os.unlink(path)
            else:
                common.write_file(path, item[0], item[1])
        except OSError:
            pass


def folders():
    """Apache's own directories: the certificates' (root's alone), its runtime one (0755: its children open
    its locks there too), the logs' (root's alone) and ModSecurity's work files' (www's: Apache's children
    write them)."""
    for folder, mode in ((common.ETC, 0o755), (paths()['certs'], 0o700), (common.RUN, 0o755), (common.LOGS, 0o750),
                         (common.WORK, 0o750), (common.WORK + '/tmp', 0o750), (common.WORK + '/data', 0o750)):
        os.makedirs(folder, exist_ok=True)
        os.chmod(folder, mode)
    for folder in (common.WORK, common.WORK + '/tmp', common.WORK + '/data'):
        try:
            shutil.chown(folder, 'www', 'www')
        except (LookupError, OSError):
            pass


def keep(result):
    result['at'] = int(time.time())
    try:
        os.makedirs(common.STATE, exist_ok=True)
        common.write_json(paths()['apply'], result)
    except OSError:
        pass
    return result


def apply(config=None, run=subprocess.run, sleep=time.sleep, listen_found=None):
    """The page's Apply, and the boot's: its answer, kept for the page."""
    p = paths()
    os.makedirs(common.STATE, exist_ok=True)
    with open(p['lock'], 'w', encoding='utf-8') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {'status': 'failed', 'code': 'busy', 'detail': '',
                    'message': 'another Apply or a Core Rule Set install is running'}
        return applied(config, run, sleep, listen_found)


def applied(config=None, run=subprocess.run, sleep=time.sleep, listen_found=None):
    """An Apply under the lock its caller holds (apply(), crs.py's install), kept for the page. Where it
    leaves Apache running what it ran, the addresses said are those that run: the last Apply's."""
    before = common.read_json(paths()['apply'])
    result = _apply(config, run, sleep, listen_found)
    if result.get('status') == 'failed' and result.get('state') != 'stopped' and result.get('code') != 'busy':
        result['listen'] = before.get('listen', []) if isinstance(before.get('listen'), list) else []
    return keep(result)


def _apply(config, run, sleep, listen_found):
    p = paths()
    try:
        root = common.read_root(config)
    except (OSError, ValueError) as error:
        return {'status': 'failed', 'code': 'config.xml', 'detail': str(error),
                'message': 'config.xml could not be read; Apache was left as it was'}
    conf = common.general(root)
    prune(root)
    if not conf['enabled']:
        rc('stop', run)
        return {'status': 'ok', 'state': 'off', 'code': '', 'detail': '', 'message': 'off: Apache stopped',
                'sites': 0, 'skipped': [], 'listen': []}
    try:
        facts = plan(root, conf, common.sites(root), listen_found, run)
        certs, cert_files = certificate_files(root, facts['usable'], p['certs'])
        ctx, files = configuration(facts, conf, certs)
    except Refused as refused:
        result = {'status': 'failed', 'code': refused.code, 'detail': refused.detail, 'listen': [],
                  'skipped': refused.more.get('skipped', []), 'sites': 0}
        if refused.more.get('conflicts'):
            result['conflicts'] = refused.more['conflicts']
        if refused.code == 'nosite':
            # nothing to publish: Apache stopped, the settings as they are
            rc('stop', run)
            result.update({'status': 'ok', 'state': 'nosite', 'message': 'no site to publish: Apache stopped'})
            return result
        result['message'] = MESSAGES.get(refused.code, refused.code) + \
            (' (%s)' % refused.detail if refused.detail else '') + '; Apache was left as it was'
        return result
    except OSError as error:
        return {'status': 'failed', 'code': 'write', 'detail': str(error), 'sites': 0, 'skipped': [],
                'message': 'the configuration could not be written (%s); Apache was left as it was' % error}

    try:
        folders()
        previous = put(dict(cert_files, **files))
    except OSError as error:
        return {'status': 'failed', 'code': 'write', 'detail': str(error), 'sites': 0, 'skipped': [],
                'message': 'the configuration could not be written (%s); Apache was left as it was' % error}
    passed, said = httpd_test(p['conf'], run)
    base = {'sites': len(facts['usable']), 'skipped': facts['skipped'], 'crs': facts['crs'].get('version'),
            'listen': [x['text'] for x in ctx['listen']]}
    if not passed:
        put_back(previous)
        return dict(base, status='failed', code='config', detail=said, message='Apache refused the '
                    'configuration (%s); the one before is kept, and Apache was left as it was' % said)
    count = '%d site%s' % (len(facts['usable']), '' if len(facts['usable']) == 1 else 's')
    ended, said = take(previous, run, sleep)
    if ended in ('reloaded', 'started'):
        tidy_certificates(p['certs'], certs)
        return dict(base, status='ok', state='running', code='', detail='',
                    message='Apache %s with %s' % (ended, count))
    if ended == 'restored':
        return dict(base, status='failed', state='running', code='restored', detail=said,
                    message='Apache could not run the new configuration (%s); the one before runs again' % said)
    if ended == 'stopped':
        return dict(base, status='failed', state='stopped', code='start', detail=said, listen=[],
                    message='Apache stopped after the reload, and the configuration before did not start '
                    'again: ' + said)
    return dict(base, status='failed', state='stopped', code='start', detail=said, listen=[],
                message='Apache did not start (%s); the configuration before is kept, and Apache is stopped, '
                'as it was' % said)


def preserve(root):
    """The days OPNsense keeps its own logs (System: Settings: Logging, Preserve logs), 31 by default."""
    value = common.text(root.find('OPNsense/Syslog/general') if root is not None else None, 'maxpreserve')
    return int(value) if re.fullmatch(r'[0-9]{1,4}', value) and int(value) > 0 else KEEP_DAYS


def prune(root=None, today=None):
    """The audit and error logs' day files older than preserve() days taken away: [their names]."""
    days = preserve(root)
    oldest = ((today or datetime.date.today()) - datetime.timedelta(days=days)).strftime('%Y%m%d')
    gone = []
    try:
        names = sorted(os.listdir(common.LOGS))
    except OSError:
        return gone
    for name in names:
        found = LOG_DAY.match(name)
        if found and found.group(2) < oldest:
            try:
                os.unlink(os.path.join(common.LOGS, name))
                gone.append(name)
            except OSError:
                pass
    return gone


def main(argv):
    command = argv[1] if len(argv) > 1 else ''
    if command == 'apply':
        print(json.dumps(apply()))
        return 0
    if command == 'enabled':
        try:
            print(json.dumps({'enabled': common.general(common.read_root())['enabled'], 'read': True}))
        except (OSError, ValueError):
            print(json.dumps({'enabled': False, 'read': False}))
        return 0
    if command == 'render':
        try:
            root = common.read_root()
            conf = common.general(root)
            facts = plan(root, conf, common.sites(root))
            certs = certificate_files(root, facts['usable'], paths()['certs'])[0]
            files = configuration(facts, conf, certs)[1]
        except Refused as refused:
            print(json.dumps({'status': 'failed', 'code': refused.code, 'detail': refused.detail}))
            return 0
        except (OSError, ValueError) as error:
            print(json.dumps({'status': 'failed', 'code': 'config.xml', 'detail': str(error)}))
            return 0
        for path, data in files.items():
            sys.stdout.write('# ---- %s\n%s' % (path, data))
        return 0
    if command == 'prune':
        try:
            root = common.read_root()
        except (OSError, ValueError):
            root = None
        print(json.dumps({'pruned': prune(root)}))
        return 0
    print('usage: setup.py apply | render | prune | enabled', file=sys.stderr)
    return 0


if __name__ == '__main__':
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sys.exit(main(sys.argv))
