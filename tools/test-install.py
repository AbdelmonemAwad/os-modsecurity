#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The installer, the removal, the package's three scripts, place-menu.sh and the rc script, run in a
temporary root.

As the family's other tests of the kind: the scripts are run with sh from a copy of the repository in
which their absolute paths are moved into the temporary root - /usr/local, /var/db/os-modsecurity,
/var/log/modsecurity, /var/tmp/os-modsecurity, /var/run/modsecurity, PHP's /var/lib/php/tmp and
/var/lib/php/cache, the caches in /tmp, /conf/config.xml, /bin/pkill, /etc/rc.subr - and stand-ins answer
for what only a firewall has: service, configctl, pkill, pkg, httpd and rc.subr, each writing down how it was
called (pkill kills nothing here). What FreeBSD does otherwise is bridged in the copy: BSD's `cp -R dir/`
copies what dir holds, written `dir/.` for GNU's cp; BSD's `mktemp -t prefix` takes a prefix, which a
stand-in gives GNU's mktemp; and install's -o root -g wheel, which a test run by anyone cannot take, is left
out by a stand-in.

What is checked is what the scripts do: Apache and ModSecurity installed where they are not there, and
nothing copied when they cannot be, or with a syntax error - no package installed then either; which files
are laid down with which modes, where the menu goes, the directories the plugin's files go in and who reads
them; the Apply at an install - off by default, so Apache stopped; on, applied again with the code just
copied; configd told, the page as PHP compiled it thrown away and no other page's; Apache started,
reloaded, stopped and asked about by the rc script, a pid file believed only when its process is this
Apache; Apache stopped before the files go, and nothing of the plugin left by the removal and by the
package's - its configuration, the Core Rule Set, the certificates, its logs - but OPNsense's packages it
needs, unless the removal's install.sh installed them and no other package needs them; nothing done by the
old package in an upgrade.

    python3 tools/test-install.py"""
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = ['install/install.sh', 'install/uninstall.sh', 'pkg/post-install.sh', 'pkg/pre-deinstall.sh',
           'pkg/post-deinstall.sh', 'src/opnsense/scripts/modsecurity/place-menu.sh',
           'src/opnsense/scripts/modsecurity/common.py', 'src/etc/rc.d/modsecurity']
LOCAL = '/usr/local'
MENU = '/usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity/Menu/Menu.xml'
XGS = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/Menu/Menu.xml'
HOOK = '/usr/local/etc/inc/plugins.inc.d/modsecurity.inc'
RC = '/usr/local/etc/rc.d/modsecurity'
HTTPD = '/usr/local/sbin/httpd'
CONF = '/usr/local/etc/os-modsecurity/httpd.conf'
ETC = '/usr/local/etc/os-modsecurity'
STATE = '/var/db/os-modsecurity'
LOGS = '/var/log/modsecurity'
WORK = '/var/tmp/os-modsecurity'
SHARE = '/usr/local/share/os-modsecurity'
# rc.subr as far as rc.d/modsecurity asks it
RC_SUBR = ('load_rc_config() { :; }\nwarn() { echo "${name}: WARNING: $*" >&2; }\n'
           'run_rc_command() {\n\tcase "$1" in\n\t*restart) ${stop_cmd}; ${start_cmd} ;;\n\t*start) ${start_cmd} ;;\n'
           '\t*stop) ${stop_cmd} ;;\n\t*status) ${status_cmd} ;;\n\t*reload) ${reload_cmd} ;;\n\tesac\n}\n')
CACHES = ['/var/lib/php/tmp/opnsense_menu_cache.xml', '/var/lib/php/tmp/opnsense_acl_cache.json',
          '/tmp/opnsense_menu_cache.xml', '/tmp/opnsense_acl_cache.json']
COMPILED = ['/var/lib/php/cache/_usr_local_opnsense_mvc_app_views_OPNsense_ModSecurity_index.volt.php',
            '/var/lib/php/cache/_usr_local_opnsense_mvc_app_views_opnsense_modsecurity_credit.volt.php']
OTHER = '/var/lib/php/cache/_usr_local_opnsense_mvc_app_views_OPNsense_XGS_status.volt.php'
COMMIT = '0123456789abcdef0123456789abcdef01234567'
ON = '<opnsense><OPNsense><ModSecurity><general><enabled>1</enabled></general></ModSecurity></OPNsense></opnsense>'
OFF = '<opnsense><system/></opnsense>'

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


PKG_STUB = r'''db=%(db)s
case "$1" in
info) [ "$2" = -e ] && [ -f "$db/$3" ]; exit ;;
install) echo "pkg $*" >> %(log)s
    if [ -f "$db/pkg-fail" ]; then
        echo "pkg: No packages available to install matching '$3' have been found in the repositories"; exit 1
    fi
    shift 2
    for n in "$@"; do : > "$db/$n"; done
    mkdir -p "$(dirname %(httpd)s)" "$(dirname %(mod)s)"
    printf '#!/bin/sh\necho "httpd $*" >> %(log)s\n' > %(httpd)s; chmod 755 %(httpd)s; : > %(mod)s ;;
query) [ -f "$db/pkg-query-fail" ] && exit 3; cat "$db/$3.rdeps" 2> /dev/null; exit 0 ;;
delete) echo "pkg $*" >> %(log)s; rm -f "$db/$3" ;;
esac'''


class Box:
    """A temporary root, a copy of the repository whose scripts work in it, and the stand-ins."""

    def __init__(self, tmp):
        self.fake = os.path.join(tmp, 'root')
        self.repo = os.path.join(tmp, 'repo')
        self.bin = os.path.join(tmp, 'bin')
        self.calls = os.path.join(tmp, 'calls')
        os.makedirs(self.fake)
        os.makedirs(self.bin)
        shutil.copytree(ROOT, self.repo, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # every file as a checkout has it, not runnable: the scripts set what must be
        for base, _, files in os.walk(self.repo):
            for name in files:
                os.chmod(os.path.join(base, name), 0o644)
        for script in SCRIPTS:
            path = os.path.join(self.repo, script)
            text = open(path, encoding='utf-8').read()
            # a path where one starts, not one inside another (/var/lib/php/tmp/ holds /tmp/ too)
            text = re.sub(r'(?<![\w/.-])(/usr/local/|/var/lib/php/tmp/|/var/lib/php/cache|/tmp/opnsense_|'
                          r'/var/db/os-modsecurity|/var/log/modsecurity|/var/tmp/os-modsecurity|/var/run/modsecurity|'
                          r'/conf/config\.xml|/bin/pkill|/etc/rc\.subr)',
                          lambda m: self.fake + m.group(1), text)
            text = text.replace('cp -R "${HERE}/src/" ', 'cp -R "${HERE}/src/." ')
            with open(path, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(text)
        hook = self.fake + HOOK
        log = self.calls
        self.stub('configctl', 'echo "configctl $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\necho OK' % (hook, log))
        self.stub('service', 'echo "service $*" >> %s' % log)
        self.stub('mktemp', 'if [ "$1" = -d ] && [ "$2" = -t ]; then exec /usr/bin/env mktemp -d '
                            '"${TMPDIR:-/tmp}/$3.XXXXXX"; fi\nexec /usr/bin/env mktemp "$@"', real='mktemp')
        self.stub('install', 'a=""\nwhile [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) a="$a \'$1\'"; shift ;; '
                             'esac; done\neval exec /usr/bin/env install $a', real='install')
        # pkg: the packages are files in pkgdb; install lays Apache down, or fails while pkg-fail is there;
        # query answers from NAME.rdeps, or fails while pkg-query-fail is there
        self.pkgdb = os.path.join(tmp, 'pkgdb')
        os.makedirs(self.pkgdb)
        self.stub('pkg', PKG_STUB % {'db': self.pkgdb, 'log': log, 'httpd': self.fake + HTTPD,
                                     'mod': self.fake + '/usr/local/lib/mod_security2.so'})
        os.makedirs(self.fake + '/bin')
        self.write(self.fake + '/bin/pkill', '#!/bin/sh\necho "pkill $*" >> %s\nexit 1\n' % log, 0o755)
        self.write(self.fake + '/etc/rc.subr', RC_SUBR)
        os.makedirs(self.fake + '/conf')
        os.makedirs(self.fake + '/var/run')
        self.config(OFF)

    def apache(self, there=True):
        """apache24 and ap24-mod_security as the installer looks for them, installed by their owner (in pkg's
        database too); httpd writing down how it was called."""
        for path in (HTTPD, '/usr/local/lib/mod_security2.so'):
            if os.path.exists(self.fake + path):
                os.remove(self.fake + path)
        for name in ('apache24', 'ap24-mod_security'):
            self.pkg(name, there)
        if there:
            self.write(self.fake + HTTPD, '#!/bin/sh\necho "httpd $*" >> %s\n' % self.calls, 0o755)
            self.write(self.fake + '/usr/local/lib/mod_security2.so', '')

    def pkg(self, name, there=True):
        """A package in pkg's stand-in database, or one of its flags: pkg-fail, pkg-query-fail, NAME.rdeps."""
        path = os.path.join(self.pkgdb, name)
        if there:
            self.write(path, there if isinstance(there, str) else '')
        elif os.path.exists(path):
            os.remove(path)

    def config(self, text):
        self.write(self.fake + '/conf/config.xml', text)

    def stub(self, name, body, real=None):
        path = os.path.join(self.bin, name)
        if real:
            # the stand-in must not find itself: the real one is looked for past this directory
            body = body.replace('/usr/bin/env %s' % real, shutil.which(real, path=os.defpath) or '/usr/bin/' + real)
        self.write(path, '#!/bin/sh\n' + body + '\n', 0o755)

    @staticmethod
    def write(path, text, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
        os.chmod(path, mode)

    def run(self, script, *args, env=None):
        return self.sh(os.path.join(self.repo, script), *args, env=env)

    def sh(self, path, *args, env=None):
        environ = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''),
                       TMPDIR=os.path.dirname(self.fake), PYTHONDONTWRITEBYTECODE='1')
        environ.update(env or {})
        done = subprocess.run(['sh', path] + list(args), env=environ, capture_output=True, text=True, timeout=300)
        return done.returncode, done.stdout + done.stderr

    def called(self, prefix=''):
        try:
            return [c for c in open(self.calls, encoding='utf-8').read().splitlines() if c.startswith(prefix)]
        except OSError:
            return []

    def forget(self):
        if os.path.exists(self.calls):
            os.remove(self.calls)

    def plugin_files(self):
        """Every file and directory under the root that the plugin has a hand in."""
        out = []
        for base, dirs, files in os.walk(self.fake):
            for name in files + dirs:
                path = os.path.join(base, name)[len(self.fake):]
                if 'modsecurity' in path.lower():
                    out.append(path)
        return sorted(out)

    def mode(self, path):
        return stat.S_IMODE(os.stat(self.fake + path).st_mode)

    def read(self, path):
        try:
            return open(self.fake + path, encoding='utf-8').read()
        except OSError:
            return None

    def there(self, paths):
        return [p for p in paths if os.path.exists(self.fake + p)]

    def python3(self):
        """/usr/local/bin/python3 of the root: the test's own python3."""
        self.write(self.fake + '/usr/local/bin/python3', '#!/bin/sh\nexec %s "$@"\n' % sys.executable, 0o755)


def source_files():
    out = []
    for base, _, files in os.walk(os.path.join(ROOT, 'src')):
        for name in files:
            if name.endswith('.pyc') or '__pycache__' in base:
                continue
            out.append(LOCAL + os.path.join(base, name)[len(os.path.join(ROOT, 'src')):].replace(os.sep, '/'))
    return sorted(out)


def apache_process(box):
    """A process ps shows as this plugin's Apache: httpd -f its configuration."""
    process = subprocess.Popen(['%s -f %s -k start' % (box.fake + HTTPD, box.fake + CONF), '60'],
                               executable=shutil.which('sleep'))
    threading.Thread(target=process.wait, daemon=True).start()
    box.write(box.fake + '/var/run/modsecurity.pid', '%d\n' % process.pid)
    return process


with tempfile.TemporaryDirectory() as tmp:
    box = Box(tmp)
    menu_own = open(os.path.join(ROOT, 'src/opnsense/scripts/modsecurity/menu/own.xml'), encoding='utf-8').read()
    menu_xgs = open(os.path.join(ROOT, 'src/opnsense/scripts/modsecurity/menu/xgs.xml'), encoding='utf-8').read()
    place = 'src/opnsense/scripts/modsecurity/place-menu.sh'

    # place-menu.sh: XGS where os-xgs-npu's menu is, Services where it is not
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    rc, out = box.run(place)
    check('place-menu.sh without os-xgs-npu: own, the Services menu file', (rc, out.strip(), box.read(MENU),
          '<Services>' in menu_own and 'VisibleName="Web Application Firewall"' in menu_own), (0, 'own', menu_own, True))
    check('place-menu.sh: the menu caches cleared', box.there(CACHES[::2]), [])
    box.write(box.fake + XGS, '<menu/>')
    rc, out = box.run(place)
    check('place-menu.sh with os-xgs-npu: xgs, the XGS menu file, order 67', (rc, out.strip(), box.read(MENU),
          'order="67"' in menu_xgs), (0, 'xgs', menu_xgs, True))
    os.remove(box.fake + XGS)
    shutil.rmtree(box.fake + LOCAL)

    # install.sh: no Apache and ModSecurity, and a repository the firewall cannot reach: said, nothing copied
    box.forget()
    box.pkg('pkg-fail')
    rc, out = box.run('install/install.sh')
    check('install.sh without apache24 and ap24-mod_security, the repository out of reach: stopped, said, pkg asked once, '
          'nothing of the plugin', (rc, out.strip().splitlines()[-1], box.plugin_files(), box.called()),
          (1, 'Once the firewall reaches it (System: Firmware), install the plugin again.', [],
           ['pkg install -y apache24 ap24-mod_security']))
    box.pkg('pkg-fail', False)

    # install.sh: the packages registered, their files missing: said, nothing asked of pkg, nothing copied
    box.pkg('apache24')
    box.pkg('ap24-mod_security')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh, the packages registered but their files missing: stopped, reinstall said, nothing of the plugin',
          (rc, out.strip().splitlines()[-1], box.plugin_files(), box.called()),
          (1, 'Reinstall them in System: Firmware: Packages, then install the plugin again.', [], []))
    box.apache(False)

    # install.sh: nothing copied, and no package installed, when a file of the tree has a syntax error
    for broken, bad in (('src/opnsense/mvc/app/library/OPNsense/ModSecurity/Site.php',
                         lambda t: t.replace('class Site', 'class Site {', 1)),
                        ('src/opnsense/scripts/modsecurity/crs.py', lambda t: t + '\ndef broken(:\n')):
        path = os.path.join(box.repo, broken)
        kept = open(path, encoding='utf-8').read()
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(bad(kept))
        box.forget()
        rc, out = box.run('install/install.sh')
        check('install.sh, %s with a syntax error, no Apache: stopped, nothing copied, nothing asked, no package '
              'installed' % os.path.basename(broken), (rc != 0, box.plugin_files(), box.called()), (True, [], []))
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(kept)
    box.apache()

    # install.sh, a fresh install: off by default
    for path in CACHES + COMPILED + [OTHER]:
        box.write(box.fake + path, 'cached')
    box.write(os.path.join(box.repo, '.source-commit'), COMMIT + ' 2026-11-20T00:00:00+00:00\n')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh: done, where the page is, and that it is off', (rc, out.strip().splitlines()[-1:]),
          (0, ['Web Application Firewall installed: Services > Web Application Firewall (off until it is turned on in Settings)']))
    laid = [f for f in box.plugin_files() if f.startswith(LOCAL) and not f.startswith((SHARE, ETC)) and f != MENU
            and os.path.isfile(box.fake + f)]
    check('install.sh: every file of src/ laid down, and nothing else', laid, source_files())
    check('install.sh: the menu file placed, the caches cleared', (box.read(MENU), box.there(CACHES)), (menu_own, []))
    check('install.sh: the page as PHP compiled it thrown away, no other page\'s', box.there(COMPILED + [OTHER]), [OTHER])
    check('install.sh, off: configd restarted, then Apache stopped, the hook there',
          box.called('service') + box.called('configctl'), ['service configd restart', 'configctl modsecurity stop hook=yes'])
    scripts = '/usr/local/opnsense/scripts/modsecurity/'
    check('install.sh: the modes', [box.mode(p) for p in (
        scripts + 'common.py', scripts + 'setup.py', scripts + 'crs.py', scripts + 'status.py', scripts + 'self-update.py',
        scripts + 'place-menu.sh', RC, scripts + 'listen.php', HOOK, '/usr/local/etc/cron.d/modsecurity',
        '/usr/local/opnsense/service/conf/actions.d/actions_modsecurity.conf', scripts + 'i18n/ui/source.json',
        scripts + 'menu/own.xml', '/usr/local/opnsense/service/templates/OPNsense/ModSecurity/httpd.conf',
        scripts + 'release-keys/xgs-release-key-13ed7f86.pub')],
        [0o755] * 7 + [0o644] * 8)
    check('install.sh: the directories - Apache\'s configuration and the Core Rule Set, the certificates root\'s alone, '
          'what the plugin did and its logs root\'s', [box.mode(p) for p in (ETC, ETC + '/crs', ETC + '/certs', STATE, LOGS)],
          [0o755, 0o755, 0o700, 0o750, 0o750])
    check('install.sh: the commit recorded for the self-update',
          '"commit": "%s"' % COMMIT in (box.read(SHARE + '/installed.json') or ''), True)

    # install.sh again: on, os-xgs-npu there
    box.config(ON)
    box.write(box.fake + XGS, '<menu/>')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh, on: XGS > Web Application Firewall, applied', (rc, out.strip().splitlines()[-1:], box.read(MENU)),
          (0, ['Web Application Firewall installed: XGS > Web Application Firewall (on: Apply ran)'], menu_xgs))
    check('install.sh, on: an Apply, so Apache runs the configuration the code just copied writes', box.called('configctl'),
          ['configctl modsecurity apply hook=yes'])

    # the rc script, as installed
    run_dir = box.fake + '/var/run'
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onestart')
    check('rc.d/modsecurity onestart, no configuration yet: refused, Apply named', (rc, box.called(), 'Apply' in out),
          (1, [], True))
    box.write(box.fake + CONF, '# written by Apply\n')
    rc, out = box.sh(box.fake + RC, 'onestart')
    check('rc.d/modsecurity onestart: httpd with the plugin\'s own configuration, its runtime directory made',
          (rc, box.called(), box.mode('/var/run/modsecurity')), (0, ['httpd -f %s -k start' % (box.fake + CONF)], 0o755))
    rc, out = box.sh(box.fake + RC, 'onestop')
    check('rc.d/modsecurity onestop, nothing running: said', (rc, out.strip()), (0, 'modsecurity is not running.'))
    apache = apache_process(box)
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onestart')
    check('rc.d/modsecurity onestart, Apache running: said, and no second one started', (rc, out.strip(), box.called()),
          (0, 'modsecurity is already running as pid %d.' % apache.pid, []))
    rc, out = box.sh(box.fake + RC, 'onestatus')
    check('rc.d/modsecurity onestatus, running: said with its pid', (rc, out.strip()),
          (0, 'modsecurity is running as pid %d.' % apache.pid))
    rc, out = box.sh(box.fake + RC, 'onereload')
    try:
        ended = apache.wait(timeout=10)
    except subprocess.TimeoutExpired:
        apache.kill()
        ended = None
    check('rc.d/modsecurity onereload, Apache running: a graceful restart, USR1 to its parent, nothing started',
          (rc, out.strip(), ended, box.called()), (0, 'Reloading modsecurity.', -signal.SIGUSR1, []))
    apache = apache_process(box)
    rc, out = box.sh(box.fake + RC, 'onestop')
    check('rc.d/modsecurity onestop, Apache running: stopped, its pid file taken away',
          (rc, out.strip(), apache.poll() is not None or apache.wait(timeout=5) is not None,
           os.path.exists(run_dir + '/modsecurity.pid')), (0, 'Stopping modsecurity.', True, False))
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onereload')
    check('rc.d/modsecurity onereload, nothing running: started', (rc, box.called()),
          (0, ['httpd -f %s -k start' % (box.fake + CONF)]))
    other = subprocess.Popen(['/usr/local/sbin/httpd -f /usr/local/etc/apache24/httpd.conf', '60'], executable=shutil.which('sleep'))
    threading.Thread(target=other.wait, daemon=True).start()
    box.write(run_dir + '/modsecurity.pid', str(other.pid))
    rc, out = box.sh(box.fake + RC, 'onestatus')
    rc2, out2 = box.sh(box.fake + RC, 'onestop')
    check('a pid file naming another Apache - the package\'s own - is not believed, and it is never signalled',
          (rc, out.strip(), out2.strip(), other.poll()), (1, 'modsecurity is not running.', 'modsecurity is not running.', None))
    other.kill()
    box.write(run_dir + '/modsecurity.pid', '1')
    rc, out = box.sh(box.fake + RC, 'onestatus')
    check('a pid file naming a process that is not an Apache is not believed', (rc, out.strip()), (1, 'modsecurity is not running.'))
    texts = [open(os.path.join(ROOT, f), encoding='utf-8').read() for f in (
        'src/etc/rc.d/modsecurity', 'src/etc/inc/plugins.inc.d/modsecurity.inc', 'src/opnsense/scripts/modsecurity/common.py')]
    check('the pid file one name in the rc script, the service list and the scripts',
          [('/var/run/modsecurity.pid' in t) for t in texts], [True, True, True])

    # uninstall.sh: Apache stopped first, then the files and everything the plugin wrote
    os.remove(box.fake + XGS)
    box.write(box.fake + RC, '#!/bin/sh\necho "rc.d modsecurity $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\n'
              % (box.fake + HOOK, box.calls), 0o755)
    for path in COMPILED + [OTHER]:
        box.write(box.fake + path, 'cached')
    for path in (ETC + '/crs/4.25.2/rules/REQUEST-901-INITIALIZATION.conf', ETC + '/certs/x.key', STATE + '/apply.json',
                 LOGS + '/audit_20261120.log', WORK + '/tmp/x', '/var/run/modsecurity/ssl_scache'):
        box.write(box.fake + path, 'x')
    os.symlink('4.25.2', box.fake + ETC + '/crs/current')
    box.write(run_dir + '/modsecurity.pid', '12345')
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/modsecurity/__pycache__', exist_ok=True)
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    calls = box.called()
    check('uninstall.sh: Apache stopped first, while the hook is there, then one the rc script did not find',
          calls[:2], ['rc.d modsecurity onestop hook=yes', 'pkill -f httpd -f %s/usr/local/etc/[o]s-modsecurity/' % box.fake])
    check('uninstall.sh: nothing of the plugin left - files, menu, configuration, Core Rule Set, certificates, logs, state, '
          'pid file, compiled page', box.plugin_files(), [])
    check('uninstall.sh: OPNsense\'s packages left, and another page as PHP compiled it', box.there([HTTPD, OTHER]), [HTTPD, OTHER])
    check('uninstall.sh: then configd, without the hook', calls[2:], ['service configd restart'])
    check('uninstall.sh: said - the packages their owner installed kept', (rc, out.strip().splitlines()[-1]),
          (0, 'Web Application Firewall removed; its settings stay in config.xml, and these packages stay installed: '
              'ap24-mod_security apache24'))
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh again, nothing there: ends 0', rc, 0)

    # the packages installed by install.sh where they were not there, as XGS: Updates' Plugins tab runs it
    mark = SHARE + '/packages-installed'
    box.apache(False)
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh without Apache: both packages installed, recorded, then the plugin',
          (rc, box.called('pkg'), box.read(mark), out.strip().splitlines()[-1].startswith('Web Application Firewall installed')),
          (0, ['pkg install -y apache24 ap24-mod_security'], 'apache24 ap24-mod_security\n', True))
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh again over it: no package installed again, the record kept', (rc, box.called('pkg'), box.read(mark)),
          (0, [], 'apache24 ap24-mod_security\n'))
    # one of them taken away by hand, then installed again: added to the record, apache24 still in it
    box.pkg('ap24-mod_security', False)
    os.remove(box.fake + '/usr/local/lib/mod_security2.so')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh, ap24-mod_security gone: it alone installed, the record keeps apache24',
          (rc, box.called('pkg'), (box.read(mark) or '').split()[:2]),
          (0, ['pkg install -y ap24-mod_security'], ['apache24', 'ap24-mod_security']))
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh: the two packages it installed removed, the module before Apache, then said',
          (rc, box.called('pkg'), sorted(os.listdir(box.pkgdb)), out.strip().splitlines()[-1]),
          (0, ['pkg delete -y ap24-mod_security', 'pkg delete -y apache24'], [],
           'Web Application Firewall removed; its settings stay in config.xml'))
    # another package needs apache24: kept; a query pkg cannot answer: both kept; one already gone: passed over
    for case, setup, deleted, said in (
            ('another package needs apache24', lambda: box.pkg('apache24.rdeps', 'php-apache24\n'),
             ['pkg delete -y ap24-mod_security'], ', and these packages stay installed: apache24'),
            ('pkg query fails', lambda: box.pkg('pkg-query-fail'),
             [], ', and these packages stay installed: ap24-mod_security apache24'),
            ('ap24-mod_security already gone', lambda: box.pkg('ap24-mod_security', False),
             ['pkg delete -y apache24'], '')):
        box.apache(False)
        rc, out = box.run('install/install.sh')
        setup()
        box.forget()
        rc2, out = box.run('install/uninstall.sh')
        check('uninstall.sh, %s: what it removed, and said' % case, (rc, rc2, box.called('pkg'), out.strip().splitlines()[-1]),
              (0, 0, deleted, 'Web Application Firewall removed; its settings stay in config.xml' + said))
        for flag in ('apache24.rdeps', 'pkg-query-fail'):
            box.pkg(flag, False)
    box.apache()

    # the package: pkg lays down the files of src/; post-install does the Apply; the old package's scripts do nothing
    # in an upgrade; a removal: Apache stopped, then post-deinstall leaves nothing of the plugin
    shutil.copytree(os.path.join(box.repo, 'src'), box.fake + LOCAL, dirs_exist_ok=True)
    for path in source_files():
        os.chmod(box.fake + path, 0o755 if open(box.fake + path, 'rb').read(2) == b'#!' else 0o644)
    box.write(box.fake + '/usr/local/sbin/configctl', '#!/bin/sh\nexec configctl "$@"\n', 0o755)
    box.write(box.fake + '/usr/local/etc/rc.d/configd', '#!/bin/sh\nservice configd "$@"\n', 0o755)
    box.python3()
    box.config(OFF)
    for path in COMPILED:
        box.write(box.fake + path, 'cached')
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh: the menu placed, said, off', (rc, box.read(MENU) == menu_own, out.strip().splitlines()[-1]),
          (0, True, 'Web Application Firewall installed: the page is at Services > Web Application Firewall (off until it is '
                    'turned on in Settings)'))
    check('post-install.sh, off: configd, then Apache stopped; the compiled page thrown away; the directories',
          (box.called('service') + box.called('configctl'), box.there(COMPILED), [box.mode(p) for p in (ETC + '/certs', STATE, LOGS)]),
          (['service configd restart', 'configctl modsecurity stop hook=yes'], [], [0o700, 0o750, 0o750]))
    box.config(ON)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh, on (an upgrade): applied again with the new code', box.called('configctl'),
          ['configctl modsecurity apply hook=yes'])
    box.write(box.fake + RC, '#!/bin/sh\necho "rc.d modsecurity $*" >> %s\n' % box.calls, 0o755)
    box.forget()
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': 'true'})
    check('pre-deinstall.sh in an upgrade: nothing done', (rc, box.called()), (0, []))
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': ''})
    check('pre-deinstall.sh in a removal: Apache stopped, and one the rc script did not find',
          box.called(), ['rc.d modsecurity onestop', 'pkill -f httpd -f %s/usr/local/etc/[o]s-modsecurity/' % box.fake])
    box.write(box.fake + STATE + '/apply.json', '{}')
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh', env={'PKG_UPGRADE': 'true'})
    check('post-deinstall.sh in an upgrade: nothing done', (rc, box.called(), box.there([MENU, STATE + '/apply.json'])),
          (0, [], [MENU, STATE + '/apply.json']))
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/modsecurity/__pycache__', exist_ok=True)
    box.write(box.fake + '/usr/local/opnsense/scripts/modsecurity/__pycache__/common.cpython-313.pyc', 'x')
    for path in (SHARE + '/update.json', ETC + '/httpd.conf', ETC + '/crs/installed.json', ETC + '/certs/x.crt',
                 LOGS + '/error_20261120.log', WORK + '/data/x', '/var/run/modsecurity.pid'):
        box.write(box.fake + path, 'x')
    for path in COMPILED:
        box.write(box.fake + path, 'cached')
    for path in source_files():
        os.remove(box.fake + path)
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh', env={'PKG_UPGRADE': ''})
    check('post-deinstall.sh: nothing of the plugin left - the menu file, Python\'s caches, the configuration, the Core Rule '
          'Set, the certificates, the logs, the state, the pid file, the compiled page, the directories', box.plugin_files(),
          [])
    check('post-deinstall.sh: configd told, said', (box.called(), out.strip().splitlines()[-1]),
          (['service configd restart'], 'Web Application Firewall removed; its settings stay in config.xml, and apache24 and '
                                        'ap24-mod_security stay installed'))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
