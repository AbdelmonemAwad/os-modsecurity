#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""crs.py against releases of the Core Rule Set made here as the owner's signing repository is to publish
them (crs-<version>: the minimal archive, crs.json and its Ed25519 signature), signed with throwaway keys,
in a place named by file:// - nothing here asks GitHub - and GitHub's list of references as a file.

What is checked: the newest release of the 4.25 line among the tags; a manifest taken only when its
signature verifies with a key the firewall holds and every field is a Core Rule Set release of this
repository checked against the pinned key; the archive taken only when it is the one signed; what an archive
may hold (its one top directory, files and directories, enough rule files); the install - unpacked, its
setup copied, Apache's test, crs/current pointed at it, the one before kept and each one a configuration on
disk names, an older one taken away - and
nothing in use changed when any of it fails; an archive given by hand, taken only with its SHA-256; Apply
after an install where the plugin is on; one install or Apply at a time; and what check says.

    python3 tools/test-crs.py"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'src/opnsense/scripts/modsecurity')
sys.path.insert(0, SCRIPTS)
import common  # noqa: E402
import crs  # noqa: E402
import setup  # noqa: E402

OPENSSL = shutil.which('openssl')
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

TOP = tempfile.mkdtemp(prefix='test-crs.')
PLACE = os.path.join(TOP, 'releases')
common.ETC = TOP + '/etc/os-modsecurity'
common.CRS = common.ETC + '/crs'
common.STATE = TOP + '/db/os-modsecurity'
common.SHARE = TOP + '/share/os-modsecurity'
common.HTTPD = TOP + '/sbin/httpd'
common.MODULES = TOP + '/libexec/apache24'
common.SECURITY2 = (TOP + '/libexec/apache24/mod_security2.so',)
common.CONFIG = TOP + '/config.xml'
crs.KEYS = TOP + '/keys'
crs.OPENSSL = OPENSSL
for folder in (crs.KEYS, PLACE, common.SHARE):
    os.makedirs(folder)
with open(os.path.join(common.SHARE, 'crs-from'), 'w') as handle:
    handle.write('file://' + PLACE + '\n')
with open(common.CONFIG, 'w') as handle:
    handle.write('<opnsense><OPNsense><ModSecurity><general><enabled>0</enabled></general></ModSecurity></OPNsense></opnsense>')


def openssl(*args):
    subprocess.run([OPENSSL] + list(args), check=True, capture_output=True)


def make_key(name):
    pem = os.path.join(TOP, name + '.pem')
    openssl('genpkey', '-algorithm', 'ed25519', '-out', pem)
    openssl('pkey', '-in', pem, '-pubout', '-out', os.path.join(TOP, name + '.pub'))
    return pem


def sign(pem, data):
    path = os.path.join(TOP, 'to-sign')
    with open(path, 'wb') as handle:
        handle.write(data)
    openssl('pkeyutl', '-sign', '-inkey', pem, '-rawin', '-in', path, '-out', path + '.sig')
    with open(path + '.sig', 'rb') as handle:
        return handle.read()


def trust(*names):
    shutil.rmtree(crs.KEYS)
    os.makedirs(crs.KEYS)
    for name in names:
        shutil.copy(os.path.join(TOP, name + '.pub'), os.path.join(crs.KEYS, 'xgs-release-key-%s.pub' % name))


def archive(version, top=None, rules=12, extra=None):
    """A minimal archive as the Core Rule Set publishes it: one top directory, its setup's example, its rules."""
    top = top or 'coreruleset-%s' % version
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        def add(name, text, kind=tarfile.REGTYPE, link=''):
            entry = tarfile.TarInfo(name)
            data = text.encode()
            entry.size = len(data) if kind == tarfile.REGTYPE else 0
            entry.type = kind
            entry.linkname = link
            tar.addfile(entry, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        directory = tarfile.TarInfo(top)
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        add(top + '/crs-setup.conf.example', 'SecAction "id:900990,phase:1,pass,nolog,setvar:tx.crs_setup_version=%s"\n'
            % version.replace('.', ''))
        add(top + '/LICENSE', 'Apache License 2.0\n')
        add(top + '/plugins/empty-before.conf', '')
        for i in range(rules):
            add(top + '/rules/REQUEST-9%02d-TEST.conf' % i, '# rule file %d\n' % i)
        for item in extra or []:
            add(*item)
    return buf.getvalue()


def publish(version, key='test', data=None, manifest=None, drop=()):
    """A release crs-<version> in the place: its archive, crs.json and crs.json.sig, signed with key."""
    data = data if data is not None else archive(version)
    folder = os.path.join(PLACE, 'download', 'crs-' + version)
    os.makedirs(folder, exist_ok=True)
    name = 'coreruleset-%s-minimal.tar.gz' % version
    with open(os.path.join(folder, name), 'wb') as handle:
        handle.write(data)
    fields = {'archive': name, 'date': '2026-11-20T10:00:00+00:00', 'format': 1, 'repository': crs.REPO,
              'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'tag': 'crs-' + version,
              'upstream': 'coreruleset/coreruleset v' + version, 'upstream_key': crs.UPSTREAM_KEY, 'version': version}
    fields.update(manifest or {})
    text = json.dumps(fields, sort_keys=True, indent=1).encode()
    files = {'crs.json': text, 'crs.json.sig': sign(os.path.join(TOP, key + '.pem'), text)}
    for file_name, content in files.items():
        if file_name not in drop:
            with open(os.path.join(folder, file_name), 'wb') as handle:
                handle.write(content)
    return data


def unpublish():
    shutil.rmtree(os.path.join(PLACE, 'download'), ignore_errors=True)


def current():
    link = os.path.join(common.CRS, 'current')
    return os.readlink(link) if os.path.islink(link) else None


def versions():
    return sorted(n for n in os.listdir(common.CRS) if os.path.isdir(os.path.join(common.CRS, n)) and
                  not os.path.islink(os.path.join(common.CRS, n))) if os.path.isdir(common.CRS) else []


def fake_httpd(code=0, said='Syntax OK'):
    os.makedirs(os.path.dirname(common.HTTPD), exist_ok=True)
    with open(common.HTTPD, 'w') as handle:
        handle.write('#!/bin/sh\necho "%s" >&2\necho "$@" > "%s/httpd.args"\nexit %d\n' % (said, TOP, code))
    os.chmod(common.HTTPD, 0o755)
    os.makedirs(common.MODULES, exist_ok=True)
    for name in ('mod_mpm_event.so', 'mod_unique_id.so', 'mod_security2.so'):
        open(os.path.join(common.MODULES, name), 'w').close()


make_key('test')
make_key('other')
trust('test')

# --- which release ---------------------------------------------------------------------------------------

check('the newest of the 4.25 line, by number, not by text', crs.newest(['crs-4.25.1', 'crs-4.25.10', 'crs-4.25.2',
                                                                       'crs-4.30.0', 'crs-3.3.9', 'v1.0.0', 'crs-4.25']),
      '4.25.10')
check('none of the line: none', crs.newest(['crs-4.30.0', 'v1.0.0']), '')
publish('4.25.1')
publish('4.25.2')
publish('4.30.0')
check('the tags of a place named by file://: its releases', crs.tags(), ['crs-4.25.1', 'crs-4.25.2', 'crs-4.30.0'])

# GitHub's list of references, as `git ls-remote` reads it
refs = os.path.join(TOP, 'refs')


def pkt(line):
    data = line.encode() + b'\n'
    return b'%04x' % (len(data) + 4) + data


with open(refs, 'wb') as handle:
    handle.write(pkt('# service=git-upload-pack') + b'0000' + pkt('a' * 40 + ' HEAD\0multi_ack') +
                 pkt('b' * 40 + ' refs/heads/main') + pkt('c' * 40 + ' refs/tags/crs-4.25.2') +
                 pkt('d' * 40 + ' refs/tags/crs-4.25.2^{}') + pkt('e' * 40 + ' refs/tags/crs-4.25.10') +
                 pkt('f' * 40 + ' refs/tags/v1.0.0') + b'0000')
os.rename(os.path.join(common.SHARE, 'crs-from'), os.path.join(common.SHARE, 'crs-from.off'))
crs.REFS = 'file://' + refs
check('the tags GitHub lists: the crs- ones, each once, an annotated tag\'s commit line not twice', crs.tags(),
      ['crs-4.25.10', 'crs-4.25.2'])
os.rename(os.path.join(common.SHARE, 'crs-from.off'), os.path.join(common.SHARE, 'crs-from'))

# --- the manifest ------------------------------------------------------------------------------------------

found = crs.signed_manifest('crs-4.25.2')
check('a manifest signed with a key this firewall holds: taken, the key named', [found['version'], found['key']],
      ['4.25.2', 'xgs-release-key-test.pub'])


codes = []


def refused(why, version='4.25.2', **kwargs):
    unpublish()
    publish(version, **kwargs)
    try:
        crs.signed_manifest('crs-' + version)
        check('refused: ' + why, 'taken', 'refused')
    except crs.Unsigned as reason:
        check('refused: ' + why, True, True)
        codes.append((reason.code, reason.detail))
        return str(reason)


said = refused('signed with a key this firewall does not hold', key='other')
check('said as such', 'does not verify' in said, True)
said = refused('no signature', drop=('crs.json.sig',))
check('said: not signed yet', 'is not signed yet: it has no crs.json.sig' in said, True)
refused('no manifest', drop=('crs.json', 'crs.json.sig'))
refused('a manifest naming another release', manifest={'tag': 'crs-4.25.1'})
refused('a manifest whose version is not its tag\'s', manifest={'version': '4.25.1'})
refused('a manifest of another repository', manifest={'repository': 'someone/os-modsecurity'})
refused('a manifest checked against another key than the pinned one', manifest={'upstream_key': 'A' * 40})
refused('a manifest of another format', manifest={'format': 2})
refused('an archive of another name', manifest={'archive': 'coreruleset-4.25.2.tar.gz'})
refused('a size no archive of it can have', manifest={'size': 64 << 20})
refused('a size that is no number', manifest={'size': '12'})
trust()
said = refused('a firewall that holds no key')
check('said as such', "this firewall's release keys - it has none" in said, True)
trust('test')
check('each refusal by a code the page says in its own language, its variable part apart', codes, [
    ('badsig', 'crs-4.25.2'), ('unsigned', 'crs-4.25.2: crs.json.sig'), ('unsigned', 'crs-4.25.2: crs.json'),
    ('manifest', 'crs-4.25.2: crs-4.25.1, 4.25.2, coreruleset-4.25.2-minimal.tar.gz'),
    ('manifest', 'crs-4.25.2: crs-4.25.2, 4.25.1, coreruleset-4.25.2-minimal.tar.gz'), ('manifest', 'crs-4.25.2: repository'),
    ('manifest', 'crs-4.25.2: upstream_key'), ('manifest', 'crs-4.25.2: format'), ('manifest', 'crs-4.25.2: archive'),
    ('manifest', 'crs-4.25.2: size'), ('manifest', 'crs-4.25.2: size'), ('nokeys', 'crs-4.25.2')])
unpublish()
got = crs.install()
check('no release of the line: said by its code, with the line', [got['status'], got['code'], got['line']],
      ['failed', 'none', '4.25'])
publish('4.25.2', drop=('crs.json.sig',))
got = crs.install()
check('the newest not signed yet: its code and its tag, nothing installed', [got['code'], got['detail'], current()],
      ['unsigned', 'crs-4.25.2: crs.json.sig', None])

# --- an install --------------------------------------------------------------------------------------------

unpublish()
data_252 = publish('4.25.2')
got = crs.install()
check('installed: the newest of the line, signed', [got['status'], got['version'], got['signed_with']],
      ['installed', '4.25.2', 'xgs-release-key-test.pub'])
record = crs.installed()
check('crs/current points at it, and its record says where it came from', [current(), record['source'], record['tag'],
                                                                           record['sha256'], record['rules'], record['line']],
      ['4.25.2', 'release', 'crs-4.25.2', hashlib.sha256(data_252).hexdigest(), 12, '4.25'])
check('its setup copied from the example, as the Core Rule Set\'s install says', open(os.path.join(
    common.CRS, 'current', 'crs-setup.conf')).read(), open(os.path.join(common.CRS, 'current', 'crs-setup.conf.example')).read())
check('no Apache here: not tested by it, and said', [record['tested'], 'not installed' in record['tested_said']], [False, True])
check('files 0644, directories 0755', [oct(os.stat(os.path.join(common.CRS, '4.25.2', 'LICENSE')).st_mode & 0o777),
                                       oct(os.stat(os.path.join(common.CRS, '4.25.2', 'rules')).st_mode & 0o777)],
      ['0o644', '0o755'])
check('nothing left of the download or the unpacking', [n for n in os.listdir(common.CRS) if n.startswith('.')], [])
got = crs.install()
check('the same release again: nothing to do', [got['status'], got['version']], ['current', '4.25.2'])

fake_httpd()
publish('4.25.3')
got = crs.install()
check('a newer release: installed, Apache\'s test passed, the one before kept', [got['status'], current(), versions(),
                                                                                 crs.installed()['previous'],
                                                                                 crs.installed()['tested']],
      ['installed', '4.25.3', ['4.25.2', '4.25.3'], '4.25.2', True])
check('Apache tested a configuration of ModSecurity and the release', open(TOP + '/httpd.args').read().split()[:2],
      ['-t', '-f'])
publish('4.25.4')
crs.install()
check('the next one: the one before kept, the older one taken away', [current(), versions()],
      ['4.25.4', ['4.25.3', '4.25.4']])
# Apache's configuration on disk names its rules by their version (setup.crs_folder()): that one stays
os.makedirs(common.ETC, exist_ok=True)
with open(common.ETC + '/httpd.conf', 'w') as handle:
    handle.write('Include "%s/4.25.3/crs-setup.conf"\nInclude "%s/4.25.3/rules/*.conf"\n' % (common.CRS, common.CRS))
check('the versions a configuration on disk names', crs.in_use(), {'4.25.3'})

fake_httpd(1, 'AH00526: Syntax error on line 4 of crs-setup.conf')
publish('4.25.5')
got = crs.install()
check('a release Apache refuses: not used, said with its words', [got['status'], current(), 'AH00526' in got['message'],
                                                                  versions()],
      ['failed', '4.25.4', True, ['4.25.3', '4.25.4']])
check('said by its code, Apache\'s words after it', [got['code'], got['detail']],
      ['refused', 'AH00526: Syntax error on line 4 of crs-setup.conf'])
fake_httpd()
unpublish()

bad = archive('4.25.6')
publish('4.25.6', data=bad, manifest={'sha256': '0' * 64})
got = crs.install()
check('an archive that is not the one signed: not installed, said, nothing in use changed',
      [got['status'], 'is not the one signed' in got['message'], current(), versions()],
      ['failed', True, '4.25.4', ['4.25.3', '4.25.4']])
check('said by its code, its tag and sizes after it', [got['code'], got['detail'].startswith('crs-4.25.6: ')],
      ['mismatch', True])
unpublish()


def refused_archive(why, data, version='4.25.7'):
    unpublish()
    publish(version, data=data)
    got = crs.install()
    check('an archive refused, %s: nothing in use changed, nothing left of it' % why,
          [got['status'], current(), versions(), [n for n in os.listdir(common.CRS) if n.startswith('.') or n.endswith('.new')]],
          ['failed', '4.25.4', ['4.25.3', '4.25.4'], []])
    check('said by its code: archive', got['code'], 'archive')
    return got['message']


refused_archive('a member outside its top directory', archive('4.25.7', extra=[('coreruleset-4.25.7/../../x', 'x')]))
refused_archive('a link', archive('4.25.7', extra=[('coreruleset-4.25.7/rules/x.conf', '', tarfile.SYMTYPE, '/etc/passwd')]))
refused_archive('a device', archive('4.25.7', extra=[('coreruleset-4.25.7/dev', '', tarfile.CHRTYPE)]))
said = refused_archive('another version\'s top directory', archive('4.25.7', top='coreruleset-4.25.1'))
check('said with its top directory', 'coreruleset-4.25.1' in said, True)
refused_archive('too few rule files', archive('4.25.7', rules=3))
refused_archive('no archive at all', b'not a gzip file')
unpublish()

# --- by hand -----------------------------------------------------------------------------------------------

path = os.path.join(TOP, 'coreruleset-4.25.8-minimal.tar.gz')
data = archive('4.25.8')
with open(path, 'wb') as handle:
    handle.write(data)
got = crs.install_archive(path, '0' * 64)
check('by hand, another SHA-256 than the archive\'s: refused', [got['status'], got['code'], current()],
      ['failed', 'mismatch', '4.25.4'])
got = crs.install_archive(path, 'x')
check('by hand, no SHA-256: refused', [got['status'], got['code']], ['failed', 'sha256'])
got = crs.install_archive(path, hashlib.sha256(data).hexdigest().upper())
check('by hand, its SHA-256: installed, said by hand', [got['status'], current(), crs.installed()['source'],
                                                        crs.installed()['signed_with']], ['installed', '4.25.8', 'hand', ''])
check('the version Apache\'s configuration on disk names kept beside the one before, though older',
      versions(), ['4.25.3', '4.25.4', '4.25.8'])

# --- Apply after an install, and one at a time -------------------------------------------------------------

applied = []
setup._apply = lambda *args: applied.append(args) or {'status': 'ok', 'state': 'running', 'sites': 1}
with open(common.CONFIG, 'w') as handle:
    handle.write('<opnsense><OPNsense><ModSecurity><general><enabled>1</enabled></general></ModSecurity></OPNsense></opnsense>')
publish('4.25.9')
got = crs.install()
check('the plugin on: Apply takes the new release, its answer with the install\'s', [got['status'], len(applied),
                                                                                     got['apply']['state']],
      ['installed', 1, 'running'])
check('Apply\'s answer kept for the page', common.read_json(common.STATE + '/apply.json')['state'], 'running')
os.unlink(common.ETC + '/httpd.conf')
os.makedirs(common.STATE, exist_ok=True)
holder = open(common.STATE + '/apply.lock', 'w')
__import__('fcntl').flock(holder, __import__('fcntl').LOCK_EX)
got = crs.install()
check('an Apply or an install running: this one says so and changes nothing', [got['status'], got['code'], current()],
      ['failed', 'busy', '4.25.9'])
holder.close()

# --- check -------------------------------------------------------------------------------------------------

check('check: the newest installed', crs.check()['status'], 'current')
publish('4.25.11')
got = crs.check()
check('check: a newer one signed, available; nothing downloaded or changed', [got['status'], got['version'], current()],
      ['available', '4.25.11', '4.25.9'])
publish('4.25.12', key='other')
check('check: the newest not signed with a key held - said', crs.check()['status'], 'unsigned')
unpublish()
check('check: no release of the line', [crs.check()['status'], crs.check()['code']], ['none', 'none'])
check('status: what is installed', crs.installed()['version'], '4.25.9')

shutil.rmtree(TOP, ignore_errors=True)
print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
