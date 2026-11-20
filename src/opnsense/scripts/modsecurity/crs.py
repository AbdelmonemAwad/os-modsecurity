#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The OWASP Core Rule Set the Web Application Firewall inspects requests with: where it comes from,
how it is checked, and its install.

    crs.py status                        what is installed, as JSON
    crs.py check                         the release install would take, and whether it is signed;
                                         nothing downloaded but its manifest, nothing changed
    crs.py install                       the newest signed release of the 4.25 line (Settings' Install)
    crs.py install-archive FILE SHA256   an archive given by hand, taken only with the SHA-256 given

WHERE IT COMES FROM (settled point 3a). The Core Rule Set publishes each release on GitHub with a PGP
signature by its project's key, fingerprint 3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72. No firewall
checks that signature itself: OPNsense installs no gpg. The owner's private signing repository fetches
each release, checks its signature with gpg against that fingerprint, and republishes the release's
minimal archive as a release of this plugin's repository, tagged crs-<version> and never marked its latest
(self-update.py follows the latest): three files - the archive; crs.json, format 1, its keys sorted as
Python's json.dumps writes them: archive, date (when it was checked), format, repository, sha256, size,
tag, upstream (the release it is, "coreruleset/coreruleset v4.25.2"), upstream_key (the fingerprint it was
checked against), version; and crs.json.sig, crs.json's Ed25519 signature by the project's release key.
A release is taken only when crs.json's signature verifies with a key in release-keys/ - the keys
self-update.py trusts - it names the fingerprint above, and the archive is the one signed.

WHICH ONE (settled point 4b). The 4.25 line, which receives the Core Rule Set's security fixes as
backports with fewer changes to its rules than the newest line, so fewer new false positives: the newest
crs-4.25.<n> tag of this repository, as GitHub's git endpoint lists them (the list `git ls-remote` reads,
not the API, so not its hourly allowance). Following the newest 4.x instead is the plan's next part.

BY HAND. An archive the owner fetched and checked himself - with the Core Rule Set's own `gpg --verify`
against the fingerprint above, on another machine - is taken with the SHA-256 he gives, from a shell
only: configd has no action for it. The page says it was installed by hand.

WHAT AN INSTALL IS. The archive unpacked - its one top directory coreruleset-<version>/, files and
directories only - into /usr/local/etc/os-modsecurity/crs/<version>; its crs-setup.conf.example copied to
crs-setup.conf, as the Core Rule Set's install says; Apache's test (httpd -t) of a configuration that
holds it; then crs/current pointed at it. A version Apache refuses is not used. The one before stays
until the next install, and so does every version Apache's configuration on disk names: it names
crs/<version>, not crs/current, so the one Apache runs keeps its rules. Where the plugin is on, Apply then
takes the new one (setup.py).

A test firewall may read the releases from another place, named in the one-line file
/usr/local/share/os-modsecurity/crs-from (a URL, file:// too): what is installed must still be signed with
a key in release-keys/, so the place decides nothing.
"""

import fcntl
import glob
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'os-modsecurity'
REPO = 'AbdelmonemAwad/os-modsecurity'
RELEASES = 'https://github.com/' + REPO + '/releases'
REFS = 'https://github.com/' + REPO + '.git/info/refs?service=git-upload-pack'
KEYS = os.path.join(HERE, 'release-keys')
OPENSSL = '/usr/bin/openssl'
AGENT = {'User-Agent': NAME + '-crs'}
# The line followed (settled point 4b), and the Core Rule Set project's key its releases are checked against.
LINE = '4.25'
UPSTREAM_KEY = '36006F0E0BA167832158821138EEACA1AB8A6E72'
MANIFEST = 'crs.json'
MANIFEST_MAX = 64 << 10
ARCHIVE_MAX = 16 << 20
UNPACKED_MAX = 64 << 20
MEMBERS_MAX = 4000
VERSION = re.compile(r'(4\.[0-9]{1,3}\.[0-9]{1,4})\Z')
FIELDS = {
    'repository': re.compile(re.escape(REPO) + r'\Z'),
    'archive': re.compile(r'coreruleset-4\.[0-9]{1,3}\.[0-9]{1,4}-minimal\.tar\.gz\Z'),
    'sha256': re.compile(r'[0-9a-f]{64}\Z'),
    'version': VERSION,
    'tag': re.compile(r'crs-4\.[0-9]{1,3}\.[0-9]{1,4}\Z'),
    'upstream_key': re.compile(re.escape(UPSTREAM_KEY) + r'\Z'),
}


class Refusal(Exception):
    """What stops an install: a code the page says in its own language (index.volt), the variable part it
    says after - a release's tag, a field's name, a file in an archive, Apache's or the system's own words -
    and the whole of it in English, for a shell and for the logs."""

    def __init__(self, code, message, detail=''):
        super().__init__(message)
        self.code = code
        self.detail = detail


class Unsigned(Refusal):
    """A release not taken: no manifest, a signature that does not verify, or a manifest that is not
    of a Core Rule Set release of this repository."""


class Unusable(Refusal):
    """An archive that is not one to install."""


def refused(code, message, detail='', **more):
    """An install's answer when it took nothing: {'status': 'failed', 'code', 'detail', 'message', ...}."""
    return dict({'status': 'failed', 'code': code, 'detail': detail, 'message': message}, **more)


def refusal(reason, **more):
    return refused(reason.code, str(reason), reason.detail, **more)


def state_path():
    return common.CRS + '/installed.json'


def crs_from():
    """Where the releases are read: this repository's on GitHub, or the place a test firewall names."""
    try:
        with open(os.path.join(common.SHARE, 'crs-from'), encoding='utf-8') as handle:
            place = handle.read().strip()
        if place:
            return place.rstrip('/')
    except OSError:
        pass
    return RELEASES


def release_url(tag, name):
    return '%s/download/%s/%s' % (crs_from(), urllib.request.quote(tag, safe=''), name)


def fetch(url, limit):
    """A file read whole; one larger than limit is no file of a release. A file missing from a place
    named by file:// is GitHub's 404 for a file a release does not have."""
    try:
        response = urllib.request.urlopen(urllib.request.Request(url, headers=AGENT), timeout=60)
    except urllib.error.URLError as error:
        if isinstance(getattr(error, 'reason', None), FileNotFoundError):
            raise urllib.error.HTTPError(url, 404, 'Not Found', {}, None) from error
        raise
    with response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise Unsigned('manifest', '%s is larger than a file of its kind can be' % url.rsplit('/', 1)[-1],
                       url.rsplit('/', 1)[-1])
    return data


def tags():
    """The crs-<version> tags there are: from GitHub's git endpoint, the list of references `git
    ls-remote` reads; from a place named by file://, its download/ directory's names."""
    place = crs_from()
    if place.startswith('file://'):
        try:
            return sorted(n for n in os.listdir(place[len('file://'):] + '/download') if n.startswith('crs-'))
        except OSError:
            return []
    request = urllib.request.Request(REFS, headers={'User-Agent': 'git/2 ' + AGENT['User-Agent']})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(8 << 20)
    found, at = set(), 0
    while at + 4 <= len(data):
        try:
            size = int(data[at:at + 4], 16)
        except ValueError:
            break
        if size < 4:
            at += 4
            continue
        line = data[at + 4:at + size].split(b'\0')[0].strip().decode('ascii', 'replace')
        at += size
        if len(line) > 41 and line[40] == ' ' and line[41:].startswith('refs/tags/crs-'):
            found.add(line[41 + len('refs/tags/'):].split('^')[0])
    return sorted(found)


def key(version):
    return tuple(int(x) for x in version.split('.'))


def newest(names, line=LINE):
    """The newest version of the line among the tags: '4.25.2' of crs-4.25.2; '' when there is none."""
    want = re.compile(r'crs-(' + re.escape(line) + r'\.[0-9]{1,4})\Z')
    versions = [m.group(1) for m in (want.match(n) for n in names) if m]
    return max(versions, key=key) if versions else ''


def signature_key(data, signature):
    """The name of the public key in KEYS whose signature over data signature is - OpenSSL's own
    Ed25519 check, as self-update.py makes it - or '' when none is."""
    keys = sorted(glob.glob(os.path.join(KEYS, '*.pub')))
    if not keys or len(signature) != 64:
        return ''
    os.makedirs(common.SHARE, exist_ok=True)
    paths = []
    try:
        for content, prefix in ((data, '.crs-manifest-'), (signature, '.crs-signature-')):
            fd, path = tempfile.mkstemp(dir=common.SHARE, prefix=prefix)
            paths.append(path)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(content)
        for one in keys:
            done = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', one, '-rawin', '-in', paths[0],
                                   '-sigfile', paths[1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=30, check=False)
            if done.returncode == 0:
                return os.path.basename(one)
    finally:
        for path in paths:
            try:
                os.unlink(path)
            except OSError:
                pass
    return ''


def signed_manifest(tag):
    """crs.json of the release tag: read, its signature verified with a key in KEYS, every field it must
    have checked against the tag. Its fields, and 'key', the key's name; Unsigned when it is not to be
    taken. A network failure is the caller's to say."""
    missing = MANIFEST
    try:
        data = fetch(release_url(tag, MANIFEST), MANIFEST_MAX)
        missing = MANIFEST + '.sig'
        signature = fetch(release_url(tag, MANIFEST + '.sig'), 64)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Unsigned('unsigned', '%s is not signed yet: it has no %s' % (tag, missing),
                           '%s: %s' % (tag, missing)) from error
        raise
    name = signature_key(data, signature)
    if not name:
        if not glob.glob(os.path.join(KEYS, '*.pub')):
            raise Unsigned('nokeys', "the signature of %s does not verify with this firewall's release keys - it "
                           'has none' % tag, tag)
        raise Unsigned('badsig', 'the signature of %s does not verify with any release key of this firewall' % tag, tag)
    try:
        found = json.loads(data.decode('utf-8'))
    except ValueError as error:
        raise Unsigned('manifest', 'the manifest of %s, signed, is not JSON' % tag, tag) from error
    if not isinstance(found, dict) or found.get('format') != 1:
        raise Unsigned('manifest', 'the manifest of %s is of a format this crs.py does not read' % tag,
                       '%s: format' % tag)
    for field, pattern in FIELDS.items():
        if not isinstance(found.get(field), str) or not pattern.match(found[field]):
            raise Unsigned('manifest', 'the manifest of %s has no %s, or not one of the form it must have' % (tag, field),
                           '%s: %s' % (tag, field))
    if found['tag'] != tag or found['tag'] != 'crs-' + found['version'] or \
            found['archive'] != 'coreruleset-%s-minimal.tar.gz' % found['version']:
        raise Unsigned('manifest', 'the manifest of %s names another release: %s' % (tag, found['tag']),
                       '%s: %s, %s, %s' % (tag, found['tag'], found['version'], found['archive']))
    size = found.get('size')
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= ARCHIVE_MAX:
        raise Unsigned('manifest', 'the manifest of %s has no size, or one no archive of it can have' % tag,
                       '%s: size' % tag)
    found['key'] = name
    return found


def download(manifest, path):
    """The archive the manifest names, read as far as its signed size and hashed on the way; Unusable
    when it is not the one signed."""
    request = urllib.request.Request(release_url(manifest['tag'], manifest['archive']), headers=AGENT)
    digest, size = hashlib.sha256(), 0
    with urllib.request.urlopen(request, timeout=120) as response, open(path, 'wb') as handle:
        while True:
            chunk = response.read(1 << 16)
            if not chunk:
                break
            size += len(chunk)
            if size > manifest['size']:
                break
            digest.update(chunk)
            handle.write(chunk)
    if size != manifest['size'] or digest.hexdigest() != manifest['sha256']:
        raise Unusable('mismatch', 'the archive of %s is not the one signed: %s bytes where %d were signed%s' % (
            manifest['tag'], 'more than %d' % manifest['size'] if size > manifest['size'] else size,
            manifest['size'], '' if size > manifest['size'] else ', SHA-256 %s where %s was' % (
                digest.hexdigest()[:16], manifest['sha256'][:16])),
            '%s: %s > %d' % (manifest['tag'], size, manifest['size']) if size > manifest['size'] else
            '%s: %d / %d, SHA-256 %s / %s' % (manifest['tag'], size, manifest['size'], digest.hexdigest()[:16],
                                             manifest['sha256'][:16]))


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b''):
            digest.update(chunk)
    return digest.hexdigest()


def unpack(archive, folder, version=None):
    """The archive's one top directory, coreruleset-<version>/, written into folder: its directories
    0755, its files 0644, nothing outside it, no link, no device. The version (of the top directory's
    name, which must be the one given where one is), and the number of rule files."""
    try:
        tar = tarfile.open(archive, 'r:gz')
    except (OSError, tarfile.TarError) as error:
        raise Unusable('archive', 'the archive cannot be read: %s' % error, str(error)) from error
    with tar:
        members = tar.getmembers()
        if not members or len(members) > MEMBERS_MAX:
            raise Unusable('archive', 'the archive holds %d entries' % len(members), '%d / %d' % (len(members), MEMBERS_MAX))
        top = members[0].name.strip('/').split('/')[0]
        found = re.fullmatch(r'coreruleset-(4\.[0-9]{1,3}\.[0-9]{1,4})', top)
        if not found or (version and found.group(1) != version):
            raise Unusable('archive', 'the archive is not coreruleset-%s: its top directory is %s' % (version or '<version>', top),
                           top)
        total = 0
        os.makedirs(folder, mode=0o755)
        for member in members:
            name = member.name.strip('/')
            parts = name.split('/')
            if parts[0] != top or '..' in parts or '' in parts or name.startswith('/'):
                raise Unusable('archive', 'the archive holds %s, outside %s/' % (member.name, top), member.name)
            inside = parts[1:]
            if not inside:
                continue
            target = os.path.join(folder, *inside)
            if member.isdir():
                os.makedirs(target, mode=0o755, exist_ok=True)
                continue
            if not member.isfile():
                raise Unusable('archive', 'the archive holds %s, which is no file' % member.name, member.name)
            total += member.size
            if total > UNPACKED_MAX:
                raise Unusable('archive', 'the archive unpacks to more than %d bytes' % UNPACKED_MAX,
                               '> %d' % UNPACKED_MAX)
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            source = tar.extractfile(member)
            with source, open(target, 'wb') as handle:
                shutil.copyfileobj(source, handle)
            os.chmod(target, 0o644)
    setup = os.path.join(folder, 'crs-setup.conf.example')
    rules = sorted(glob.glob(os.path.join(folder, 'rules', '*.conf')))
    if not os.path.isfile(setup) or len(rules) < 10:
        raise Unusable('archive', 'the archive has no crs-setup.conf.example, or %d rule files' % len(rules),
                       'crs-setup.conf.example, rules/*.conf: %d' % len(rules))
    shutil.copyfile(setup, os.path.join(folder, 'crs-setup.conf'))
    os.chmod(os.path.join(folder, 'crs-setup.conf'), 0o644)
    return found.group(1), len(rules)


def httpd_check(folder, run=subprocess.run):
    """Apache's test (httpd -t) of a configuration that holds this Core Rule Set: (True, what it said),
    (False, what it said), or (None, why not) where Apache or ModSecurity is not installed."""
    import setup
    module = setup.security2()
    the_mpm = setup.mpm()
    if not os.path.isfile(common.HTTPD) or module is None or the_mpm is None:
        return None, 'not tested by Apache: apache24 or ap24-mod_security is not installed'
    with tempfile.TemporaryDirectory(prefix='.crs-check-', dir=common.CRS) as work:
        conf = os.path.join(work, 'httpd.conf')
        lines = ['ServerRoot "/usr/local"', 'ErrorLog "/dev/null"', 'PidFile "%s/httpd.pid"' % work,
                 'LoadModule %s %s' % (the_mpm['name'], the_mpm['path'])]
        # the modules Apply's configuration always loads, as far as Apache has them
        lines += ['LoadModule %s %s' % (m['name'], m['path']) for m in setup.modules(setup.ALWAYS)[0]]
        lines += ['LoadModule security2_module %s' % module, 'ServerName localhost', 'SecRuleEngine Off',
                  'Include "%s/crs-setup.conf"' % folder, 'Include "%s/rules/*.conf"' % folder]
        with open(conf, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
        return setup.httpd_test(conf, run)


def installed():
    """What is installed: installed.json, when crs/current is there; else {}."""
    found = common.read_json(state_path())
    if not found.get('version') or not os.path.isdir(os.path.join(common.CRS, 'current', 'rules')):
        return {}
    return found


def in_use():
    """The versions Apache's configuration on disk names (crs/<version>/, setup.crs_folder()): never taken
    away, so the one Apache runs, and the one an Apply puts back, keep their rules."""
    try:
        with open(common.ETC + '/httpd.conf', encoding='utf-8', errors='replace') as handle:
            text = handle.read()
    except OSError:
        return set()
    return set(re.findall(re.escape(common.CRS) + r'/(4\.[0-9]{1,3}\.[0-9]{1,4})/', text))


def activate(version, rules, record, run=subprocess.run):
    """The unpacked version in crs/<version>.new made crs/<version>, tested, and pointed at by
    crs/current; the one before kept, and every one a configuration on disk names, any older one taken
    away. The record written; Unusable when Apache refuses it - then nothing in use changed."""
    staged = os.path.join(common.CRS, version + '.new')
    passed, said = httpd_check(staged, run)
    if passed is False:
        raise Unusable('refused', 'Apache refused the Core Rule Set %s: %s' % (version, said), said)
    before = installed().get('version', '')
    final = os.path.join(common.CRS, version)
    if os.path.lexists(final):
        aside = os.path.join(common.CRS, '.old-%s-%d' % (version, os.getpid()))
        os.replace(final, aside)
        shutil.rmtree(aside, ignore_errors=True)
    os.replace(staged, final)
    link = os.path.join(common.CRS, '.current.new')
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(version, link)
    os.replace(link, os.path.join(common.CRS, 'current'))
    record.update({'version': version, 'rules': rules, 'installed_at': int(time.time()), 'line': LINE,
                   'tested': passed is True, 'tested_said': said if passed is not True else '',
                   'previous': before if before != version else record.get('previous', '')})
    common.write_json(state_path(), record, 0o644)
    named = in_use()
    for name in os.listdir(common.CRS):
        path = os.path.join(common.CRS, name)
        if name in (version, before, 'current', 'installed.json') or name in named or not os.path.isdir(path) or \
                os.path.islink(path):
            continue
        if re.fullmatch(r'4\.[0-9.]+(\.new)?', name) or name.startswith('.old-'):
            shutil.rmtree(path, ignore_errors=True)
    return record


def stage(archive, version=None):
    """The archive unpacked into crs/<version>.new: (version, rules)."""
    os.makedirs(common.CRS, mode=0o755, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix='.unpack-', dir=common.CRS)
    try:
        found, rules = unpack(archive, os.path.join(scratch, 'tree'), version)
        staged = os.path.join(common.CRS, found + '.new')
        if os.path.lexists(staged):
            shutil.rmtree(staged, ignore_errors=True)
        os.replace(os.path.join(scratch, 'tree'), staged)
        return found, rules
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def then_apply(result, run=subprocess.run):
    """With the plugin on, Apply takes the new Core Rule Set: its answer joins this one."""
    import setup
    try:
        on = common.general(common.read_root()).get('enabled')
    except (OSError, ValueError):
        on = False
    if on:
        result['apply'] = setup.applied(None, run, time.sleep, None)
    return result


def locked(work):
    """work() under Apply's lock: an install and an Apply never run at once."""
    os.makedirs(common.STATE, exist_ok=True)
    with open(common.STATE + '/apply.lock', 'w', encoding='utf-8') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return refused('busy', 'another Apply or a Core Rule Set install is running')
        return work()


def install(run=subprocess.run):
    """The newest signed release of the line, installed unless it is what is installed."""
    def work():
        try:
            found = tags()
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as error:
            return refused('unlisted', "this repository's releases could not be listed: %s" % error, str(error))
        version = newest(found)
        if not version:
            return refused('none', 'no release of the Core Rule Set %s is published for this plugin yet' % LINE,
                           line=LINE)
        tag = 'crs-' + version
        try:
            manifest = signed_manifest(tag)
        except Unsigned as reason:
            return refusal(reason, tag=tag)
        except urllib.error.HTTPError as error:
            return refused('unreachable', 'GitHub refused the manifest of %s (%s)' % (tag, error.code),
                           '%s: HTTP %s' % (tag, error.code), tag=tag)
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as error:
            return refused('unreachable', 'could not reach GitHub: %s' % error, str(error), tag=tag)
        have = installed()
        if have.get('version') == version and have.get('sha256') == manifest['sha256']:
            return {'status': 'current', 'version': version, 'message': 'the Core Rule Set %s is installed '
                    'already' % version}
        os.makedirs(common.CRS, mode=0o755, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.download-', dir=common.CRS) as work_dir:
            archive = os.path.join(work_dir, manifest['archive'])
            try:
                download(manifest, archive)
                staged, rules = stage(archive, version)
                record = {'source': 'release', 'tag': tag, 'sha256': manifest['sha256'], 'size': manifest['size'],
                          'signed_with': manifest['key'], 'date': str(manifest.get('date', '')),
                          'upstream_key': manifest['upstream_key']}
                activate(staged, rules, record, run)
            except Unusable as reason:
                shutil.rmtree(os.path.join(common.CRS, version + '.new'), ignore_errors=True)
                return refusal(reason, tag=tag)
            except (urllib.error.URLError, http.client.HTTPException) as error:
                shutil.rmtree(os.path.join(common.CRS, version + '.new'), ignore_errors=True)
                return refused('unreachable', 'the archive of %s could not be downloaded: %s' % (tag, error),
                               str(error), tag=tag)
            except OSError as error:
                shutil.rmtree(os.path.join(common.CRS, version + '.new'), ignore_errors=True)
                return refused('write', 'the archive of %s could not be installed: %s' % (tag, error), str(error),
                               tag=tag)
        return then_apply({'status': 'installed', 'version': version, 'tag': tag, 'signed_with': manifest['key'],
                           'message': 'the Core Rule Set %s installed, signed with %s' % (version, manifest['key'])},
                          run)
    return locked(work)


def install_archive(path, sha256, run=subprocess.run):
    """An archive given by hand, taken only when its SHA-256 is the one given."""
    def work():
        want = (sha256 or '').strip().lower()
        if not re.fullmatch(r'[0-9a-f]{64}', want):
            return refused('sha256', 'give the archive\'s SHA-256, 64 hexadecimal digits, as checked with its '
                           'signature')
        try:
            got = sha256_of(path)
        except OSError as error:
            return refused('archive', 'the archive cannot be read: %s' % error, str(error))
        if got != want:
            return refused('mismatch', 'the archive is not the one given: SHA-256 %s, not %s' % (got[:16], want[:16]),
                           'SHA-256 %s / %s' % (got[:16], want[:16]))
        try:
            version, rules = stage(path)
            record = {'source': 'hand', 'tag': '', 'sha256': got, 'size': os.path.getsize(path), 'signed_with': '',
                      'date': '', 'upstream_key': ''}
            activate(version, rules, record, run)
        except Unusable as reason:
            for name in glob.glob(os.path.join(common.CRS, '*.new')):
                shutil.rmtree(name, ignore_errors=True)
            return refusal(reason)
        except OSError as error:
            return refused('write', 'the archive could not be installed: %s' % error, str(error))
        return then_apply({'status': 'installed', 'version': version, 'tag': '', 'signed_with': '',
                           'message': 'the Core Rule Set %s installed by hand' % version}, run)
    return locked(work)


def check():
    """The release install would take, whether its manifest is signed, and what is installed."""
    have = installed()
    try:
        version = newest(tags())
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as error:
        return refused('unlisted', "this repository's releases could not be listed: %s" % error, str(error),
                       installed=have.get('version', ''))
    if not version:
        return dict(refused('none', 'no release of the Core Rule Set %s is published for this plugin yet' % LINE,
                            line=LINE, installed=have.get('version', '')), status='none')
    try:
        manifest = signed_manifest('crs-' + version)
    except Unsigned as reason:
        return dict(refusal(reason, version=version, installed=have.get('version', '')), status='unsigned')
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as error:
        return refused('unreachable', 'could not reach GitHub: %s' % error, str(error), version=version,
                       installed=have.get('version', ''))
    newer = have.get('version') != version or have.get('sha256') != manifest['sha256']
    return {'status': 'available' if newer else 'current', 'version': version, 'signed_with': manifest['key'],
            'installed': have.get('version', ''), 'message': ('%s is signed and would be installed' if newer
                                                              else '%s is installed') % version}


def main(argv):
    command = argv[1] if len(argv) > 1 else 'status'
    if command == 'status':
        print(json.dumps(installed()))
    elif command == 'check':
        print(json.dumps(check()))
    elif command == 'install':
        print(json.dumps(install()))
    elif command == 'install-archive' and len(argv) == 4:
        print(json.dumps(install_archive(argv[2], argv[3])))
    else:
        print('usage: crs.py status | check | install | install-archive FILE SHA256', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
