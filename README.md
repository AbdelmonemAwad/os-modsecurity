<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/readme/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/readme/banner-light.svg">
  <img src="docs/images/readme/banner-light.svg" alt="os-modsecurity - the OWASP Core Rule Set in front of published sites" width="100%">
</picture>

<p align="center">
  <img alt="status: written, not released" src="https://img.shields.io/badge/status-written%2C%20not%20released-lightgrey.svg?style=flat-square">
  <a href="https://github.com/AbdelmonemAwad/os-modsecurity/actions/workflows/checks.yml"><img alt="checks on main" src="https://img.shields.io/github/actions/workflow/status/AbdelmonemAwad/os-modsecurity/checks.yml?branch=main&amp;style=flat-square&amp;label=checks"></a>
  <a href="LICENSE"><img alt="licence: BSD-2-Clause" src="https://img.shields.io/badge/licence-BSD--2--Clause-blue.svg?style=flat-square"></a>
  <a href="#what-is-tested"><img alt="OPNsense 26.7" src="https://img.shields.io/badge/OPNsense-26.7-d94f00.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/opnsense-arabic"><img alt="the page in English and in Arabic" src="https://img.shields.io/badge/GUI-English%20%C2%B7%20Arabic-2da44e.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/os-xgs-npu"><img alt="part of os-xgs-npu" src="https://img.shields.io/badge/part%20of-os--xgs--npu-9a6700.svg?style=flat-square"></a>
</p>

# ModSecurity for OPNsense

A Web Application Firewall in front of the sites published through the firewall: each request received
on the firewall by an Apache of the plugin's own, inspected by ModSecurity with the OWASP Core Rule Set,
and passed to the site's backend.

> ~~**Planned - nothing here runs yet.** This repository was opened on 2026-11-16 to hold
> ModSecurity as a plugin of its own. No code has been written or moved into it, and there is no
> release.~~
>
> **Written, not released (2026-11-20).** The first part is here: the sites, each one's mode and
> paranoia level, its certificate, and the Core Rule Set's install. Off by default. It has not run on an
> appliance yet: what was run is under [What is tested](#what-is-tested).

<p align="center"><b>Contents:</b> <a href="#what-it-does">What it does</a> &middot; <a href="#engine-and-why-it-is-not-the-plans">Engine, and why it is not the plan's</a> &middot; <a href="#where-the-rules-come-from">Where the rules come from</a> &middot; <a href="#what-it-does-not-do">What it does not do</a> &middot; <a href="#not-yet-and-why">Not yet, and why</a> &middot; <a href="#what-is-tested">What is tested</a> &middot; <a href="#installation">Installation</a> &middot; <a href="#updates">Updates</a> &middot; <a href="#where-it-fits">Where it fits</a> &middot; <a href="#licence">Licence</a></p>

## What it does

**Services: Web Application Firewall** (XGS: Web Application Firewall, order 67, when os-xgs-npu is
installed), one page, off by default:

- **sites** - each with its host names (a wildcard as the whole first label, `*.example.com`), its backend
  (`http://` or `https://`, an address or a name, a port, a path), its certificate of System: Trust or
  none, its mode and its paranoia level. A host name belongs to one site: the page refuses a name another
  site has, or one under another site's wildcard, since Apache would give such a request to one of them by
  the order of its configuration, which the page does not show. A request for a name no site has meets a
  catch-all that refuses it with 403, not inspected.
- **modes** - *Detection only*, every new site's first mode: each request is inspected and what the rules
  find is written to the audit log, and the request passes. *Blocking*: a request the Core Rule Set judges
  an attack, by its anomaly score, is refused with 403. ModSecurity's own `SecRuleEngine`, set in each
  site's virtual hosts.
- **paranoia levels** - 1 to 4, the Core Rule Set's own: level 1 for a new site, the fewest false
  positives; each level up runs more rules. Set for each site by a rule before the Core Rule Set's start
  (ids 19001 and on), by the host name its request names, which Apache chose the site by.
- **TLS** - a site with a certificate is served over HTTPS with it, and its plain HTTP requests are sent
  there; TLS 1.2 and 1.3 as Mozilla's intermediate profile has them. Without one, plain HTTP. A backend
  over HTTPS has its certificate checked against the firewall's trust store, unless the site says not to.
- **where Apache listens** - Settings' Listen interfaces' addresses, as OPNsense's web GUI takes its own
  (followed when one gets a new address), or every address; an HTTP port (80) and an HTTPS port (443). A
  port the web GUI holds where Apache would listen is refused, never taken, and the page says how to move
  the GUI: another TCP port, or its Listen interfaces, in System: Settings: Administration. The plugin
  never changes the GUI's settings.
- **the audit log** - JSON, one record a line, a file a day in `/var/log/modsecurity/audit_YYYYMMDD.log`:
  each transaction that matched a rule, or was refused or failed, with its rule ids - without the
  request's body or uploaded files, its `Authorization`, `Cookie` and `Set-Cookie` headers masked. Apache's
  own messages beside it (`error_YYYYMMDD.log`). Both kept as long as OPNsense keeps its own logs (System:
  Settings: Logging, 31 days by default). The page's table of what the rules found is the plan's next part.
- **Apply** - writes Apache's configuration from the page's settings with the plugin's templates
  (`templates/OPNsense/ModSecurity`), has Apache test it (`httpd -t`), and only then starts or reloads Apache
  with it: a configuration Apache refuses is put back as it was, and Apache goes on with what it had. A site
  that cannot be served - a certificate without its key, no port for its kind - is left out, named on the
  page with its reason.
- **System: Services** lists it while it is on; it starts at boot while it is on.

Nothing here adds a firewall rule: a site reached from another network needs a rule on that interface
passing its port to This Firewall, which the page reminds of. A site published by a port forward instead
never meets the rules.

**On an XGS appliance** a fifth card says what phase 0 measured: a site behind the firewall runs on the host
processor, never in hardware - a reverse proxy ends every connection on the firewall, which neither of
os-xgs-npu's flow makers offloads (a way out by `lo0`); on the second XGS 3300, 2,000 requests one at a time
through Apache and the Core Rule Set at paranoia level 1 (plain HTTP, Detection only): 148 a second, no flow
in hardware, and about 75 a second for each host core, derived from the processor time a request took - not
a load test. On the XGS 136: not measured yet.

## Engine, and why it is not the plan's

The plan names libmodsecurity 3 with nginx's module, loaded into os-nginx's nginx. Phase 0 found that
cannot be built as written on OPNsense 26.7.9 (read on the second XGS 3300, 2026-11-19): OPNsense's
repository has neither libmodsecurity 3 nor its nginx connector, its nginx is built with `MODSECURITY3=off`
(and NAXSI on), os-nginx's `nginx.conf` writes a fixed list of `load_module` lines with no place for
another, and a separate nginx would be the same package with the same module missing. What OPNsense's
repository does build is **Apache 2.4.70 with ModSecurity 2.9.15** - `apache24` and `ap24-mod_security`,
the pairing the Core Rule Set documents for Apache - so this plugin depends on those two packages
(`PLUGIN_DEPENDS`), as os-frontpanel depends on lcdproc, and runs Apache as its own instance: its
configuration in `/usr/local/etc/os-modsecurity`, its pid file `/var/run/modsecurity.pid`, never the
package's own configuration. Not taken: building libmodsecurity 3 and the connector here for each nginx
update OPNsense publishes (binaries to build, sign and keep up), and Coraza, which OPNsense has no package
for.

## Where the rules come from

The OWASP Core Rule Set publishes its releases on GitHub, each signed with its project's PGP key
(fingerprint `3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72`). A firewall has no gpg (OPNsense installs
none), so the signature is checked before a release reaches one: the owner's signing repository fetches
the release, checks it with gpg against that fingerprint, and republishes its minimal archive as a release
of this repository, `crs-<version>`, with `crs.json` (the archive's SHA-256 and size, the fingerprint it was
checked against) signed with the project's release key - the one chain of trust every plugin of the project
is installed by. **Install**, in Settings, takes the newest such release of the **4.25 line**, which receives
the Core Rule Set's security fixes as backports with fewer changes to its rules than the newest line, so
fewer new false positives: only when `crs.json`'s Ed25519 signature verifies with a key in `release-keys/`
and the archive is the one signed. The archive is unpacked into `/usr/local/etc/os-modsecurity/crs/<version>`
(its one top directory, files and directories only), its `crs-setup.conf.example` copied to `crs-setup.conf`
as the Core Rule Set's install says, tested by Apache, and only then used; the version before is kept until
the next install.

By hand, an archive checked elsewhere with the Core Rule Set's own `gpg --verify` is taken with the SHA-256
given, from a shell only: `/usr/local/opnsense/scripts/modsecurity/crs.py install-archive <archive> <sha256>`.
The page then says it was installed by hand.

## What it does not do

- **change the web GUI** - its port, its interfaces, its redirect: a port it holds is refused;
- **add a firewall rule**, or a port forward;
- **inspect what a site sends back** - responses pass unread (`SecResponseBodyAccess Off`, as phase 0
  measured), so the Core Rule Set's rules on responses do not run;
- **HTTP/2 or WebSocket** - Apache speaks HTTP/1.1, to clients and to backends;
- **touch the coprocessor** - nothing of os-xgs-npu is asked or changed.

## Not yet, and why

- **the table of what the rules found, exclusions, the Core Rule Set's updates** - the plan's next part:
  the incidents read from the JSON audit log with their rule ids (settled point 7a; phase 0 measured
  ModSecurity 2.9.15 accepting `SecAuditLogFormat JSON` and its records carrying the ids), exclusions for a
  site, and following the Core Rule Set's releases - the 4.25 line or the newest 4.x - by itself.
- **the Core Rule Set's releases** - none is published yet: the owner's signing repository has no job for
  them yet. Until then Install says the line has no release, and the lab installs one by hand.
- **the lab** - none of this has run on an appliance yet. The plan's test: a site behind the firewall,
  known attacks - SQL injection, a script tag, a path with `../` - refused in Blocking and logged in
  Detection only, ordinary requests passing, each finding in the log with its rule id; on the second XGS
  3300, the XGS 136 and a plain OPNsense. Not measured yet: Apache with the plugin's configuration, TLS
  (phase 0's figures are plain HTTP), a paranoia level above 1, the cost of each level, the request body's
  limit in Blocking, false positives on real sites.
- **the page in a browser** - not opened yet, in either theme or language.

## What is tested

On 2026-11-20, from this branch, away from an appliance - the checks, run under Python 3.14, PHP 8.5 and
node 24:

- **the Apply** - `tools/test-setup.py`, 201 checks: host names, wildcards and backends read as the model
  reads them - one table with `tools/test-model.php` (`tools/fixtures/cases.json`) - and the web GUI's
  listeners and where they meet the plugin's ports; a config.xml as OPNsense 26.7 writes it
  (`tools/fixtures/config.xml`, every address a documentation one), its certificates and keys made by
  OpenSSL at each run; the sites given to Apache and those left out with their reasons, a name taken twice
  or under a wildcard; the certificates written with their chain, the keys 0600, nothing else kept once
  Apache took the configuration; Apache's configuration rendered from the templates - its listeners, the
  catch-alls, each site's mode, its paranoia rule matched as Apache matches its names, the redirect to
  HTTPS, an HTTPS backend checked or not, a wildcard-only site's ServerName, the JSON audit log, and nothing
  of an unchecked config.xml in it; Apply's every way - off, each refusal (the packages, a module, the Core
  Rule Set, the web GUI's ports, no address, no site), Apache's test failing and the files put back, the
  start, the reload, Apache gone after either - and one at a time; the logs' days; listen.php's addresses
  through a stand-in of `interfaces_addresses()`; the page's status in each state;
- **the Core Rule Set** - `tools/test-crs.py`, 50 checks: releases made here and signed with throwaway keys -
  the newest of the line, a manifest refused for each field it must have, a key the firewall does not hold
  or none; the archive refused when it is not the one signed, holds a link, a device, a path outside its
  top directory, another version or too few rules - nothing in use changed; Apache refusing a release; the
  one before kept, an older one taken away; an archive by hand; Apply after an install; one at a time;
- **the model** - `tools/test-model.php`, 131 checks: Settings and each site checked as a Save checks them,
  each refusal on its field and only where its part changed; the model's XML in step with `common.py`;
- **the page's API and the hook** - `tools/test-mvc.php`, 26 checks: the status, Apply and Install POST
  only, the grid's rows, the service while on, the start at boot, a new address followed only on a Listen
  interface chosen, every configd action asked for there;
- **the page's script** - `tools/test-page.js`, 44 checks, under node with a stand-in jQuery: the cards in
  each state, the fifth on an XGS appliance, the lines under them, each refusal in the page's words, markup
  in a value written as text, Apply from Settings and from Sites, Install, the grid's columns;
- **the installation** - `tools/test-install.py`, 41 checks, in a temporary root: nothing copied without
  Apache and ModSecurity or with a syntax error, every file laid down with its mode and taken away, the menu
  at XGS 67 or under Services, the directories and who reads them, the rc script - start, reload as a
  graceful restart, stop, status, a pid file believed only when its process is this Apache - Apache stopped
  first at a removal, nothing of the plugin left, OPNsense's packages kept, nothing done by the old package
  in an upgrade;
- **the self-update** - `tools/test-self-update.py`, 45 checks, as os-blocklists has it;
- **the strings** - `tools/check-strings.py`: each of the 121 strings the GUI shows is in `source.json`; 24
  have their Arabic in opnsense-arabic already, the other 97 wait for it there;
- **the rest** - every installed file removed by the uninstaller (`tools/check-uninstall.sh`), `php -l`,
  `py_compile` and pyflakes, `sh -n`, XML and JSON, nothing private, no Arabic in the code, the copyright
  line; and, by hand, the page kit (kit).

Fifteen faults planted one at a time - the GUI's redirect port forgotten in either reading, a wildcard
that takes nothing, a refused configuration not put back, certificates taken away before Apache's test,
paranoia rules that do not stop at the first match, a release taken unsigned, an archive taken whatever its
SHA-256, a link in an archive, the pinned key not asked, a site checked though unchanged, a line written as
HTML, Apply by GET, the rc script believing any pid, the removal leaving the Core Rule Set - each was caught.

Measured in phase 0, on the second XGS 3300 (its lab, 2026-11-20, Apache and the Core Rule Set v4.25.2 as
that lab configured them, not this plugin): in Detection only an SQL injection, a script tag and a path with
`../` passed and were logged with rule ids of 942, 941 and 930; in Blocking the three were refused with 403
and a plain request answered 200; the audit log in JSON with the ids; the rates above; and `pkg delete` of
the two packages leaving nothing behind (`pkg autoremove` then takes apr, gdbm and yajl, which they
brought).

Not tested: anything on an appliance (above) - Apache itself has not read this configuration yet.

## Installation

It is not in the OPNsense plugin repository, so there is no `pkg install os-modsecurity`, and there is no
release yet.

**From a checkout** of this repository, on the firewall, as root, after OPNsense's own packages:

```sh
pkg install apache24 ap24-mod_security
sh install/install.sh
```

It stops when either package is missing, checks the PHP with `php -l` and the Python with `py_compile`
before anything is copied, copies `src/` onto `/usr/local`, puts the page in the menu (`place-menu.sh`: XGS
with os-xgs-npu, Services without), and stops Apache, or applies again where the plugin is on: no site is
published until it is turned on in Settings and the Core Rule Set is installed. Safe to run again: the
settings in config.xml and the Core Rule Set installed are kept.

`sh install/uninstall.sh` stops Apache and removes the plugin's files, its menu entry and everything it
wrote: Apache's configuration and the certificates exported for it, the Core Rule Set, its logs and what it
last did. The settings stay in config.xml, and `apache24` and `ap24-mod_security` stay installed:
`pkg delete ap24-mod_security apache24` takes them away.

**From a package**, once there is a release: `tools/make-package.sh` builds it on a firewall, and
`release.yml` in a FreeBSD virtual machine for each release, as os-blocklists does; pkg then installs the
two packages with it.

## Updates

As os-blocklists: taken by hand, to this repository's **releases** - from **XGS: Updates**, its *Plugins*
tab, where an os-xgs-npu that lists this plugin is installed, or by running
`/usr/local/opnsense/scripts/modsecurity/self-update.py` (`check` to ask). A release is installed only as its
owner signed it (`release.json` and its Ed25519 signature, the public key in `release-keys/`), only forward,
by the `install/install.sh` it carries. No cron entry runs it. The Core Rule Set's releases, `crs-<version>`,
are never this repository's latest: the self-update does not see them.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue. It installs the same on a plain OPNsense. os-nginx and its NAXSI are left as they are.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE). The Core Rule Set it installs is the OWASP Core Rule Set project's,
under the Apache License 2.0, which travels inside its archive.
