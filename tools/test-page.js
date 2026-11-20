#!/usr/bin/env node
/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The page's script (views/OPNsense/ModSecurity/index.volt), run under node: taken out of the template as
 * OPNsense would compile it in English - each lang._('...') the English it stands for - and run against
 * the family's small stand-in of jQuery that builds elements and writes them out as HTML, with stand-ins for
 * OPNsense's own page functions (ajaxGet, ajaxCall, mapDataToFormUI, saveFormToEndpoint) and the grid.
 *
 * What is checked: the four cards before a reading, and for each state of the service - off, packages
 * missing, no rules, no site, failed, stopped, running - with the sites by mode, the Core Rule Set and where
 * it came from, where Apache listens; the fifth card on an XGS appliance with phase 0's figures, and not
 * elsewhere; the lines under the cards - the firewall rule a site needs, the web GUI on a port chosen here
 * (settled point 8a), the sites not published and why, the last Apply refused - every value written as text,
 * so markup in one is shown and never run; an answer that cannot be read; Settings' Core Rule Set line and
 * its button; Apply from Settings (saved first) and from Sites, said under each; the Core Rule Set's
 * install, said; and the grid's columns.
 *
 *   node tools/test-page.js
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const VOLT = path.join(ROOT, 'src/opnsense/mvc/app/views/OPNsense/ModSecurity/index.volt');

let failed = 0;
let checks = 0;

function check(name, got, want) {
    checks++;
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) {
        failed++;
        console.log('FAIL ' + name + ' - got ' + JSON.stringify(got) + ', want ' + JSON.stringify(want));
    } else {
        console.log('ok   ' + name);
    }
}

/* --- the script, as the template compiles it in English --------------------------------------------- */

const volt = fs.readFileSync(VOLT, 'utf8');
let script = volt.split('<script>')[1].split('</script>')[0].replace(/\{#[\s\S]*?#\}/g, '');
const BS = String.fromCharCode(92);
/* Volt escapes what lang._() gives as HTML: an apostrophe comes out as &#039; - so does this */
script = script.replace(/\{\{\s*lang\._\('((?:[^'\\]|\\.)*)'\)\s*\}\}/g, function (all, text) {
    return text.split(BS + "'").join('&#039;').split('"').join('&quot;');
});
check('the script: no Volt left in it once compiled', script.indexOf('{{'), -1);

/* --- a small jQuery ---------------------------------------------------------------------------------- */

function escape(text) {
    return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function unescape(text) {
    return String(text).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#039;/g, "'")
        .replace(/&amp;/g, '&');
}

class Node {
    constructor(tag, classes) {
        this.tag = tag;
        this.attrs = {};
        this.classes = classes ? classes.split(/\s+/).filter(Boolean) : [];
        this.children = [];
        this.raw = null;
        this.shown = true;
        this.props = {};
        this.handlers = {};
    }

    get text() {
        if (this.raw !== null) {
            /* a textarea's content is text, markup and all, as a browser parses it */
            return unescape(this.tag === 'textarea' ? this.raw : this.raw.replace(/<[^>]*>/g, ''));
        }
        return this.children.map(c => (typeof c === 'string' ? c : c.text)).join('');
    }

    get inner() {
        if (this.raw !== null) {
            return this.raw;
        }
        return this.children.map(c => (typeof c === 'string' ? escape(c) : c.outer)).join('');
    }

    get outer() {
        let attrs = '';
        if (this.classes.length) {
            attrs += ' class="' + escape(this.classes.join(' ')) + '"';
        }
        for (const [k, v] of Object.entries(this.attrs)) {
            attrs += ' ' + k + '="' + escape(v) + '"';
        }
        return '<' + this.tag + attrs + '>' + this.inner + '</' + this.tag + '>';
    }
}

const byId = {};

function element(id) {
    return (byId[id] = byId[id] || new Node('div'));
}

function wrap(nodes) {
    const w = {
        nodes: nodes,
        addClass(c) {
            nodes.forEach(n => String(c).split(/\s+/).filter(Boolean).forEach(x => n.classes.includes(x) || n.classes.push(x)));
            return w;
        },
        removeClass(c) {
            nodes.forEach(n => (n.classes = n.classes.filter(x => !String(c).split(/\s+/).includes(x))));
            return w;
        },
        append(child) {
            nodes.forEach(n => {
                n.raw = null;
                (child && child.nodes ? child.nodes : [child]).forEach(c => n.children.push(c));
            });
            return w;
        },
        empty() {
            nodes.forEach(n => {
                n.children = [];
                n.raw = null;
            });
            return w;
        },
        text(value) {
            if (value === undefined) {
                return nodes.map(n => n.text).join('');
            }
            nodes.forEach(n => {
                n.raw = null;
                n.children = [String(value)];
            });
            return w;
        },
        html(value) {
            if (value === undefined) {
                return nodes.length ? nodes[0].inner : '';
            }
            nodes.forEach(n => {
                n.children = [];
                n.raw = String(value);
            });
            return w;
        },
        attr(name, value) {
            if (value === undefined) {
                return nodes.length ? nodes[0].attrs[name] : undefined;
            }
            nodes.forEach(n => (n.attrs[name] = String(value)));
            return w;
        },
        prop(name, value) {
            if (name === 'outerHTML') {
                return nodes.length ? nodes[0].outer : '';
            }
            if (value === undefined) {
                return nodes.length ? nodes[0].props[name] : undefined;
            }
            nodes.forEach(n => (n.props[name] = value));
            return w;
        },
        toggle(on) {
            nodes.forEach(n => (n.shown = !!on));
            return w;
        },
        show() {
            return w.toggle(true);
        },
        hide() {
            return w.toggle(false);
        },
        click(fn) {
            nodes.forEach(n => (n.handlers.click = fn));
            return w;
        },
        on(event, fn) {
            nodes.forEach(n => (n.handlers[event] = fn));
            return w;
        },
        tab() {
            return w;
        },
        selectpicker() {
            return w;
        },
        UIBootgrid(options) {
            nodes.forEach(n => (n.grid = options));
            return w;
        },
        bootgrid(what) {
            nodes.forEach(n => (n.reloads = (n.reloads || 0) + (what === 'reload' ? 1 : 0)));
            return w;
        }
    };
    return w;
}

let ready = null;

function $(what) {
    if (typeof what === 'function') {
        ready = what;
        return;
    }
    if (what && what.nodes) {
        return what;
    }
    if (what && what.tagName) {
        return wrap([what.node]);
    }
    if (what === document) {
        return {ready: fn => (ready = fn)};
    }
    const made = /^<(\w+)(?:\s+class="([^"]*)")?\s*\/?>$/.exec(String(what));
    if (made) {
        return wrap([new Node(made[1], made[2])]);
    }
    if (/^#[\w-]+$/.test(String(what))) {
        return wrap([element(String(what).slice(1))]);
    }
    return wrap([]);
}
$.each = function (list, fn) {
    if (Array.isArray(list)) {
        list.forEach((v, i) => fn(i, v));
    } else {
        Object.keys(list || {}).forEach(k => fn(k, list[k]));
    }
};
$.map = function (list, fn) {
    const out = [];
    (list || []).forEach((v, i) => {
        const got = fn(v, i);
        if (got !== null && got !== undefined) {
            out.push(got);
        }
    });
    return out;
};

const asked = [];
const answers = {};
const timers = [];
const document = {};
const window = {location: {hash: ''}};
const history = {pushState() {}};

function ajaxGet(url, data, callback) {
    asked.push(['GET', url, data]);
    callback(answers[url]);
}

function ajaxCall(url, data, callback) {
    asked.push(['POST', url, data]);
    callback(answers[url]);
}

function mapDataToFormUI(map) {
    asked.push(['MAP', map]);
    return {done: fn => fn()};
}

function saveFormToEndpoint(url, form, callback) {
    asked.push(['SAVE', url, form]);
    callback();
}

function formatTokenizersUI() {
    asked.push(['TOKENIZE']);
}

function setTimeout(fn, ms) {
    timers.push([fn, ms]);
}


/* --- the page, run ----------------------------------------------------------------------------------- */

new Function('$', 'document', 'window', 'history', 'ajaxGet', 'ajaxCall', 'mapDataToFormUI', 'saveFormToEndpoint',
    'setTimeout', script)($, document, window, history, ajaxGet, ajaxCall, mapDataToFormUI, saveFormToEndpoint, setTimeout);
check('the script waits for the document', typeof ready, 'function');

function cards() {
    return element('ms-cards').children.map(c => ({
        cls: c.classes.filter(x => x !== 'xgs-card').join(' '),
        key: c.children[1].text,
        value: c.children[2].text,
        sub: c.children[3].text
    }));
}

function shown(id) {
    return element(id).shown ? element(id).text : null;
}

const STATUS = '/api/modsecurity/service/status';
answers[STATUS] = undefined;
ready();
check('the Settings form read first', asked[0], ['MAP', {frm_general: '/api/modsecurity/settings/get'}]);
check('then the status asked', asked[1], ['GET', STATUS, {}]);
check('no answer: one red card, the status could not be read', cards().map(c => [c.cls, c.key, c.value]),
    [['bad', 'Web Application Firewall', 'Its status could not be read.']]);
check('the grid on the Sites tab\'s API', [element('grid-sites').grid.search, element('grid-sites').grid.set,
    element('grid-sites').grid.toggle], ['/api/modsecurity/settings/search_sites', '/api/modsecurity/settings/set_site/',
    '/api/modsecurity/settings/toggle_site/']);
check('the grid read again with each status', element('grid-sites').reloads, 1);

function status(data) {
    answers[STATUS] = data;
    element('refreshAct').handlers.click();
}

const at = new Date(1795000000 * 1000).toLocaleString();
const base = {
    state: 'running', enabled: true, pid: 4242,
    counts: {sites: 3, enabled: 3, blocking: 1, detection: 1, tls: 1, usable: 2},
    skipped: [], ports: {http: 80, https: 443}, interfaces: [{key: 'wan', descr: 'WAN'}],
    listen: ['203.0.113.1:80', '203.0.113.1:443', '[2001:db8::1]:443'],
    gui: {ports: [80, 4443], interfaces: [{key: 'lan', descr: 'LAN'}]}, conflicts: [],
    crs: {version: '4.25.2', source: 'release', tag: 'crs-4.25.2', signed_with: 'xgs-release-key-13ed7f86.pub',
        installed_at: 1795000000, rules: 27, line: '4.25', tested: true},
    last: {at: 1795000000, status: 'ok', state: 'running', code: '', detail: '', message: 'Apache started with 2 sites', sites: 2},
    xgs: false
};

status(base);
check('running: four cards, the service green with its pid', cards(), [
    {cls: 'ok', key: 'Service', value: 'running', sub: 'pid 4242'},
    {cls: '', key: 'Sites', value: '2', sub: '1 blocking · 1 detection only'},
    {cls: '', key: 'Core Rule Set', value: '4.25.2', sub: 'signed release, xgs-release-key-13ed7f86.pub'},
    {cls: '', key: 'Listening', value: '80, 443', sub: 'WAN'}]);
check('running: the line on the firewall rule a site needs; nothing else under the cards',
    [shown('ms-firewall') !== null, shown('ms-gui'), shown('ms-skipped'), shown('ms-error')], [true, null, null, null]);
check('Settings: the Core Rule Set installed, signed, and the button to take a newer one',
    [element('ms-crs-line').text, element('ms-crs-label').text],
    ['Version 4.25.2, 27 rule files, installed ' + at + '. A signed release, its signature checked with xgs-release-key-13ed7f86.pub.',
        'Install again']);

status(Object.assign({}, base, {xgs: true}));
check('an XGS appliance: a fifth card, the sites on the host processor, phase 0\'s figures and what is not measured',
    cards()[4], {cls: '', key: 'Hardware', value: 'host processor',
        sub: 'A site behind this firewall runs on its host processor, never in hardware: measured on an XGS 3300, 148 requests ' +
            'a second one at a time through Apache and the Core Rule Set at paranoia level 1, plain HTTP - about 75 a second for ' +
            'each host core, derived from its processor time. On an XGS 136: not measured yet.'});
status(base);
check('not an XGS appliance: four cards', cards().length, 4);

status(Object.assign({}, base, {state: 'off', enabled: false, pid: null, counts: Object.assign({}, base.counts, {enabled: 0, usable: 0,
    blocking: 0, detection: 0}), interfaces: []}));
check('off: the service grey, no site published; no line on the firewall', [cards()[0], cards()[1].sub, cards()[3].sub,
    shown('ms-firewall')], [{cls: '', key: 'Service', value: 'off', sub: 'no site is published'}, 'none enabled', 'every address', null]);

status(Object.assign({}, base, {state: 'packages', pid: null}));
check('apache24 and ap24-mod_security missing: red, with the command that installs them', [cards()[0].cls, cards()[0].value,
    cards()[0].sub], ['bad', 'not installed', 'pkg install apache24 ap24-mod_security']);

status(Object.assign({}, base, {state: 'norules', pid: null, crs: null}));
check('no Core Rule Set: amber, the service and the card say where to install it', [cards()[0].cls, cards()[0].value,
    cards()[0].sub, cards()[2].cls, cards()[2].value, cards()[2].sub],
    ['warn', 'no rules', 'Install the Core Rule Set in Settings', 'warn', 'not installed', 'Install it in Settings']);
check('Settings, no Core Rule Set: said, and the button Install', [element('ms-crs-line').text.indexOf('Not installed.') === 0,
    element('ms-crs-label').text], [true, 'Install']);

status(Object.assign({}, base, {state: 'nosite', pid: null, counts: Object.assign({}, base.counts, {usable: 0}),
    skipped: [{uuid: 'u1', description: 'Shop', names: ['www.example.com'], reason: 'nohttps', detail: ''},
        {uuid: 'u2', description: 'Wiki', names: ['wiki.example.com'], reason: 'covered', detail: 'wiki.example.com'},
        {uuid: 'u3', description: '<b>x</b>', names: [], reason: 'names', detail: 'a b'}]}));
check('no site to publish: amber, and the sites card says none can be', [cards()[0].value, cards()[1].cls, cards()[1].sub],
    ['no site', 'warn', 'none can be published']);
check('each site not published, by its first name, with its reason - markup in one shown, not run', shown('ms-skipped'),
    'Not published: www.example.com (a certificate, and no HTTPS port in Settings), wiki.example.com (a host name a site before ' +
    'it takes too: wiki.example.com), <b>x</b> (a host name that is not one: a b).');
check('the line is text', element('ms-skipped').inner.indexOf('<b>') === -1, true);

const refused = {at: 1795000000, status: 'failed', code: 'config', detail: 'AH00526: Syntax error', message: 'x', sites: 0};
status(Object.assign({}, base, {state: 'failed', pid: null, last: refused}));
check('the last Apply refused, Apache not running: red, its reason in the page\'s words and Apache\'s', [cards()[0].cls,
    cards()[0].value, cards()[0].sub], ['bad', 'not running',
    'Apache refused the configuration, and runs the one before: AH00526: Syntax error']);
check('and not said twice under the cards', shown('ms-error'), null);
status(Object.assign({}, base, {last: refused}));
check('the last Apply refused, Apache running the one before: said under the cards, with its time', shown('ms-error'),
    'Apache refused the configuration, and runs the one before: AH00526: Syntax error (' + at + ')');
const codes = [['packages', '', 'apache24 and ap24-mod_security are not installed: pkg install apache24 ap24-mod_security'],
    ['norules', '', 'The Core Rule Set is not installed: Install it in Settings.'],
    ['gui', '80,443', 'The web GUI listens on a port chosen here: 80,443'],
    ['noaddress', 'wan', 'The Listen interfaces have no address now: wan'],
    ['module', 'mod_ssl.so', 'Apache has no module the configuration needs: mod_ssl.so'],
    ['certificate', 'abc', 'A site\'s certificate is not in System: Trust with its private key: abc'],
    ['start', 'AH00072: make_sock', 'Apache did not run: AH00072: make_sock'],
    ['restored', 'AH00072: make_sock', 'Apache could not run the new configuration, and runs the one before again: AH00072: make_sock'],
    ['busy', '', 'Another Apply or a Core Rule Set install is running: try again once it ends.'],
    ['write', 'disk full', 'The configuration could not be written, and Apache was left as it was: disk full'],
    ['config.xml', 'does not parse', 'config.xml could not be read, and Apache was left as it was: does not parse'],
    ['unreadable', '', 'No answer could be read.'],
    ['other', 'x', 'The settings could not be applied: its own words']];
check('each reason by its code, in the page\'s words, the detail after them; an unknown code with its message',
    codes.map(function (c) {
        status(Object.assign({}, base, {state: 'failed', pid: null, last: {status: 'failed', code: c[0], detail: c[1],
            message: 'its own words', at: 1}}));
        return cards()[0].sub;
    }), codes.map(c => c[2]));

status(Object.assign({}, base, {state: 'stopped', pid: null}));
check('on, not running: red, Apply starts it', [cards()[0].cls, cards()[0].sub], ['bad', 'Apply starts it']);
status(Object.assign({}, base, {state: 'failed', pid: null, interfaces: [{key: 'opt1', descr: 'R&amp;amp;D'}],
    last: {status: 'failed', code: 'config', detail: 'AH00526: &amp;lt;Location&amp;gt;', at: 1}}));
check('a message or a description holding an entity: shown as it is written, made plain once, not twice',
    [cards()[0].sub, cards()[3].sub], ['Apache refused the configuration, and runs the one before: AH00526: &lt;Location&gt;',
        'R&amp;D']);
status(Object.assign({}, base, {state: 'failed', pid: null, last: {status: 'failed', code: 'sameport', detail: '', at: 1}}));
check('one port for both kinds: said in the words of the model\'s own refusal', cards()[0].sub, 'HTTP and HTTPS need a port each.');

status(Object.assign({}, base, {conflicts: [{port: 443, interfaces: []}, {port: 80, interfaces: ['lan', 'opt1']}]}));
check('the web GUI on a port chosen here: the Listening card red, the line with how to move it', [cards()[3].cls, shown('ms-gui')],
    ['bad', 'The web GUI listens on a port chosen here - move it in System: Settings: Administration (another TCP port, or Listen ' +
        'interfaces without the ones chosen here), or choose another port in Settings: 443 (every interface), 80 (lan, opt1).']);

status(Object.assign({}, base, {crs: Object.assign({}, base.crs, {source: 'hand', signed_with: ''})}));
check('the Core Rule Set installed by hand: said so on its card and in Settings', [cards()[2].sub,
    element('ms-crs-line').text.split('. ').slice(-1)[0]], ['installed by hand',
    'Installed by hand from an archive: its signature was checked where it was fetched, not here.']);

status(Object.assign({}, base, {listen: ['203.0.113.1:443', '[2001:db8::1]:443']}));
check('running: the ports Apache listens on, not a port of Settings no site of its kind uses', cards()[3].value, '443');
status(Object.assign({}, base, {state: 'stopped', pid: null, listen: []}));
check('not running: the ports Settings has', cards()[3].value, '80, 443');
status(Object.assign({}, base, {interfaces: [], ports: {http: null, https: 8443}, listen: ['0.0.0.0:8443', '[::]:8443']}));
check('every address, HTTPS alone on another port', [cards()[3].value, cards()[3].sub], ['8443', 'every address']);

status({state: 'unreadable', error: {message: 'config.xml could not be read: <x>'}});
check('an answer that cannot be read: one red card with its words, as text', [cards().length, cards()[0].sub,
    element('ms-cards').inner.indexOf('<x>') === -1], [1, 'config.xml could not be read: <x>', true]);

/* Apply */
const RECONFIGURE = '/api/modsecurity/service/reconfigure';
asked.length = 0;
answers[RECONFIGURE] = {status: 'ok', state: 'running', sites: 2, current: base};
element('applyAct').handlers.click();
check('Settings\' Apply: saved, then applied', asked.slice(0, 2).map(x => x[0] + ' ' + x[1]),
    ['SAVE /api/modsecurity/settings/set', 'POST ' + RECONFIGURE]);
check('said under Settings; the cards drawn from its answer', [shown('ms-result'), element('ms-result').attrs.class,
    cards()[0].value], ['Applied. Sites published: 2.', 'text-muted', 'running']);
asked.length = 0;
answers[RECONFIGURE] = {status: 'failed', code: 'gui', detail: '443', message: 'x',
    current: Object.assign({}, base, {conflicts: [{port: 443, interfaces: []}]})};
element('applySitesAct').handlers.click();
check('Sites\' Apply: not saved again, applied', asked.map(x => x[0] + ' ' + x[1]), ['POST ' + RECONFIGURE]);
check('refused: said in red under Sites, in the page\'s words', [shown('ms-sites-result'), element('ms-sites-result').attrs.class],
    ['The web GUI listens on a port chosen here: 443', 'text-danger']);
answers[RECONFIGURE] = {status: 'ok', state: 'off', current: Object.assign({}, base, {state: 'off', enabled: false})};
element('applySitesAct').handlers.click();
check('applied off: said', shown('ms-sites-result'), 'Applied: the Web Application Firewall is off.');
answers[RECONFIGURE] = {status: 'ok', state: 'nosite', current: base};
element('applySitesAct').handlers.click();
check('applied with no site: said', shown('ms-sites-result'), 'Applied: no site can be published, so Apache is stopped.');
answers[RECONFIGURE] = undefined;
element('applySitesAct').handlers.click();
check('no answer: said', shown('ms-sites-result'), 'No answer could be read.');

/* the Core Rule Set's install */
const INSTALL = '/api/modsecurity/service/crsinstall';
answers[INSTALL] = {status: 'installed', version: '4.25.3', apply: {status: 'ok', state: 'running', sites: 2}, current: base};
element('crsInstallAct').handlers.click();
check('Install: the newest release, then Apply - both said', [asked.slice(-1)[0][1], shown('ms-crs-result'),
    element('ms-crs-result').attrs.class], [INSTALL, 'The Core Rule Set 4.25.3 is installed. Applied. Sites published: 2.', 'text-muted']);
answers[INSTALL] = {status: 'current', version: '4.25.2', current: base};
element('crsInstallAct').handlers.click();
check('Install with nothing newer: said', shown('ms-crs-result'), 'The Core Rule Set 4.25.2 is the newest of its line, and installed.');
answers[INSTALL] = {status: 'failed', message: 'crs-4.25.3 is not signed yet: it has no crs.json.sig', current: base};
element('crsInstallAct').handlers.click();
check('Install refused with a code the page has not: said in red with crs.py\'s words', [shown('ms-crs-result'),
    element('ms-crs-result').attrs.class], ['The Core Rule Set was not installed: crs-4.25.3 is not signed yet: it has no crs.json.sig',
    'text-danger']);
const crsCodes = [
    [{code: 'none', line: '4.25'}, 'No release of the Core Rule Set\'s 4.25 line is published for this plugin yet.'],
    [{code: 'unsigned', detail: 'crs-4.25.3: crs.json.sig'}, 'The newest release is not signed yet: crs-4.25.3: crs.json.sig'],
    [{code: 'badsig', detail: 'crs-4.25.3'}, 'The release\'s signature does not verify with a release key of this firewall: crs-4.25.3'],
    [{code: 'nokeys', detail: 'crs-4.25.3'}, 'This firewall holds no release key to check a release with: crs-4.25.3'],
    [{code: 'manifest', detail: 'crs-4.25.3: size'}, 'The release\'s signed manifest is not one this firewall takes: crs-4.25.3: size'],
    [{code: 'unlisted', detail: 'no reference'}, 'The list of this plugin\'s releases could not be read: no reference'],
    [{code: 'unreachable', detail: '[Errno 8] hostname nor servname'}, 'GitHub could not be reached: [Errno 8] hostname nor servname'],
    [{code: 'mismatch', detail: 'crs-4.25.3: 10 / 12'}, 'The archive is not the one signed: crs-4.25.3: 10 / 12'],
    [{code: 'archive', detail: 'coreruleset-4.25.3/../x'}, 'The archive is not one this firewall installs: coreruleset-4.25.3/../x'],
    [{code: 'refused', detail: 'AH00526: <x>'}, 'Apache refused the configuration with this Core Rule Set, so the one before stays in use: AH00526: <x>'],
    [{code: 'write', detail: 'No space left on device'}, 'The Core Rule Set could not be written: No space left on device'],
    [{code: 'busy'}, 'Another Apply or a Core Rule Set install is running: try again once it ends.'],
    [{code: 'unreadable', message: 'No answer could be read.'}, 'No answer could be read.']];
check('each refusal of Install by crs.py\'s code, in the page\'s words, its detail after them as text', crsCodes.map(function (c) {
    answers[INSTALL] = Object.assign({status: 'failed', message: 'its own words', current: base}, c[0]);
    element('crsInstallAct').handlers.click();
    return [shown('ms-crs-result'), element('ms-crs-result').inner.indexOf('<x>') === -1];
}), crsCodes.map(c => [c[1], true]));
answers[INSTALL] = {status: 'installed', version: '4.25.3', apply: {status: 'failed', code: 'config', detail: 'AH00526'}, current: base};
element('crsInstallAct').handlers.click();
check('installed, and Apply refused: both said, in red', [shown('ms-crs-result'), element('ms-crs-result').attrs.class],
    ['The Core Rule Set 4.25.3 is installed. Apache refused the configuration, and runs the one before: AH00526', 'text-danger']);

/* the grid's columns */
const formatters = element('grid-sites').grid.options.formatters;
check('host names: each one, left to right', formatters.hostnames(null, {hostnames: 'www.example.com,example.com'}),
    '<span dir="ltr">www.example.com, example.com</span>');
check('a certificate: HTTPS and its name; none: plain HTTP', [formatters.certificate(null, {certificate: 'www'}),
    formatters.certificate(null, {certificate: ''})], ['HTTPS <span class="text-muted">www</span>',
    '<span class="text-muted">plain HTTP</span>']);
check('the backend, left to right', formatters.backend(null, {backend: 'http://192.0.2.10:8080'}),
    '<span dir="ltr">http://192.0.2.10:8080</span>');

/* the template around the script */
check('the page kit\'s blocks', [volt.indexOf('KIT-CSS-BEGIN') > 0, volt.indexOf('KIT-JS-BEGIN') > 0], [true, true]);
check('the dialog and the credit', [volt.indexOf('\'fields\': formDialogSite, \'id\': \'DialogSite\'') > 0,
    volt.indexOf('partial("OPNsense/ModSecurity/credit")') > 0], [true, true]);

console.log(failed ? failed + ' of ' + checks + ' checks failed' : checks + ' checks passed');
process.exit(failed ? 1 : 0);
