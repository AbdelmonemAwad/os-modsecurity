{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Services: Web Application Firewall (XGS: Web Application Firewall when os-xgs-npu is installed) - the
 # sites published through this firewall, each received here, inspected by ModSecurity with the OWASP Core
 # Rule Set and passed to its backend: four cards, a fifth on an XGS appliance, the lines under them, the
 # Sites tab and Settings, with the Core Rule Set's install.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes the
       difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #grid-sites .tabulator-tableholder { overflow-x: hidden; }
    }
    .ms-lines { padding: 0 0 10px; }
    .ms-lines > div { margin-top: 2px; }
    .ms-foot { padding: 0 15px 15px; }
    .ms-crs { padding: 0 15px 15px; }
    .ms-crs > div { margin-bottom: 8px; }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        /* the service's card, by status.py's state: [class, value, sub-line] */
        const states = {
            'off': ['', "{{ lang._('off') }}", "{{ lang._('no site is published') }}"],
            'packages': ['bad', "{{ lang._('not installed') }}", "{{ lang._('pkg install apache24 ap24-mod_security') }}"],
            'norules': ['warn', "{{ lang._('no rules') }}", "{{ lang._('Install the Core Rule Set in Settings') }}"],
            'nosite': ['warn', "{{ lang._('no site') }}", "{{ lang._('Add one in Sites, then Apply') }}"],
            'failed': ['bad', "{{ lang._('not running') }}", ''],
            'stopped': ['bad', "{{ lang._('not running') }}", "{{ lang._('Apply starts it') }}"],
            'running': ['ok', "{{ lang._('running') }}", '']
        };

        /* why an Apply was refused, by setup.py's code, in the page's language; its detail after it */
        const failures = {
            'packages': "{{ lang._('apache24 and ap24-mod_security are not installed: pkg install apache24 ap24-mod_security') }}",
            'norules': "{{ lang._('The Core Rule Set is not installed: Install it in Settings.') }}",
            'gui': "{{ lang._('The web GUI listens on a port chosen here:') }}",
            'noaddress': "{{ lang._('The Listen interfaces have no address now:') }}",
            'module': "{{ lang._('Apache has no module the configuration needs:') }}",
            'certificate': "{{ lang._('A site\'s certificate is not in System: Trust with its private key:') }}",
            'config': "{{ lang._('Apache refused the configuration, and runs the one before:') }}",
            'restored': "{{ lang._('Apache could not run the new configuration, and runs the one before again:') }}",
            'start': "{{ lang._('Apache did not run:') }}"
        };

        function failure(last) {
            if (!last || !last.code) {
                return '';
            }
            const text = failures[last.code];
            if (text === undefined) {
                return plain("{{ lang._('The settings could not be applied:') }}") + ' ' + plain(last.message);
            }
            return plain(text) + (last.detail ? ' ' + plain(last.detail) : '');
        }

        /* why a site is not published: common.check_sites' reason */
        const reasons = {
            'names': "{{ lang._('a host name that is not one') }}",
            'duplicate': "{{ lang._('a host name of a site before it') }}",
            'covered': "{{ lang._('a host name a site before it takes too') }}",
            'backend': "{{ lang._('a backend that is not a URL to pass requests to') }}",
            'certificate': "{{ lang._('its certificate is not in System: Trust with its private key') }}",
            'nohttps': "{{ lang._('a certificate, and no HTTPS port in Settings') }}",
            'nohttp': "{{ lang._('no certificate, and no HTTP port in Settings') }}",
            'many': "{{ lang._('more sites than one Apache is given') }}"
        };

        function count(n) {
            return n === null || n === undefined || n === '' ? '-' : Number(n).toLocaleString();
        }

        function when(ts) {
            return ts ? new Date(ts * 1000).toLocaleString() : '-';
        }

        /* the interfaces by their descriptions, or every address */
        function where(list) {
            return list && list.length ? $.map(list, function (i) {
                return plain(i.descr);
            }).join(', ') : plain("{{ lang._('every address') }}");
        }

        /* One quiet line: the text, then the list, plain, as text */
        function line(id, text, items) {
            const $line = $(id);
            if (!items.length) {
                $line.hide().text('');
                return;
            }
            $line.text(plain(text) + ' ' + items.join(', ') + '.').show();
        }

        let current = null;

        /*
         * Four cards: the service, the sites, the Core Rule Set and where Apache listens. A fifth on an XGS
         * appliance (settled point 9a): a site behind this firewall runs on its host processor, never in
         * the coprocessor, as phase 0 measured.
         */
        function draw(data) {
            current = data;
            const $cards = $('#ms-cards').empty();
            if (!data || !data.state || data.state === 'unreadable') {
                $cards.append(card('bad', 'fa-shield', "{{ lang._('Web Application Firewall') }}",
                    "{{ lang._('Its status could not be read.') }}", data && data.error ? data.error.message : ''));
                $.each(['#ms-gui', '#ms-skipped', '#ms-error', '#ms-firewall'], function (i, id) {
                    $(id).hide();
                });
                crs_line(null);
                return;
            }
            const c = data.counts || {};
            const state = states[data.state] || states.stopped;
            let sub = state[2];
            if (data.state === 'running') {
                sub = plain("{{ lang._('pid %s') }}").replace('%s', String(data.pid));
            } else if (data.state === 'failed') {
                sub = failure(data.last);
            }
            $cards.append(card(state[0], 'fa-shield', "{{ lang._('Service') }}", state[1], sub));

            $cards.append(card(data.enabled && !c.usable ? 'warn' : '', 'fa-globe', "{{ lang._('Sites') }}", count(c.usable),
                c.usable ? plain("{{ lang._('%s blocking') }}").replace('%s', count(c.blocking)) + ' · ' +
                    plain("{{ lang._('%s detection only') }}").replace('%s', count(c.detection)) :
                    plain(c.enabled ? "{{ lang._('none can be published') }}" : "{{ lang._('none enabled') }}")));

            const crs = data.crs;
            $cards.append(card(crs ? '' : (data.enabled ? 'warn' : ''), 'fa-list-ol', "{{ lang._('Core Rule Set') }}",
                crs ? crs.version : "{{ lang._('not installed') }}",
                crs ? (crs.source === 'release' ? plain("{{ lang._('signed release, %s') }}").replace('%s', plain(crs.signed_with)) :
                    plain("{{ lang._('installed by hand') }}")) : "{{ lang._('Install it in Settings') }}"));

            const ports = $.map([data.ports.http, data.ports.https], function (p) {
                return p ? String(p) : null;
            });
            const conflicts = data.conflicts || [];
            $cards.append(card(conflicts.length ? 'bad' : '', 'fa-plug', "{{ lang._('Listening') }}",
                ports.length ? ports.join(', ') : '-', where(data.interfaces)));

            if (data.xgs) {
                $cards.append(card('', 'fa-microchip', "{{ lang._('Hardware') }}", "{{ lang._('host processor') }}",
                    "{{ lang._('A site behind this firewall runs on its host processor, never in hardware: measured on an XGS 3300, 148 requests a second one at a time through Apache and the Core Rule Set at paranoia level 1, plain HTTP - about 75 a second for each host core, derived from its processor time. On an XGS 136: not measured yet.') }}"));
            }

            $('#ms-firewall').toggle(!!data.enabled);
            line('#ms-gui', "{{ lang._('The web GUI listens on a port chosen here - move it in System: Settings: Administration (another TCP port, or Listen interfaces without the ones chosen here), or choose another port in Settings:') }}",
                $.map(conflicts, function (x) {
                    return String(x.port) + ' (' + (x.interfaces && x.interfaces.length ? $.map(x.interfaces, plain).join(', ') :
                        plain("{{ lang._('every interface') }}")) + ')';
                }));
            line('#ms-skipped', "{{ lang._('Not published:') }}", $.map(data.skipped || [], function (s) {
                const name = s.names && s.names.length ? plain(s.names[0]) : plain(s.description || s.uuid);
                return name + ' (' + plain(reasons[s.reason] || s.reason) + (s.detail ? ': ' + plain(s.detail) : '') + ')';
            }));
            const last = data.last;
            if (data.enabled && last && last.status === 'failed' && data.state !== 'failed') {
                $('#ms-error').text(failure(last) + ' (' + when(last.at) + ')').show();
            } else {
                $('#ms-error').hide().text('');
            }
            crs_line(data);
        }

        /* Settings' Core Rule Set line, and its button: Install, or Install again for a newer release */
        function crs_line(data) {
            const crs = data ? data.crs : null;
            if (!crs) {
                $('#ms-crs-line').text(plain("{{ lang._('Not installed. Install takes the newest release of the 4.25 line, as this project republished it signed once its own signature was checked.') }}"));
                $('#ms-crs-label').text(plain("{{ lang._('Install') }}"));
                return;
            }
            $('#ms-crs-line').text(plain("{{ lang._('Version %s, %s rule files, installed %s.') }}")
                .replace('%s', plain(crs.version)).replace('%s', count(crs.rules)).replace('%s', when(crs.installed_at)) + ' ' +
                (crs.source === 'release' ? plain("{{ lang._('A signed release, its signature checked with %s.') }}").replace('%s', plain(crs.signed_with)) :
                    plain("{{ lang._('Installed by hand from an archive: its signature was checked where it was fetched, not here.') }}")));
            $('#ms-crs-label').text(plain("{{ lang._('Install again') }}"));
        }

        function refresh() {
            ajaxGet('/api/modsecurity/service/status', {}, function (data) {
                draw(data);
                $('#grid-sites').bootgrid('reload');
            });
        }

        /* what an Apply did, under the button that asked for it */
        function said(data) {
            if (!data || data.status === undefined) {
                return [false, plain("{{ lang._('No answer could be read.') }}")];
            }
            if (data.status !== 'ok') {
                return [false, failure(data) || plain(data.message)];
            }
            if (data.state === 'off') {
                return [true, plain("{{ lang._('Applied: the Web Application Firewall is off.') }}")];
            }
            if (data.state === 'nosite') {
                return [true, plain("{{ lang._('Applied: no site can be published, so Apache is stopped.') }}")];
            }
            return [true, plain("{{ lang._('Applied. Sites published: %s.') }}").replace('%s', count(data.sites))];
        }

        function apply($button, $progress, $result, save) {
            $button.prop('disabled', true);
            $progress.addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            const go = function () {
                ajaxCall('/api/modsecurity/service/reconfigure', {}, function (data) {
                    done();
                    const result = said(data);
                    $result.attr('class', result[0] ? 'text-muted' : 'text-danger').text(result[1]).show();
                    if (data && data.current) {
                        draw(data.current);
                    }
                    $('#grid-sites').bootgrid('reload');
                });
            };
            if (save) {
                saveFormToEndpoint('/api/modsecurity/settings/set', 'frm_general', go, false, done);
            } else {
                go();
            }
        }

        /* The grid's rows are built by the API controller; the API escapes what it returns, so nothing here
           escapes it again. */
        $('#grid-sites').UIBootgrid({
            search: '/api/modsecurity/settings/search_sites',
            get: '/api/modsecurity/settings/get_site/',
            set: '/api/modsecurity/settings/set_site/',
            add: '/api/modsecurity/settings/add_site/',
            del: '/api/modsecurity/settings/del_site/',
            toggle: '/api/modsecurity/settings/toggle_site/',
            options: {
                formatters: {
                    hostnames: function (column, row) {
                        return '<span dir="ltr">' + String(row.hostnames || '').split(',').join(', ') + '</span>';
                    },
                    backend: function (column, row) {
                        return '<span dir="ltr">' + row.backend + '</span>';
                    },
                    certificate: function (column, row) {
                        return row.certificate ? 'HTTPS <span class="text-muted">' + row.certificate + '</span>' :
                            '<span class="text-muted">' + "{{ lang._('plain HTTP') }}" + '</span>';
                    }
                }
            }
        });

        $('#refreshAct').click(function () {
            refresh();
        });

        mapDataToFormUI({'frm_general': '/api/modsecurity/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });
        $('#applyAct').click(function () {
            apply($(this), $('#frm_general_progress'), $('#ms-result'), true);
        });
        $('#applySitesAct').click(function () {
            apply($(this), $('#ms-sites-progress'), $('#ms-sites-result'), false);
        });
        $('#crsInstallAct').click(function () {
            const $button = $(this).prop('disabled', true);
            $('#ms-crs-progress').addClass('fa fa-spinner fa-pulse');
            ajaxCall('/api/modsecurity/service/crsinstall', {}, function (data) {
                $('#ms-crs-progress').removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
                let text = plain("{{ lang._('No answer could be read.') }}");
                let good = false;
                if (data && data.status === 'installed') {
                    good = true;
                    text = plain("{{ lang._('The Core Rule Set %s is installed.') }}").replace('%s', plain(data.version));
                    if (data.apply) {
                        const applied = said(data.apply);
                        good = applied[0];
                        text += ' ' + applied[1];
                    }
                } else if (data && data.status === 'current') {
                    good = true;
                    text = plain("{{ lang._('The Core Rule Set %s is the newest of its line, and installed.') }}").replace('%s', plain(data.version));
                } else if (data && data.message) {
                    text = plain("{{ lang._('The Core Rule Set was not installed:') }}") + ' ' + plain(data.message);
                }
                $('#ms-crs-result').attr('class', good ? 'text-muted' : 'text-danger').text(text).show();
                if (data && data.current) {
                    draw(data.current);
                }
            });
        });

        cards_wait('#ms-cards', ["{{ lang._('Service') }}", "{{ lang._('Sites') }}", "{{ lang._('Core Rule Set') }}",
            "{{ lang._('Listening') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="ms-cards"></div>
<div class="text-muted clearfix ms-lines">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    <div>{{ lang._('Each site is published here: its requests end on this firewall, ModSecurity inspects them with the OWASP Core Rule Set, and Apache passes them on to the site\'s backend. A site reached through a port forward instead never meets these rules.') }}</div>
    <div id="ms-firewall" style="display: none;">{{ lang._('A site reached from another network needs a rule on that interface passing its port to This Firewall (Firewall: Rules): none is made here.') }}</div>
    <div id="ms-gui" class="text-danger" style="display: none;"></div>
    <div id="ms-skipped" class="text-warning" style="display: none;"></div>
    <div id="ms-error" class="text-warning" style="display: none;"></div>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#sites">{{ lang._('Sites') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="sites" class="tab-pane active">
        <table id="grid-sites" class="table table-condensed table-hover table-striped" data-editDialog="DialogSite">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="boolean" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="hostnames" data-type="string" data-formatter="hostnames">{{ lang._('Host names') }}</th>
                    <th data-column-id="backend" data-type="string" data-formatter="backend">{{ lang._('Backend') }}</th>
                    <th data-column-id="certificate" data-type="string" data-formatter="certificate">{{ lang._('Certificate') }}</th>
                    <th data-column-id="mode" data-type="string">{{ lang._('Mode') }}</th>
                    <th data-column-id="paranoia" data-width="7em" data-type="string">{{ lang._('Paranoia level') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div class="text-muted ms-foot">
            {{ lang._('A new site is in Detection only: what the rules find is logged and the request passes. Blocking refuses an attack with 403. Changes here are put into use with Apply.') }}
        </div>
        <div class="ms-foot">
            <button id="applySitesAct" class="btn btn-primary" type="button"><b>{{ lang._('Apply') }}</b> <i id="ms-sites-progress"></i></button>
            <div id="ms-sites-result" style="display: none; padding-top: 10px;"></div>
        </div>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="ms-result" style="display: none;"></div></div>
        <div class="ms-crs">
            <div class="xgs-head">{{ lang._('Core Rule Set') }}</div>
            <div id="ms-crs-line" class="text-muted"></div>
            <div>
                <button id="crsInstallAct" class="btn btn-default" type="button"><b id="ms-crs-label">{{ lang._('Install') }}</b> <i id="ms-crs-progress"></i></button>
            </div>
            <div id="ms-crs-result" style="display: none;"></div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogSite, 'id': 'DialogSite', 'label': lang._('Edit site')]) }}
{{ partial("OPNsense/ModSecurity/credit") }}
