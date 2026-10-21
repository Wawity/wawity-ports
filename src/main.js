import './style.css';
import { createElement, EthernetPort, ArrowRight, RefreshCw, ShieldCheck, Router, X, Minus, Square, Trash2, ChevronLeft, ChevronRight, Info, Github, Globe, Download, Check, Copy, FileText, ScanLine, Repeat } from 'lucide';
import { t, getLang, setLang, locale } from './i18n.js';

const iconSet = { ports: EthernetPort, arrow: ArrowRight, refresh: RefreshCw, shield: ShieldCheck, router: Router, close: X, minus: Minus, square: Square, trash: Trash2, left: ChevronLeft, right: ChevronRight, info: Info, github: Github, globe: Globe, download: Download, check: Check, copy: Copy, file: FileText, scan: ScanLine, rebind: Repeat };
const icon = (name) => createElement(iconSet[name], { 'stroke-width': 1.7, 'aria-hidden': 'true' }).outerHTML;
const native = window.__TAURI__;
let busy = false;
let rules = [];
let page = 0;
let resultTimer;
let fullResult = '';
let checkResults = [];
let checkPage = 0;
const pageSize = 1;

document.querySelector('#app').innerHTML = `
  <header class="titlebar" data-tauri-drag-region>
    <img class="app-icon" src="/wawity.ico" alt="" data-tauri-drag-region />
    <span class="title-wordmark" data-tauri-drag-region>wawity <span>ports</span></span>
    <div class="window-controls">
      <button id="minimize" aria-label="${t('win.minimize')}">${icon('minus')}</button>
      <button id="maximize" aria-label="${t('win.maximize')}">${icon('square')}</button>
      <button id="close" aria-label="${t('win.close')}">${icon('close')}</button>
    </div>
  </header>
  <div class="shell">
    <aside class="rail">
      <button class="nav-item active" id="nav-ports" aria-current="page" title="${t('nav.ports')}">${icon('ports')}<span>${t('nav.ports')}</span></button>
      <button class="nav-item" id="nav-check" title="${t('nav.check')}">${icon('scan')}<span>${t('nav.check')}</span></button>
      <button class="nav-item" id="nav-network" title="${t('nav.network')}">${icon('globe')}<span>${t('nav.network')}</span></button>
      <button class="nav-item" id="nav-about" title="${t('nav.about')}">${icon('info')}<span>${t('nav.about')}</span></button>
      <div class="rail-bottom"><button id="last-result" class="text-button" hidden>${icon('file')}${t('side.lastResult')}</button><div id="vpn-thanks" class="vpn-thanks" hidden><img class="vpn-w" src="/wawity.ico" alt=""><span>${t('side.vpnThanks')}<strong>${t('side.vpnThanksStrong')}</strong></span></div><div class="sidebar-note">${icon('shield')}<span>${t('side.note1')}<br>${t('side.note2')}</span></div><span class="version">Wawity Ports v0.2.0</span></div>
    </aside>
    <main id="ports-view">
      <div class="page-heading"><div><h1>${t('nav.ports')}</h1><p>${t('ports.subtitle')}</p></div><span id="admin" class="badge">${t('badge.check')}</span></div>
      <section class="workspace" aria-label="Wawity Ports">
        <form id="port-form">
          <label class="field-label" for="ports">${t('ports.label')}</label>
          <input id="ports" name="ports" placeholder="25565" autocomplete="off" spellcheck="false" maxlength="250" required aria-describedby="ports-help" />
          <p id="ports-help" class="hint">${t('ports.hint')}</p>
          <fieldset class="protocol"><legend>${t('ports.protocol')}</legend><div class="segments">
            <label><input type="radio" name="protocol" value="TCP" checked /><span>TCP</span></label>
            <label><input type="radio" name="protocol" value="UDP" /><span>UDP</span></label>
            <label><input type="radio" name="protocol" value="BOTH" /><span>TCP + UDP</span></label>
          </div></fieldset>
          <label class="toggle-row"><span>${icon('router')}<span><strong>${t('ports.router')}</strong><small>${t('ports.routerSmall')}</small></span></span><input id="router" type="checkbox" checked /><span class="check-control" aria-hidden="true">${icon('check')}</span></label>
          <label class="toggle-row"><span>${icon('refresh')}<span><strong>${t('ports.renew')}</strong><small>${t('ports.renewSmall')}</small></span></span><input id="auto-renew" type="checkbox" checked /><span class="check-control" aria-hidden="true">${icon('check')}</span></label>
          <label class="toggle-row"><span>${icon('rebind')}<span><strong>${t('ports.rebind')}</strong><small>${t('ports.rebindSmall')}</small></span></span><input id="rebind" type="checkbox" /><span class="check-control" aria-hidden="true">${icon('check')}</span></label>
          <label class="toggle-row public-row"><span>${icon('shield')}<span><strong>${t('ports.public')}</strong><small>${t('ports.publicSmall')}</small></span></span><input id="public" type="checkbox" /><span class="check-control" aria-hidden="true">${icon('check')}</span></label>
          <button class="primary" id="open" type="submit"><span>${t('ports.open')}</span>${icon('arrow')}</button>
        </form>
        <div class="explanation"><div class="connection-path"><div class="path-node">${icon('ports')}<span>${t('path.app')}</span></div><div class="path-line"></div><div class="path-node">${icon('shield')}<span>Windows</span></div><div class="path-line"></div><div class="path-node">${icon('router')}<span>${t('path.router')}</span></div></div>
          <h2>${t('ports.explainTitle')}</h2>
          <p>${t('ports.explain')}</p>
          <div class="note"><strong>${t('ports.leaseTitle')}</strong><p>${t('ports.leaseText1')}</p><p>${t('ports.leaseText2')}</p></div>
          <div id="vpn-warning" class="vpn-warning" hidden role="status"></div>
        </div>
      </section>
      <section class="rules-section"><div class="section-heading"><h2>${t('ports.rules')} <span id="count">0</span></h2><button id="refresh" class="text-button">${icon('refresh')}${t('ports.refresh')}</button></div>
        <div id="rules" aria-live="polite"></div>
        <div class="pagination" id="pagination" hidden><button id="prev" aria-label="${t('aria.prevRules')}">${icon('left')}</button><span id="page-label"></span><button id="next" aria-label="${t('aria.nextRules')}">${icon('right')}</button></div>
      </section>
      <footer>${t('ports.footer')}<span>${t('ports.footerNote')}</span></footer>
    </main>
    <main id="check-view" hidden>
      <div class="page-heading"><div><h1>${t('nav.check')}</h1><p>${t('check.subtitle')}</p></div></div>
      <section class="check-workspace">
        <form id="check-form">
          <label class="field-label" for="check-ports">${t('check.label')}</label><input id="check-ports" class="port-input" placeholder="25565" maxlength="120" autocomplete="off" required />
          <p class="hint">${t('check.hint')}</p>
          <fieldset><legend>${t('ports.protocol')}</legend><div class="segments"><label><input type="radio" name="check-protocol" value="TCP" checked /><span>TCP</span></label><label><input type="radio" name="check-protocol" value="UDP" /><span>UDP</span></label><label><input type="radio" name="check-protocol" value="BOTH" /><span>TCP + UDP</span></label></div></fieldset>
          <label class="toggle-row"><span>${icon('globe')}<span><strong>${t('check.external')}</strong><small>${t('check.externalSmall')}</small></span></span><input id="external-check" type="checkbox" checked /><span class="check-control" aria-hidden="true">${icon('check')}</span></label>
          <label class="toggle-row" id="test-server-row"><span>${icon('ports')}<span><strong>${t('check.testServer')}</strong><small>${t('check.testServerSmall')}</small></span></span><input id="test-server" type="checkbox" /><span class="check-control" aria-hidden="true">${icon('check')}</span></label>
          <button id="check-submit" class="primary" type="submit"><span>${t('check.submit')}</span>${icon('scan')}</button>
        </form>
        <div class="check-explanation"><div id="check-intro"><h2>${t('check.introTitle')}</h2><p>${t('check.introText1')}</p><p>${t('check.introText2')}</p><div class="note"><strong>${t('check.noteTitle')}</strong><p>${t('check.noteText1')}</p><p>${t('check.noteText2')}</p></div></div>
          <section id="check-summary" class="check-summary" hidden aria-live="polite">
            <div class="summary-heading"><h2>${t('check.summary')}</h2><span id="check-time"></span></div>
            <div id="verdict" class="verdict"><div id="verdict-icon"></div><span id="verdict-port"></span><h3 id="verdict-title"></h3><p id="verdict-detail"></p></div>
            <div class="verdict-pages" id="verdict-pages" hidden><button id="verdict-prev" aria-label="${t('aria.prevVerdict')}">${icon('left')}</button><span id="verdict-page"></span><button id="verdict-next" aria-label="${t('aria.nextVerdict')}">${icon('right')}</button></div>
            <button id="check-details" class="text-button">${icon('file')}${t('check.details')}</button>
          </section>
        </div>
      </section>
      <div class="check-tip">${icon('info')}<p>${t('check.tip')}</p></div>
      <footer>${t('check.footer')}<span>TCP / UDP</span></footer>
    </main>
    <main id="network-view" hidden>
      <div class="page-heading"><div><h1>${t('nav.network')}</h1><p>${t('net.subtitle')}</p></div></div>
      <section class="network-options"><label class="toggle-row"><span>${icon('router')}<span><strong>${t('net.natpmp')}</strong><small>${t('net.natpmpSmall')}</small></span></span><input id="allow-nat-pmp" type="checkbox" /><span class="check-control" aria-hidden="true">${icon('check')}</span></label><p class="hint">${t('net.natpmpHint')}</p></section>
      <button id="network-scan" class="primary"><span>${t('net.scan')}</span>${icon('scan')}</button>
      <div id="network-status" class="network-status" aria-live="polite"><p>${t('net.statusHint')}</p></div>
      <footer>${t('net.footer')}<span>${t('net.footerNote')}</span></footer>
    </main>
    <main id="about-view" hidden>
      <div class="page-heading"><div><h1>${t('nav.about')}</h1><p>${t('about.subtitle')}</p></div><span class="badge">Ports v0.2.0</span></div>
      <section class="about-brand"><img src="/wawity.ico" alt="" /><div><h2>wawity<span>.</span></h2><p>${t('about.tagline')}</p></div></section>
      <p class="about-copy">${t('about.copy')}</p>
      <section class="beta-notice"><p class="beta-label">beta · telemetry</p><p class="beta-title">${t('beta.title')}</p><p class="beta-text">${t('beta.text')}</p></section>
      <fieldset class="lang-picker" aria-label="${t('about.language')}"><legend>${t('about.language')}</legend><label class="toggle-row"><span>${icon('globe')}<span><strong>English</strong></span></span><input type="radio" name="app-lang" value="en" ${getLang() === 'en' ? 'checked' : ''} /><span class="check-control" aria-hidden="true">${icon('check')}</span></label><label class="toggle-row"><span>${icon('globe')}<span><strong>Russian</strong></span></span><input type="radio" name="app-lang" value="ru" ${getLang() === 'ru' ? 'checked' : ''} /><span class="check-control" aria-hidden="true">${icon('check')}</span></label></fieldset>
      <section class="vpn-promo"><div class="promo-heading">${icon('shield')}<h2>${t('about.promoTitle')}</h2></div><p>${t('about.promo')}</p><button class="primary external-link" data-url="https://github.com/Wawity/wawity-desktop/releases"><span>${t('about.promoButton')}</span>${icon('download')}</button><small>${t('about.promoSmall')}</small></section>
      <div class="about-links"><button class="external-link" data-url="https://wawity.lol">${icon('globe')}<span>wawity.lol</span>${icon('arrow')}</button><button class="external-link" data-url="https://github.com/Wawity/wawity-desktop">${icon('github')}<span>${t('about.github')}</span>${icon('arrow')}</button></div>
      <footer>Wawity Ports v0.2.0<span>Windows / Portable</span></footer>
    </main>
  </div>
  <section id="activity" class="activity" hidden aria-live="polite"><div class="activity-heading"><div class="result-title">${icon('file')}<h2>${t('act.title')}</h2></div><button id="dismiss" aria-label="${t('aria.dismiss')}">${icon('close')}</button></div><div id="messages"></div><div class="result-actions"><button id="copy-result">${icon('copy')}<span>${t('act.copy')}</span></button><button id="open-log">${icon('file')}<span>${t('act.openLog')}</span></button><span id="result-feedback" role="status"></span></div></section>`;

const $ = (selector) => document.querySelector(selector);
let checkLogMessages = [];
function renderVerdict() {
  const result = checkResults[checkPage];
  if (!result) return;
  const reachable = ['reachable', 'verified-local'].includes(result.status);
  $('#verdict').className = `verdict ${reachable ? 'verdict-ok' : ['no-listener', 'loopback-only'].includes(result.status) ? 'verdict-blocked' : 'verdict-unknown'}`;
  $('#verdict-icon').innerHTML = icon(reachable ? 'check' : ['no-listener', 'loopback-only'].includes(result.status) ? 'close' : 'info');
  $('#verdict-port').textContent = `${result.port} / ${result.protocol}`;
  $('#verdict-title').textContent = result.title;
  $('#verdict-detail').textContent = result.detail;
  $('#verdict-pages').hidden = checkResults.length <= 1;
  $('#verdict-page').textContent = `${checkPage + 1} / ${checkResults.length}`;
  $('#verdict-prev').disabled = checkPage === 0;
  $('#verdict-next').disabled = checkPage === checkResults.length - 1;
}
function showCheckOutcome(result) {
  checkResults = result.results;
  checkPage = 0;
  checkLogMessages = [...result.results.map(item => `${item.port}/${item.protocol}: ${item.title}. ${item.detail}`), ...result.messages];
  $('#check-intro').hidden = true;
  $('#check-summary').hidden = false;
  const when = new Date(result.checkedAt * 1000);
  $('#check-time').textContent = when.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  $('#check-time').title = when.toLocaleString(locale());
  $('#check-details').disabled = false;
  renderVerdict();
}
function checkProgress(title, detail, failed = false) {
  checkResults = [];
  $('#check-intro').hidden = true;
  $('#check-summary').hidden = false;
  $('#verdict').className = 'verdict verdict-unknown';
  $('#verdict-icon').innerHTML = icon(failed ? 'info' : 'scan');
  $('#verdict-port').textContent = '';
  $('#verdict-title').textContent = title;
  $('#verdict-detail').textContent = detail;
  $('#check-time').textContent = '';
  $('#verdict-pages').hidden = true;
  $('#check-details').disabled = true;
}
$('#verdict-prev').addEventListener('click', () => { checkPage--; renderVerdict(); });
$('#verdict-next').addEventListener('click', () => { checkPage++; renderVerdict(); });
$('#check-details').addEventListener('click', () => showMessages(checkLogMessages));
for (const view of ['ports', 'check', 'network', 'about']) {
  $(`#nav-${view}`).addEventListener('click', () => {
    for (const name of ['ports', 'check', 'network', 'about']) {
      $(`#${name}-view`).hidden = name !== view;
      $(`#nav-${name}`).classList.toggle('active', name === view);
      if (name === view) $(`#nav-${name}`).setAttribute('aria-current', 'page');
      else $(`#nav-${name}`).removeAttribute('aria-current');
    }
    if (view === 'check') $('#activity').hidden = true;
  });
}
document.querySelectorAll('input[name="app-lang"]').forEach(input => input.addEventListener('change', () => {
  if (input.value !== getLang()) { setLang(input.value); location.reload(); }
}));
$('#allow-nat-pmp').addEventListener('change', () => {
  if ($('#allow-nat-pmp').checked && !window.confirm(t('confirm.natPmp'))) $('#allow-nat-pmp').checked = false;
});
$('#router').addEventListener('change', () => { if (!$('#router').checked) { $('#auto-renew').checked = false; $('#rebind').checked = false; } });
$('#auto-renew').addEventListener('change', () => { if ($('#auto-renew').checked) $('#router').checked = true; });
$('#rebind').addEventListener('change', () => { if ($('#rebind').checked) $('#router').checked = true; });
$('#network-scan').addEventListener('click', () => run(async () => {
  $('#network-status').textContent = t('net.scanning');
  try {
    const result = await native.tauri.invoke('network_diagnostics');
    $('#network-status').replaceChildren();
    const info = document.createElement('p');
    info.className = 'network-address';
    info.textContent = t('net.lan', { ip: result.localIp || t('net.notFound'), gw: result.gateway || t('net.notFound') });
    $('#network-status').append(info);
    for (const method of result.methods) {
      const row = document.createElement('div');
      row.className = 'network-method';
      const name = document.createElement('strong');
      name.textContent = method.name;
      const state = document.createElement('span');
      state.className = method.state === 'available' ? 'ok' : 'muted';
      state.textContent = method.state === 'available' ? t('net.available') : t('net.unconfirmed');
      row.title = method.detail;
      row.append(name, state);
      $('#network-status').append(row);
    }
    const ipv6 = document.createElement('p');
    ipv6.textContent = result.ipv6.length ? t('net.ipv6', { list: result.ipv6.join(', ') }) : t('net.ipv6None');
    $('#network-status').append(ipv6);
    showMessages([...result.messages, ...result.methods.map(m => `${m.name}: ${m.detail}`)]);
  } catch (error) { $('#network-status').textContent = t('net.failed'); throw error; }
}));
document.querySelectorAll('.external-link').forEach(button => button.addEventListener('click', async () => {
  const url = button.dataset.url;
  if (!native) { window.open(url, '_blank', 'noopener,noreferrer'); return; }
  try { await native.shell.open(url); }
  catch { button.title = t('link.openFailed', { url }); }
}));
let checkingVpn = false;
async function checkVpn() {
  if (!native || checkingVpn) return;
  checkingVpn = true;
  try {
    const adapters = await native.tauri.invoke('vpn_status');
    const wawity = adapters.find(name => /wawity/i.test(name));
    $('#vpn-thanks').hidden = !wawity;
    if (wawity) $('#vpn-thanks').title = t('vpn.thanksTitle', { name: wawity });
    $('#vpn-warning').hidden = adapters.length === 0;
    $('#vpn-warning').textContent = t('vpn.active', { list: adapters.join(', ') });
    $('#vpn-warning').title = adapters.join(', ');
  } catch {
    $('#vpn-warning').hidden = false;
    $('#vpn-warning').textContent = t('vpn.checkFailed');
  } finally { checkingVpn = false; }
}
function renderRules() {
  const routerLabels = { 'not-requested': t('rules.notRequested'), pending: t('rules.pending'), mapped: t('rules.mapped'), unverified: t('rules.unverified'), failed: t('rules.failed'), expired: t('rules.expired'), 'close-failed': t('rules.closeFailed') };
  const renewalLabels = { off: t('rules.renewOff'), scheduled: t('rules.renewScheduled'), retry: t('rules.renewRetry'), paused: t('rules.renewPaused'), expired: t('rules.renewExpired') };
  const pages = Math.max(1, Math.ceil(rules.length / pageSize));
  page = Math.min(page, pages - 1);
  $('#pagination').hidden = pages === 1;
  $('#page-label').textContent = `${page + 1} / ${pages}`;
  $('#prev').disabled = page === 0;
  $('#next').disabled = page === pages - 1;
  $('#count').textContent = rules.length;
  $('#rules').replaceChildren();
  if (!rules.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.innerHTML = `${icon('ports')}<div><strong>${t('rules.emptyTitle')}</strong><p>${t('rules.emptyText')}</p></div>`;
    $('#rules').append(empty);
    return;
  }
  const table = document.createElement('table');
  table.innerHTML = `<thead><tr><th>${t('rules.thPort')}</th><th>Windows</th><th>${t('rules.thRouter')}</th><th><span class="sr-only">${t('rules.thAction')}</span></th></tr></thead>`;
  const body = document.createElement('tbody');
  for (const rule of rules.slice(page * pageSize, (page + 1) * pageSize)) {
    const row = document.createElement('tr');
    const port = document.createElement('td');
    port.className = 'port-number';
    port.textContent = rule.port;
    const protocol = document.createElement('span');
    protocol.className = 'protocol-label';
    protocol.textContent = rule.protocol;
    port.append(protocol);
    const firewall = document.createElement('td');
    firewall.className = rule.firewall ? 'ok' : 'warning';
    firewall.textContent = rule.firewall ? t('rules.allowed') : t('rules.notAllowed');
    const router = document.createElement('td');
    router.className = rule.router === 'mapped' ? 'ok' : ['failed', 'expired', 'close-failed'].includes(rule.router) ? 'warning' : 'muted';
    router.textContent = rule.router === 'mapped' ? t('rules.accepted') : routerLabels[rule.router] || rule.router;
    const lease = document.createElement('small');
    const remaining = rule.expiresAt ? Math.max(0, Math.ceil((rule.expiresAt - Date.now() / 1000) / 60)) : null;
    lease.textContent = `${rule.method || t('rules.fallbackMethod')}${remaining === null ? '' : ` / ${remaining} ${t('rules.min')}`}`;
    lease.title = `${rule.externalIp || ''}\n${renewalLabels[rule.renewalState] || ''}${rule.lastError ? `\n${rule.lastError}` : ''}`;
    router.append(lease);
    const renewal = document.createElement('small');
    renewal.textContent = renewalLabels[rule.renewalState] || t('rules.renewOff');
    renewal.title = rule.lastError || '';
    router.append(renewal);
    if (rule.autoRenew && ['retry', 'paused', 'expired'].includes(rule.renewalState)) router.className = 'warning';
    const action = document.createElement('td');
    if (rule.method && rule.expiresAt) {
      const verb = t(rule.autoRenew ? 'rules.stop' : 'rules.enable');
      const renew = document.createElement('button');
      renew.className = `renew-rule${rule.autoRenew ? ' enabled' : ''}`;
      renew.innerHTML = icon('refresh');
      renew.title = `${verb} ${t('rules.renewWord')}. ${renewalLabels[rule.renewalState] || ''}${rule.lastError ? `: ${rule.lastError}` : ''}`;
      renew.setAttribute('aria-label', t('rules.renewAria', { verb, port: rule.port, protocol: rule.protocol }));
      renew.setAttribute('aria-pressed', String(rule.autoRenew));
      renew.disabled = busy || !native;
      renew.addEventListener('click', () => run(async () => {
        const result = await native.tauri.invoke('set_auto_renew', { id: rule.id, enabled: !rule.autoRenew });
        rules = result.rules;
        showMessages(result.messages);
      }));
      action.append(renew);
    }
    const button = document.createElement('button');
    button.className = 'remove';
    button.innerHTML = icon('trash');
    button.setAttribute('aria-label', t('rules.removeAria', { port: rule.port, protocol: rule.protocol }));
    button.disabled = busy || !native;
    button.addEventListener('click', () => run(async () => {
      let result = await native.tauri.invoke('close_rule', { id: rule.id, rebind: false });
      let all = [...result.messages];
      if (all.some(m => String(m).includes('not on the current physical LAN')) && window.confirm(t('confirm.closeRebind'))) {
        const retry = await native.tauri.invoke('close_rule', { id: rule.id, rebind: true });
        all = [...all, ...retry.messages];
        result = retry;
      }
      rules = result.rules;
      showMessages(all);
    }));
    action.append(button);
    row.append(port, firewall, router, action);
    body.append(row);
  }
  table.append(body);
  $('#rules').append(table);
}
function showMessages(messages, error = false) {
  fullResult = messages.map(String).join('\n');
  $('#result-feedback').textContent = '';
  $('#activity').hidden = false;
  $('#last-result').hidden = false;
  $('#activity').classList.toggle('error', error);
  const text = fullResult.replace(/\n{3,}/g, '\n\n').trim();
  $('#messages').textContent = text.length > 600 ? `${text.slice(0, 600).trimEnd()}…` : (text || t('act.noMessages'));
  scheduleResultHide();
}
function scheduleResultHide() {
  clearTimeout(resultTimer);
  if ($('#activity').matches(':hover') || $('#activity').contains(document.activeElement)) return;
  resultTimer = setTimeout(() => { $('#activity').hidden = true; }, 15000);
}
$('#activity').addEventListener('mouseenter', () => clearTimeout(resultTimer));
$('#activity').addEventListener('mouseleave', scheduleResultHide);
$('#activity').addEventListener('focusin', () => clearTimeout(resultTimer));
$('#activity').addEventListener('focusout', event => { if (!$('#activity').contains(event.relatedTarget)) scheduleResultHide(); });
$('#last-result').addEventListener('click', () => { $('#activity').hidden = false; scheduleResultHide(); });
$('#copy-result').addEventListener('click', async () => {
  try {
    if (native) await native.clipboard.writeText(fullResult);
    else await navigator.clipboard.writeText(fullResult);
    $('#result-feedback').textContent = t('act.copied');
  } catch { $('#result-feedback').textContent = t('act.copyFailed'); }
});
$('#open-log').addEventListener('click', async () => {
  if (!native) { $('#result-feedback').textContent = t('act.browserOnly'); return; }
  try { await native.tauri.invoke('open_log'); $('#result-feedback').textContent = t('act.logOpened'); }
  catch (error) { $('#result-feedback').textContent = t('act.logError', { error }); }
});
$('#prev').addEventListener('click', () => { page--; renderRules(); });
$('#next').addEventListener('click', () => { page++; renderRules(); });
$('#dismiss').addEventListener('click', () => { $('#activity').hidden = true; });
async function run(operation) {
  if (busy) return;
  busy = true;
  $('#port-form').setAttribute('aria-busy', 'true');
  document.querySelectorAll('#port-form input, #check-form input, #allow-nat-pmp, #network-scan, #open, #check-submit, #refresh, .remove, .renew-rule').forEach(el => el.disabled = true);
  $('#open span').textContent = t('ports.opening');
  try { await operation(); }
  catch (error) {
    showMessages([String(error)], true);
    if (native) {
      try { await native.tauri.invoke('write_log', { text: String(error) }); }
      catch { $('#result-feedback').textContent = t('act.logSaveFailed'); }
    }
  }
  finally {
    busy = false;
    $('#port-form').setAttribute('aria-busy', 'false');
    document.querySelectorAll('#port-form input, #check-form input, #allow-nat-pmp, #network-scan, #open, #check-submit, #refresh').forEach(el => el.disabled = !native);
    $('#test-server').disabled = !native || $('#check-form input[name="check-protocol"]:checked').value === 'UDP';
    $('#open span').textContent = t('ports.open');
    renderRules();
  }
}
async function refresh() {
  const result = await native.tauri.invoke('status');
  rules = result.rules;
  $('#admin').textContent = result.admin ? t('badge.admin') : t('badge.noAdmin');
  $('#admin').classList.toggle('ok', result.admin);
}
$('#port-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!native) return;
  const request = { ports: $('#ports').value.trim(), protocol: new FormData(event.currentTarget).get('protocol'), router: $('#router').checked, public: $('#public').checked, autoRenew: $('#router').checked && $('#auto-renew').checked, allowNatPmp: $('#allow-nat-pmp').checked, rebind: $('#router').checked && $('#rebind').checked };
  if (request.public && !window.confirm(t('confirm.public'))) return;
  if (request.rebind && !window.confirm(t('confirm.rebind'))) return;
  run(async () => {
    await checkVpn();
    const result = await native.tauri.invoke('open_ports', { request });
    rules = result.rules;
    showMessages(result.messages);
    checkProgress(t('progress.local'), t('progress.localDetail'));
    try {
      const checked = await native.tauri.invoke('check_ports', { request: { ports: request.ports, protocol: request.protocol, external: false, testServer: false } });
      showCheckOutcome(checked);
      showMessages([...result.messages, ...checkLogMessages]);
      if (!$('#check-view').hidden) $('#activity').hidden = true;
    } catch (error) {
      checkProgress(t('progress.autoFailed'), String(error), true);
      showMessages([...result.messages, t('progress.autoFailedMsg', { error })]);
    }
  });
});
$('#check-form').addEventListener('submit', event => {
  event.preventDefault();
  if (!native) return;
  const protocol = new FormData(event.currentTarget).get('check-protocol');
  const request = { ports: $('#check-ports').value.trim(), protocol, external: $('#external-check').checked && protocol !== 'UDP', testServer: $('#test-server').checked && protocol !== 'UDP' };
  const consent = request.testServer ? t('confirm.testServer') : t('confirm.external');
  if (request.external && !window.confirm(consent)) return;
  run(async () => {
    checkProgress(request.testServer ? t('progress.path') : t('progress.reachability'), request.testServer ? t('progress.pathDetail') : request.external && request.protocol !== 'UDP' ? t('progress.externalDetail') : t('progress.localOnlyDetail'));
    $('#check-submit span').textContent = t('check.checking');
    try {
      const result = await native.tauri.invoke('check_ports', { request });
      showCheckOutcome(result);
      showMessages(checkLogMessages);
      $('#activity').hidden = true;
    } catch (error) {
      checkProgress(t('progress.checkFailed'), t('progress.checkFailedDetail'), true);
      throw error;
    } finally { $('#check-submit span').textContent = t('check.submit'); }
  });
});
$('#test-server').addEventListener('change', () => { if ($('#test-server').checked) $('#external-check').checked = true; });
$('#external-check').addEventListener('change', () => { if (!$('#external-check').checked) $('#test-server').checked = false; });
document.querySelectorAll('input[name="check-protocol"]').forEach(input => input.addEventListener('change', () => {
  const udp = input.value === 'UDP';
  $('#test-server').disabled = udp || !native;
  $('#test-server-row').classList.toggle('setting-disabled', udp);
  if (udp) $('#test-server').checked = false;
}));
$('#refresh').addEventListener('click', () => { checkVpn(); run(refresh); });
if (native) {
  const win = native.window.appWindow;
  $('#minimize').addEventListener('click', () => win.minimize());
  $('#maximize').addEventListener('click', () => win.toggleMaximize());
  $('#close').addEventListener('click', () => win.close());
  run(refresh);
  checkVpn();
  setInterval(() => { if (!document.hidden) checkVpn(); }, 15000);
  setInterval(async () => {
    if (busy || document.hidden || $('#ports-view').hidden) return;
    try { const result = await native.tauri.invoke('status'); if (!busy) { rules = result.rules; renderRules(); } }
    catch { }
  }, 20000);
  window.addEventListener('focus', checkVpn);
} else {
  $('#admin').textContent = t('preview.badge');
  document.querySelectorAll('#open, #check-submit, #network-scan, #refresh, .window-controls button').forEach(el => el.disabled = true);
  showMessages([t('preview.message')]);
}
renderRules();
