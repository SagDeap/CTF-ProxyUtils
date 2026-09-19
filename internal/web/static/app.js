/* CTF-ProxyUtils — фронтенд панели.
   Без внешних зависимостей: файл вшит в бинарник и должен открываться
   на голой виртуалке без интернета. */

'use strict';

const $ = (id) => document.getElementById(id);
const API_BASE = '/api/v1';

let token = localStorage.getItem('cpu_token') || '';
let state = { rules: [], scan: {}, system: {} };
let pollTimer = null;
let expandedConns = new Set();
let openTab = 'rules';
let editingId = null;
let trafficView = 'hex';
let trafficLayout = 'stream';
let polling = false;
let authGeneration = 0;
let trafficController = null;
let trafficGeneration = 0;
let trafficOffset = 0;
let trafficTotal = 0;
let trafficItems = [];
const trafficDetails = new Map();
const routingPending = new Set();
const { joinStream, buildSearch, chartSeries } = TrafficUtils;

/* ── Экранирование ────────────────────────────────────────────
   Баннеры сервисов, имена хостов и дампы трафика приходят с чужих
   машин. Всё, что попадает в разметку, обязано быть экранировано —
   иначе чужой баннер выполнит скрипт в нашей же панели. */
function esc(s) {
  return TrafficUtils.escapeHTML(s);
}

/* ── Обращения к API ─────────────────────────────────────────── */
async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (token) headers['X-Auth-Token'] = token;
  if (path.startsWith('/api/') && !path.startsWith('/api/v1/')) path = API_BASE + path.slice(4);
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401) {
    showLogin();
    throw new Error('требуется авторизация');
  }
  let body = null;
  const text = await res.text();
  if (text) { try { body = JSON.parse(text); } catch (e) { body = null; } }
  if (!res.ok) {
    const err = new Error((body && body.error) || ('ошибка ' + res.status));
    err.body = body;
    throw err;
  }
  return body;
}

/* ── Форматирование ──────────────────────────────────────────── */
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
}

function fmtAgo(ms) {
  if (!ms) return '—';
  const d = Math.floor((Date.now() - ms) / 1000);
  if (d < 0) return 'только что';
  if (d < 60) return d + ' с назад';
  if (d < 3600) return Math.floor(d / 60) + ' мин назад';
  return Math.floor(d / 3600) + ' ч назад';
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  return d.toLocaleTimeString('ru-RU');
}

function toast(msg, kind) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast ' + (kind || '');
  setTimeout(() => t.classList.add('hidden'), 3200);
  t.classList.remove('hidden');
}

/* ── Вход ────────────────────────────────────────────────────── */
function showLogin() {
  stopPolling();
  authGeneration++;
  invalidateTraffic();
  $('login').classList.remove('hidden');
  $('app').classList.add('hidden');
}

function showApp() {
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  startPolling();
  loadInterfaces();
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const t = $('login-token').value.trim();
  try {
    await fetch(API_BASE + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: t }),
    }).then((r) => { if (!r.ok) throw new Error('неверный токен'); });
    token = t;
    localStorage.setItem('cpu_token', t);
    $('login-error').textContent = '';
    showApp();
  } catch (err) {
    $('login-error').textContent = err.message;
  }
});

$('btn-logout').addEventListener('click', () => {
  token = '';
  localStorage.removeItem('cpu_token');
  $('login-token').value = '';
  showLogin();
});

/* ── Опрос состояния ─────────────────────────────────────────── */
function startPolling() {
  if (pollTimer) return;
  poll();
  pollTimer = setInterval(poll, 1000);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function poll() {
  if (document.hidden || polling) return;
  polling = true;
  const generation = authGeneration;
  try {
    const next = await api('/api/state');
    if (generation !== authGeneration) return;
    state = next;
    $('conn-dot').classList.remove('stale');
    render();
  } catch (err) {
    $('conn-dot').classList.add('stale');
  } finally {
    polling = false;
  }
}

function render() {
  const sys = state.system || {};
  $('sys-host').textContent = sys.hostname || '';
  $('badge-rules').textContent = (state.rules || []).length;
  $('badge-findings').textContent = (state.findings || []).length;
  renderRules();
  renderScan();
  renderTrafficSelect();
  if (openTab === 'findings') renderFindings();
  if (openTab === 'monitor') renderMonitor();
}

/* ── Пробросы ────────────────────────────────────────────────── */
function renderRules() {
  const list = $('rules-list');
  const rules = state.rules || [];

  $('rules-empty').classList.toggle('hidden', rules.length > 0);

  let conns = 0, bin = 0, bout = 0;
  rules.forEach((r) => { conns += r.active_conns; bin += r.bytes_in; bout += r.bytes_out; });
  $('rules-totals').textContent = rules.length
    ? `${conns} активных · ↓${fmtBytes(bin)} ↑${fmtBytes(bout)}`
    : '';

  const ids = new Set(rules.map((r) => r.spec.id));
  for (const child of [...list.children]) if (!ids.has(child.dataset.rule)) child.remove();
  rules.forEach((rule) => {
    const template = document.createElement('template');
    template.innerHTML = ruleCard(rule).trim();
    const next = template.content.firstElementChild;
    const current = [...list.children].find((el) => el.dataset.rule === rule.spec.id);
    if (!current) { list.appendChild(next); return; }
    current.className = next.className;
    for (const selector of ['.rule-identity', '.rule-stats', '.rule-error']) {
      const target = current.querySelector(selector);
      const fresh = next.querySelector(selector);
      if (target.innerHTML !== fresh.innerHTML) target.innerHTML = fresh.innerHTML;
      target.className = fresh.className;
    }
    const actions = current.querySelector('.rule-actions');
    const freshActions = next.querySelector('.rule-actions');
    // Keep controls mounted while their labels and live counters change.
    const select = actions.querySelector('[data-routing]');
    const freshSelect = freshActions.querySelector('[data-routing]');
    if (!!select !== !!freshSelect) {
      if (!actions.contains(document.activeElement)) actions.innerHTML = freshActions.innerHTML;
    } else {
      actions.querySelector('[data-act="toggle"]').textContent = rule.running ? 'Стоп' : 'Пуск';
      if (select && document.activeElement !== select && !routingPending.has(rule.spec.id)) {
        select.value = rule.spec.routing_mode || 'auto';
      }
    }
  });
}

$('rules-list').addEventListener('click', (e) => {
  const button = e.target.closest('[data-act]');
  if (button) ruleAction(button.dataset.id, button.dataset.act);
});

$('rules-list').addEventListener('change', async (e) => {
  const select = e.target.closest('[data-routing]');
  if (!select) return;
  const id = select.dataset.routing;
  routingPending.add(id);
  select.disabled = true;
  try {
    await api(`/api/rules/${encodeURIComponent(id)}/switch`, { method: 'POST', body: JSON.stringify({ mode: select.value }) });
  } catch (err) { toast(err.message, 'err'); }
  finally { routingPending.delete(id); select.disabled = false; poll(); }
});

function ruleCard(r) {
  const s = r.spec;
  const target = r.using_backup && s.backup ? s.backup : s.target;
  let cls = 'rule ';
  if (!r.running) cls += 'off';
  else if (r.last_error && !r.target_up) cls += 'err';
  else if (r.using_backup) cls += 'backup';
  else cls += 'on';

  const tags = [];
  if (r.running) tags.push('<span class="tag up">работает</span>');
  else tags.push('<span class="tag">выключен</span>');

  if (s.health.enabled) {
    tags.push(r.target_up
      ? '<span class="tag up">цель жива</span>'
      : '<span class="tag down">цель не отвечает</span>');
  }
  tags.push(`<span class="tag">${esc((s.protocol || 'tcp').toUpperCase())}</span>`);
  if (s.inspect && s.inspect.enabled) tags.push('<span class="tag warn">инспекция</span>');
  if (r.using_backup) tags.push('<span class="tag warn">на резерве</span>');
  if (s.dump.enabled) tags.push(`<span class="tag">запись ${r.dump_count}</span>`);
  if (s.allow_cidr && s.allow_cidr.length) tags.push('<span class="tag">ACL</span>');

  const hasBackup = s.backup && s.backup.host;

  return `
  <div class="${cls}" data-rule="${esc(s.id)}">
    <div class="rule-head">
      <div class="rule-identity">
      <span class="rule-name">${esc(s.name || 'без названия')}</span>
      <span class="rule-path">
        ${esc(s.listen_host)}:${s.listen_port}<span class="to">→</span>${esc(target.host)}:${target.port}
      </span>
      ${tags.join('')}
      </div>
      <div class="rule-actions">
        ${hasBackup ? `<select class="select routing-select" data-routing="${esc(s.id)}" aria-label="Режим маршрутизации ${esc(s.name || s.listen_port)}">
          <option value="auto" ${!s.routing_mode || s.routing_mode === 'auto' ? 'selected' : ''}>Авто</option>
          <option value="primary" ${s.routing_mode === 'primary' ? 'selected' : ''}>Основной</option>
          <option value="backup" ${s.routing_mode === 'backup' ? 'selected' : ''}>Резерв</option></select>` : ''}
        <button class="btn btn-sm" data-act="toggle" data-id="${esc(s.id)}">
          ${r.running ? 'Стоп' : 'Пуск'}</button>
        <button class="btn btn-sm btn-ghost" data-act="edit" data-id="${esc(s.id)}">Изменить</button>
        <button class="btn btn-sm btn-ghost btn-danger" data-act="delete" data-id="${esc(s.id)}">Удалить</button>
      </div>
    </div>
    <div class="rule-stats">
      <span>активных <b>${r.active_conns}</b></span>
      <span>всего <b>${r.total_conns}</b></span>
      <span>принято <b>${fmtBytes(r.bytes_in)}</b></span>
      <span>отдано <b>${fmtBytes(r.bytes_out)}</b></span>
      ${r.failed_conns ? `<span>сбоев <b>${r.failed_conns}</b></span>` : ''}
      ${r.denied_conns ? `<span>отклонено <b>${r.denied_conns}</b></span>` : ''}
      ${r.target_health && r.target_health.at ? `<span>health <b>${r.target_health.ok ? esc(r.target_health.latency_ms + ' мс') : 'ошибка'}</b></span>` : ''}
      <span>${fmtAgo(r.last_active_unix_ms)}</span>
    </div>
    <div class="rule-error${r.last_error ? '' : ' hidden'}">${esc(r.last_error)}</div>
  </div>`;
}

async function ruleAction(id, act) {
  const rule = (state.rules || []).find((r) => r.spec.id === id);
  if (!rule) return;
  try {
    if (act === 'toggle') {
      await api(`/api/rules/${id}/toggle`, {
        method: 'POST',
        body: JSON.stringify({ enabled: !rule.running }),
      });
    } else if (act === 'delete') {
      const name = rule.spec.name || `${rule.spec.listen_port}`;
      if (!confirm(`Удалить проброс «${name}»?`)) return;
      await api(`/api/rules/${id}`, { method: 'DELETE' });
      toast('Проброс удалён', 'ok');
    } else if (act === 'edit') {
      openModal(rule.spec);
      return;
    }
    poll();
  } catch (err) {
    toast(err.message, 'err');
    poll();
  }
}

/* ── Модальное окно правила ──────────────────────────────────── */
function openModal(spec, presets) {
  editingId = spec ? spec.id : null;
  $('modal-title').textContent = spec ? 'Изменить проброс' : 'Новый проброс';
  $('modal-error').classList.add('hidden');

  const s = spec || {
    name: '', listen_host: '0.0.0.0', listen_port: '',
    target: { host: '', port: '' }, backup: null,
    protocol: 'tcp', udp_idle_sec: 30,
    health: { enabled: false, interval_sec: 3, timeout_ms: 1000, fail_after: 2, rise_after: 2, auto_failover: true, auto_failback: true, mode: 'tcp', request_mode: 'text', expect_mode: 'text', http_method: 'GET', http_path: '/', http_status: 200 },
    dump: { enabled: false, max_conns: 50, max_bytes_per: 65536 },
    inspect: { enabled: true, auto_pin: true },
    allow_cidr: [], max_conns: 0, idle_timeout_sec: 0, dial_timeout_ms: 3000,
    enabled: true,
  };

  $('f-name').value = s.name || '';
  $('f-protocol').value = s.protocol || 'tcp';
  $('f-udp-idle').value = s.udp_idle_sec || 30;
  $('f-listen-host').value = s.listen_host || '0.0.0.0';
  $('f-listen-port').value = s.listen_port || '';
  $('f-target-host').value = s.target.host || '';
  $('f-target-port').value = s.target.port || '';
  $('f-backup-host').value = s.backup ? s.backup.host : '';
  $('f-backup-port').value = s.backup ? s.backup.port : '';

  $('f-health').checked = !!s.health.enabled;
  $('f-health-interval').value = s.health.interval_sec || 3;
  $('f-health-timeout').value = s.health.timeout_ms || 1000;
  $('f-health-fail').value = s.health.fail_after || 2;
  $('f-health-rise').value = s.health.rise_after || 2;
  $('f-health-mode').value = s.health.mode || 'tcp';
  $('f-health-request-mode').value = s.health.request_mode || 'text';
  $('f-health-expect-mode').value = s.health.expect_mode || 'text';
  $('f-health-request').value = s.health.request || '';
  $('f-health-expect').value = s.health.expect || '';
  $('f-health-http-method').value = s.health.http_method || 'GET';
  $('f-health-http-path').value = s.health.http_path || '/';
  $('f-health-http-host').value = s.health.http_host || '';
  $('f-health-http-status').value = s.health.http_status || 200;
  $('f-health-http-headers').value = Object.entries(s.health.http_headers || {}).map(([key, value]) => `${key}: ${value}`).join('\n');
  $('f-autofail').checked = s.health.auto_failover !== false;
  $('f-autoback').checked = s.health.auto_failback !== false;

  $('f-dump').checked = !!s.dump.enabled;
  $('f-inspect').checked = !!(s.inspect && s.inspect.enabled);
  $('f-auto-pin').checked = !s.inspect || s.inspect.auto_pin !== false;
  $('f-dump-conns').value = s.dump.max_conns || 50;
  $('f-dump-kb').value = Math.round((s.dump.max_bytes_per || 65536) / 1024);

  $('f-acl').value = (s.allow_cidr || []).join(', ');
  $('f-maxconns').value = s.max_conns || 0;
  $('f-idle').value = s.idle_timeout_sec || 0;
  $('f-dial').value = s.dial_timeout_ms || 3000;
  $('f-enabled').checked = s.enabled !== false;
  syncProtocolFields();

  // Предзаполнение из результатов скана.
  if (presets) {
    $('f-target-host').value = presets.host;
    $('f-target-port').value = presets.port;
    $('f-listen-port').value = presets.port;
    $('f-name').value = presets.name || '';
  }

  $('modal').classList.remove('hidden');
  ($('f-name').value ? $('f-listen-port') : $('f-name')).focus();
}

function closeModal() {
  $('modal').classList.add('hidden');
  editingId = null;
}

$('modal-close').addEventListener('click', closeModal);
$('btn-cancel').addEventListener('click', closeModal);
$('modal').addEventListener('mousedown', (e) => { if (e.target === $('modal')) closeModal(); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('modal').classList.contains('hidden')) closeModal();
});
$('btn-new-rule').addEventListener('click', () => openModal(null));

$('btn-profile-export').addEventListener('click', async () => {
  try {
    const profile = await api('/api/profile');
    const url = URL.createObjectURL(new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `ctf-proxyutils-${(profile.name || 'profile').replace(/[^a-zA-Z0-9_-]/g, '_')}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) { toast(err.message, 'err'); }
});

$('btn-profile-import').addEventListener('click', () => $('profile-file').click());
$('profile-file').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  event.target.value = '';
  if (!file) return;
  try {
    const profile = JSON.parse(await file.text());
    const preview = await api('/api/profile', { method: 'POST', body: JSON.stringify({ profile, mode: 'merge', dry_run: true }) });
    if (!confirm(`Импортировать профиль «${profile.name || file.name}»?\nДобавится: ${preview.added}, обновится: ${preview.updated}, удалится: ${preview.removed}.`)) return;
    await api('/api/profile', { method: 'POST', body: JSON.stringify({ profile, mode: 'merge', dry_run: false }) });
    toast('Профиль импортирован', 'ok');
    poll();
  } catch (err) { toast(err.message, 'err'); }
});

$('rule-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const backupHost = $('f-backup-host').value.trim();
  const backupPort = parseInt($('f-backup-port').value, 10);
  const acl = $('f-acl').value.split(',').map((s) => s.trim()).filter(Boolean);
  let httpHeaders;
  try { httpHeaders = TrafficUtils.parseHeaderLines($('f-health-http-headers').value); }
  catch (err) {
    $('modal-error').textContent = err.message;
    $('modal-error').classList.remove('hidden');
    return;
  }

  const spec = {
    name: $('f-name').value.trim(),
    protocol: $('f-protocol').value,
    udp_idle_sec: parseInt($('f-udp-idle').value, 10) || 30,
    routing_mode: editingId ? ((state.rules || []).find((r) => r.spec.id === editingId)?.spec.routing_mode || 'auto') : 'auto',
    enabled: $('f-enabled').checked,
    listen_host: $('f-listen-host').value.trim() || '0.0.0.0',
    listen_port: parseInt($('f-listen-port').value, 10),
    target: {
      host: $('f-target-host').value.trim(),
      port: parseInt($('f-target-port').value, 10),
    },
    backup: (backupHost && backupPort) ? { host: backupHost, port: backupPort } : null,
    health: {
      enabled: $('f-health').checked,
      interval_sec: parseInt($('f-health-interval').value, 10),
      timeout_ms: parseInt($('f-health-timeout').value, 10),
      fail_after: parseInt($('f-health-fail').value, 10),
      rise_after: parseInt($('f-health-rise').value, 10),
      auto_failover: $('f-autofail').checked,
      auto_failback: $('f-autoback').checked,
      mode: $('f-health-mode').value,
      request: $('f-health-request').value,
      request_mode: $('f-health-request-mode').value,
      expect: $('f-health-expect').value,
      expect_mode: $('f-health-expect-mode').value,
      http_method: $('f-health-http-method').value.trim() || 'GET',
      http_path: $('f-health-http-path').value.trim() || '/',
      http_host: $('f-health-http-host').value.trim(),
      http_status: parseInt($('f-health-http-status').value, 10) || 0,
      http_headers: httpHeaders,
    },
    dump: {
      enabled: $('f-dump').checked,
      max_conns: parseInt($('f-dump-conns').value, 10),
      max_bytes_per: parseInt($('f-dump-kb').value, 10) * 1024,
    },
    inspect: { enabled: $('f-inspect').checked, auto_pin: $('f-auto-pin').checked },
    allow_cidr: acl,
    max_conns: parseInt($('f-maxconns').value, 10) || 0,
    idle_timeout_sec: parseInt($('f-idle').value, 10) || 0,
    dial_timeout_ms: parseInt($('f-dial').value, 10) || 3000,
  };

  try {
    if (editingId) {
      await api(`/api/rules/${editingId}`, { method: 'PUT', body: JSON.stringify(spec) });
      toast('Проброс обновлён', 'ok');
    } else {
      await api('/api/rules', { method: 'POST', body: JSON.stringify(spec) });
      toast('Проброс создан', 'ok');
    }
    closeModal();
    poll();
  } catch (err) {
    const box = $('modal-error');
    box.textContent = err.message;
    box.classList.remove('hidden');
    poll();
  }
});

/* ── Сканер ──────────────────────────────────────────────────── */
async function loadInterfaces() {
  try {
    const data = await api('/api/interfaces');
    const dl = $('cidr-list');
    dl.innerHTML = (data.interfaces || [])
      .filter((i) => i.suggested)
      .map((i) => `<option value="${esc(i.cidr)}">${esc(i.name)} — ${i.host_count} адресов</option>`)
      .join('');
    if (!$('scan-cidr').value) {
      const d = state.scan_defaults || {};
      $('scan-cidr').value = d.cidr || data.default_cidr || '';
      if (d.ports) $('scan-ports').value = d.ports;
      if (d.timeout_ms) $('scan-timeout').value = d.timeout_ms;
      if (d.concurrency) $('scan-conc').value = d.concurrency;
    }
    $('chip-ctf').dataset.ports = data.ctf_ports || '';
  } catch (err) { /* панель работает и без подсказок */ }
}

document.querySelectorAll('.chip').forEach((c) => {
  c.addEventListener('click', () => { $('scan-ports').value = c.dataset.ports || ''; });
});

$('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/scan', {
      method: 'POST',
      body: JSON.stringify({
        cidr: $('scan-cidr').value.trim(),
        ports: $('scan-ports').value.trim(),
        timeout_ms: parseInt($('scan-timeout').value, 10),
        concurrency: parseInt($('scan-conc').value, 10),
        fingerprint: $('scan-fp').checked,
      }),
    });
    poll();
  } catch (err) {
    toast(err.message, 'err');
  }
});

$('btn-scan-stop').addEventListener('click', async () => {
  try { await api('/api/scan', { method: 'DELETE' }); poll(); }
  catch (err) { toast(err.message, 'err'); }
});

function renderScan() {
  const sc = state.scan || {};
  const running = !!sc.running;

  $('btn-scan').disabled = running;
  $('btn-scan').textContent = running ? 'Сканирую…' : 'Сканировать';
  $('btn-scan-stop').classList.toggle('hidden', !running);
  $('scan-progress').classList.toggle('hidden', !running && !sc.total);

  if (sc.total) {
    const pct = Math.min(100, Math.round((sc.done / sc.total) * 100));
    $('scan-fill').style.width = pct + '%';
    const hosts = (sc.hosts || []).length;
    $('scan-text').textContent = running
      ? `${sc.done} / ${sc.total} проб · найдено машин: ${hosts}`
      : `Готово: ${sc.done} / ${sc.total} проб · найдено машин: ${hosts}`;
  }

  const hosts = sc.hosts || [];
  $('scan-empty').classList.toggle('hidden', running || hosts.length > 0 || !sc.total);
  const markup = hosts.map(hostCard).join('');
  if ($('scan-results').innerHTML === markup || $('scan-results').contains(document.activeElement)) return;
  $('scan-results').innerHTML = markup;

  $('scan-results').querySelectorAll('[data-fwd]').forEach((btn) => {
    btn.addEventListener('click', () => {
      openModal(null, {
        host: btn.dataset.host,
        port: parseInt(btn.dataset.port, 10),
        name: btn.dataset.label || '',
      });
    });
  });
}

function hostCard(h) {
  const meta = [];
  if (h.hostname) meta.push(esc(h.hostname));
  if (h.mac) meta.push(esc(h.mac));
  if (h.vendor) meta.push(esc(h.vendor));

  const ports = (h.ports || []).map((p) => {
    const label = h.hostname ? h.hostname.split('.')[0] : h.ip;
    return `
    <div class="port">
      <span class="port-num">${p.port}</span>
      ${p.service ? `<span class="port-svc">${esc(p.service)}</span>` : ''}
      ${p.banner ? `<span class="port-banner" title="${esc(p.banner)}">${esc(p.banner)}</span>` : ''}
      <button class="btn btn-sm" data-fwd="1" data-host="${esc(h.ip)}" data-port="${p.port}"
              data-label="${esc(label + ':' + p.port)}">пробросить</button>
    </div>`;
  }).join('');

  return `
  <div class="host${h.is_self ? ' self' : ''}">
    <div class="host-head">
      <span class="host-ip">${esc(h.ip)}</span>
      ${h.is_self ? '<span class="tag up">это я</span>' : ''}
      ${meta.length ? `<span class="host-meta">${meta.join(' · ')}</span>` : ''}
      ${!(h.ports || []).length ? '<span class="tag">жив, порты закрыты</span>' : ''}
    </div>
    ${ports ? `<div class="ports">${ports}</div>` : ''}
  </div>`;
}

/* ── Трафик ──────────────────────────────────────────────────── */
function renderTrafficSelect() {
  const sel = $('traffic-rule');
  const rules = (state.rules || []).filter((r) => r.spec.dump.enabled || r.dump_count > 0);
  const cur = sel.value;
  const opts = rules.map((r) =>
    `<option value="${esc(r.spec.id)}">${esc(r.spec.name || r.spec.listen_port)}</option>`
  ).join('');
  const markup = opts || '<option value="">нет правил с записью трафика</option>';
  if (sel.innerHTML !== markup && document.activeElement !== sel) {
    sel.innerHTML = markup;
    if (cur && rules.some((r) => r.spec.id === cur)) sel.value = cur;
    if (cur !== sel.value) resetTraffic();
  }
}

function invalidateTraffic() {
  trafficGeneration++;
  if (trafficController) trafficController.abort();
  trafficController = null;
}

function resetTraffic() {
  invalidateTraffic();
  trafficOffset = 0;
  expandedConns.clear();
  trafficDetails.clear();
  trafficItems = [];
  $('traffic-list').replaceChildren();
  if (openTab === 'traffic') loadTraffic();
}

function trafficFilters() {
  return { q: $('traffic-query').value, mode: $('traffic-mode').value, dir: $('traffic-dir').value,
    remote: $('traffic-remote').value, from: $('traffic-from').value, to: $('traffic-to').value,
    pinned: $('traffic-pinned').checked };
}

async function loadTraffic(background = false) {
  if (document.hidden || $('app').classList.contains('hidden') || (background && trafficController)) return;
  invalidateTraffic();
  const id = $('traffic-rule').value;
  if (!id) {
    trafficItems = [];
    $('traffic-list').replaceChildren();
    $('traffic-count').textContent = '';
    $('traffic-prev').disabled = $('traffic-next').disabled = true;
    $('traffic-empty').classList.remove('hidden');
    return;
  }
  const generation = trafficGeneration;
  const controller = new AbortController();
  trafficController = controller;
  $('traffic-list').setAttribute('aria-busy', 'true');
  try {
    const query = buildSearch(trafficFilters(), trafficOffset);
    const result = await api(`/api/rules/${encodeURIComponent(id)}/dumps?${query}`, { signal: controller.signal });
    if (generation !== trafficGeneration) return;
    trafficItems = result.items || [];
    trafficTotal = result.total || 0;
    if (!trafficItems.length && trafficOffset > 0 && trafficTotal <= trafficOffset) {
      trafficOffset = Math.max(0, Math.floor(Math.max(0, trafficTotal - 1) / 50) * 50);
      loadTraffic();
      return;
    }
    const liveIDs = new Set(trafficItems.map((c) => String(c.id)));
    for (const cid of expandedConns) if (!liveIDs.has(cid)) expandedConns.delete(cid);
    for (const cid of trafficDetails.keys()) if (!liveIDs.has(cid)) trafficDetails.delete(cid);
    $('traffic-error').classList.add('hidden');
    renderTraffic();
    for (const cid of expandedConns) {
      const summary = trafficItems.find((c) => String(c.id) === cid);
      const cached = trafficDetails.get(cid);
      if (cached && cached.ended_at && cached.bytes_in === summary.bytes_in && cached.bytes_out === summary.bytes_out) continue;
      const detail = await api(`/api/rules/${encodeURIComponent(id)}/dumps/${encodeURIComponent(cid)}`, { signal: controller.signal });
      if (generation !== trafficGeneration) return;
      trafficDetails.set(cid, detail);
      renderTraffic();
    }
  } catch (err) {
    if (err.name !== 'AbortError' && generation === trafficGeneration) {
      $('traffic-error').textContent = err.message;
      $('traffic-error').classList.remove('hidden');
    }
  } finally {
    if (generation === trafficGeneration) {
      trafficController = null;
      $('traffic-list').setAttribute('aria-busy', 'false');
    }
  }
}

function renderTraffic() {
  $('traffic-empty').classList.toggle('hidden', trafficItems.length > 0);
  $('traffic-count').textContent = trafficTotal ? `${trafficOffset + 1}–${trafficOffset + trafficItems.length} из ${trafficTotal}` : 'Найдено: 0';
  $('traffic-prev').disabled = trafficOffset === 0;
  $('traffic-next').disabled = trafficOffset + trafficItems.length >= trafficTotal;
  const list = $('traffic-list');
  const liveIDs = new Set(trafficItems.map((c) => String(c.id)));
  for (const child of [...list.children]) if (!liveIDs.has(child.dataset.cid)) child.remove();
  trafficItems.forEach((connection, index) => {
    let card = [...list.children].find((el) => el.dataset.cid === String(connection.id));
    const template = document.createElement('template');
    template.innerHTML = connCard(connection).trim();
    const next = template.content.firstElementChild;
    if (!card) { card = next; }
    else {
      card.className = next.className;
      // Headers and pin buttons retain focus during background refreshes.
      const toggle = card.querySelector('[data-expand]');
      const freshToggle = next.querySelector('[data-expand]');
      if (toggle.innerHTML !== freshToggle.innerHTML) toggle.innerHTML = freshToggle.innerHTML;
      toggle.setAttribute('aria-expanded', freshToggle.getAttribute('aria-expanded'));
      const pin = card.querySelector('[data-pin]');
      const freshPin = next.querySelector('[data-pin]');
      pin.textContent = freshPin.textContent;
      pin.setAttribute('aria-pressed', freshPin.getAttribute('aria-pressed'));
      const body = card.querySelector('.conn-body');
      const freshBody = next.querySelector('.conn-body');
      if (!freshBody) { if (body) body.remove(); }
      else if (!body) card.appendChild(freshBody);
      else if (body.innerHTML !== freshBody.innerHTML) {
        for (const selector of ['.traffic-content', '.capture-note']) {
          const target = body.querySelector(selector);
          const replacement = freshBody.querySelector(selector);
          if (target.innerHTML !== replacement.innerHTML) target.innerHTML = replacement.innerHTML;
        }
        for (const btn of body.querySelectorAll('[data-view], [data-layout]')) {
          const selected = btn.dataset.view ? btn.dataset.view === trafficView : btn.dataset.layout === trafficLayout;
          btn.className = `btn btn-sm ${selected ? 'btn-primary' : 'btn-ghost'}`;
          btn.setAttribute('aria-pressed', String(selected));
        }
      }
    }
    if (list.children[index] !== card) list.insertBefore(card, list.children[index] || null);
  });
}

function connCard(c) {
  const open = expandedConns.has(String(c.id));
  const dur = c.ended_at && c.started_at
    ? ((new Date(c.ended_at) - new Date(c.started_at)) / 1000).toFixed(1) + ' с'
    : 'открыто';

  let body = '';
  if (open) {
    const detail = trafficDetails.get(String(c.id));
    body = `<div class="conn-body">
      <div class="view-toggle">
        ${['hex', 'text'].map((view) => `<button class="btn btn-sm ${trafficView === view ? 'btn-primary' : 'btn-ghost'}" data-view="${view}" aria-pressed="${trafficView === view}">${view === 'hex' ? 'Hex' : 'Текст'}</button>`).join('')}
        ${['stream', 'chunks'].map((layout) => `<button class="btn btn-sm ${trafficLayout === layout ? 'btn-primary' : 'btn-ghost'}" data-layout="${layout}" aria-pressed="${trafficLayout === layout}">${layout === 'stream' ? 'Целый поток' : 'Чанки'}</button>`).join('')}
        <button class="btn btn-sm btn-ghost export-button" data-export="${esc(c.id)}">Скачать JSON</button>
      </div>
      <div class="traffic-content">${detail ? trafficContent(detail) : '<p class="dim">Загрузка потока…</p>'}</div>
      <p class="hint capture-note">${c.truncated ? 'Запись обрезана по лимиту.' : ''}</p>
    </div>`;
  }

  return `
  <div class="conn${c.pinned ? ' pinned' : ''}" data-cid="${esc(c.id)}">
    <div class="conn-head"><button class="conn-expand" data-expand="${esc(c.id)}" aria-expanded="${open}">
      <span>${open ? '▾' : '▸'}</span>
      <span class="conn-remote">${esc(c.remote_addr)}</span>
      <span class="dim">→ ${esc(c.target)}</span>
      <span class="dim" title="${esc(new Date(c.started_at).toLocaleString('ru-RU'))}">${fmtTime(c.started_at)}</span>
      <span class="dim">↓${fmtBytes(c.bytes_in)} ↑${fmtBytes(c.bytes_out)}</span>
      <span class="dim">${dur}</span>
      ${c.truncated ? '<span class="tag warn">обрезано</span>' : ''}
      </button><button class="btn btn-sm btn-ghost pin-button" data-pin="${esc(c.id)}" aria-pressed="${!!c.pinned}">${c.pinned ? '★ Закреплено' : '☆ Закрепить'}</button>
    </div>
    ${body}
  </div>`;
}

function trafficContent(detail) {
  if (trafficLayout === 'chunks') return (detail.chunks || []).map(chunkBlock).join('') || '<p class="dim">Пусто</p>';
  return ['in', 'out'].map((dir) => {
    const bytes = joinStream(detail.chunks, dir);
    const content = trafficView === 'hex' ? hexdump(bytes) : esc(bytesToText(bytes));
    return `<div class="chunk"><div class="chunk-head ${dir}">${dir === 'in' ? '→ От клиента' : '← От сервиса'} · ${fmtBytes(bytes.length)}</div><pre class="hexdump">${content || 'пусто'}</pre></div>`;
  }).join('');
}

function chunkBlock(ch) {
  const bytes = b64ToBytes(ch.data);
  const dirLabel = ch.dir === 'in' ? '→ от клиента' : '← от сервиса';
  const content = trafficView === 'hex' ? hexdump(bytes) : esc(bytesToText(bytes));
  return `
  <div class="chunk">
    <div class="chunk-head ${esc(ch.dir)}">${dirLabel} · ${bytes.length} байт · ${fmtTime(ch.at)}</div>
    <pre class="hexdump">${content}</pre>
  </div>`;
}

function b64ToBytes(b64) {
  return TrafficUtils.decodeBytes(b64);
}

// bytesToText показывает полезную нагрузку как текст, заменяя непечатаемое.
function bytesToText(bytes) {
  return new TextDecoder('utf-8').decode(bytes).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '.');
}

// hexdump рисует классические 16 байт в строке: смещение, hex, ASCII.
function hexdump(bytes) {
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.subarray(off, off + 16);
    let hex = '';
    let asc = '';
    for (let i = 0; i < 16; i++) {
      hex += i < slice.length ? slice[i].toString(16).padStart(2, '0') + ' ' : '   ';
      if (i === 7) hex += ' ';
      if (i < slice.length) {
        const b = slice[i];
        asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
      }
    }
    lines.push(
      `<span class="off">${off.toString(16).padStart(8, '0')}</span>  ${hex} <span class="asc">${esc(asc)}</span>`
    );
  }
  return lines.join('\n');
}

$('traffic-rule').addEventListener('change', resetTraffic);
$('btn-traffic-refresh').addEventListener('click', () => loadTraffic());
$('traffic-search').addEventListener('submit', (e) => { e.preventDefault(); trafficOffset = 0; loadTraffic(); });
$('traffic-search').addEventListener('reset', () => { setTimeout(() => { trafficOffset = 0; loadTraffic(); }, 0); });
$('traffic-prev').addEventListener('click', () => { trafficOffset = Math.max(0, trafficOffset - 50); loadTraffic(); });
$('traffic-next').addEventListener('click', () => { if (trafficOffset + 50 < trafficTotal) { trafficOffset += 50; loadTraffic(); } });
$('btn-traffic-clear').addEventListener('click', async () => {
  const id = $('traffic-rule').value;
  if (!id || !confirm('Стереть незакреплённые записи этого правила? Закреплённые останутся.')) return;
  try {
    await api(`/api/rules/${encodeURIComponent(id)}/dumps`, { method: 'DELETE' });
    trafficOffset = 0;
    loadTraffic();
    toast('Незакреплённые записи стёрты', 'ok');
  } catch (err) { toast(err.message, 'err'); }
});

$('traffic-list').addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  if (btn.dataset.view || btn.dataset.layout) {
    if (btn.dataset.view) trafficView = btn.dataset.view;
    if (btn.dataset.layout) trafficLayout = btn.dataset.layout;
    renderTraffic();
    return;
  }
  if (btn.dataset.expand) {
    const cid = btn.dataset.expand;
    const wasOpen = expandedConns.has(cid);
    expandedConns.clear();
    if (!wasOpen) expandedConns.add(cid);
    renderTraffic();
    if (!wasOpen) loadTraffic();
    return;
  }
  const ruleID = $('traffic-rule').value;
  try {
    if (btn.dataset.pin) {
      const cid = btn.dataset.pin;
      const item = trafficItems.find((c) => String(c.id) === cid);
      if (!item) return;
      const pinned = !item.pinned;
      btn.disabled = true;
      await api(`/api/rules/${encodeURIComponent(ruleID)}/dumps/${encodeURIComponent(cid)}/pin`, { method: 'POST', body: JSON.stringify({ pinned }) });
      if ($('traffic-rule').value !== ruleID) return;
      item.pinned = pinned;
      if (trafficDetails.has(cid)) trafficDetails.get(cid).pinned = pinned;
      loadTraffic();
    } else if (btn.dataset.export) {
      const cid = btn.dataset.export;
      const detail = trafficDetails.get(cid);
      if (!detail) { toast('Дождитесь загрузки потока', 'err'); return; }
      const url = URL.createObjectURL(new Blob([JSON.stringify(detail, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `traffic-${ruleID.replace(/[^a-zA-Z0-9_-]/g, '_')}-${cid}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  } catch (err) { toast(err.message, 'err'); }
  finally { btn.disabled = false; }
});

let trafficTimer = null;
$('traffic-auto').addEventListener('change', (e) => {
  if (e.target.checked) {
    trafficTimer = setInterval(() => { if (openTab === 'traffic') loadTraffic(true); }, 2000);
  } else if (trafficTimer) {
    clearInterval(trafficTimer);
    trafficTimer = null;
  }
});

/* ── Подозрительный трафик и детекторы ─────────────────────── */
function severityLabel(value) {
  return ({ critical: 'критический', high: 'высокий', medium: 'средний', low: 'низкий' })[value] || value;
}

function syncProtocolFields() {
  const udp = $('f-protocol').value === 'udp';
  $('f-udp-idle').disabled = !udp;
  const httpOption = $('f-health-mode').querySelector('option[value="http"]');
  httpOption.disabled = udp;
  const tcpOption = $('f-health-mode').querySelector('option[value="tcp"]');
  tcpOption.disabled = udp;
  if (udp && $('f-health-mode').value !== 'payload') $('f-health-mode').value = 'payload';
}

$('f-protocol').addEventListener('change', syncProtocolFields);

function renderFindings() {
  const query = $('findings-query').value.trim().toLocaleLowerCase('ru-RU');
  const minimum = parseInt($('findings-score').value, 10) || 0;
  const all = state.findings || [];
  const items = all.filter((finding) => {
    if (finding.score < minimum) return false;
    const signalText = (finding.signals || []).map((signal) => `${signal.detector_name} ${signal.reason} ${signal.excerpt || ''}`).join(' ');
    return !query || `${finding.rule_name} ${finding.remote_addr} ${finding.target} ${signalText}`.toLocaleLowerCase('ru-RU').includes(query);
  });
  $('findings-summary').textContent = `${all.length} находок · ${(state.detection && state.detection.dropped) || 0} пропущено`;
  $('findings-empty').classList.toggle('hidden', items.length > 0);
  $('findings-list').innerHTML = items.map((finding) => `<article class="finding severity-${esc(finding.severity)}">
    <div class="finding-score"><strong>${finding.score}</strong><span>/100</span></div>
    <div class="finding-content"><div class="finding-head"><b>${esc(finding.rule_name || finding.rule_id)}</b><span class="tag ${finding.severity === 'critical' || finding.severity === 'high' ? 'down' : 'warn'}">${esc(severityLabel(finding.severity))}</span><span class="tag">${esc((finding.protocol || 'tcp').toUpperCase())}</span>${finding.auto_pinned ? '<span class="tag warn">закреплено</span>' : ''}</div>
    <div class="finding-meta">${esc(finding.remote_addr)} → ${esc(finding.target)} · ${fmtTime(finding.at)}</div>
    <div class="finding-signals">${(finding.signals || []).map((signal) => `<div><b>+${signal.score} ${esc(signal.detector_name)}</b>${signal.excerpt ? `<code>${esc(signal.excerpt)}</code>` : ''}</div>`).join('')}</div></div>
    <button class="btn btn-sm btn-ghost" data-finding-traffic="${esc(finding.rule_id)}" data-connection="${esc(finding.connection_id)}">Открыть запись</button>
  </article>`).join('');
  renderDetectors();
}

function renderDetectors() {
  const config = (state.detection && state.detection.config) || {};
  if (!['INPUT', 'SELECT'].includes(document.activeElement && document.activeElement.tagName)) {
    $('detector-enabled').checked = !!config.enabled;
    $('detector-builtins').checked = !!config.builtins;
    $('detector-threshold').value = config.threshold || 25;
    $('detector-autopin').value = config.auto_pin_score || 60;
  }
  $('detectors-list').innerHTML = (config.detectors || []).map((detector) => `<div class="detector-row">
    <label class="check"><input type="checkbox" data-detector-toggle="${esc(detector.id)}" ${detector.enabled ? 'checked' : ''}> <b>${esc(detector.name)}</b></label>
    <span class="tag">${esc(detector.mode)}${detector.case_insensitive ? ' · i' : ''}</span><span class="tag">${esc(detector.scope || 'stream')}</span><span class="tag warn">+${detector.score}</span>${detector.rule_ids && detector.rule_ids.length ? `<span class="tag">${detector.rule_ids.length} правил</span>` : ''}
    <code>${detector.sensitive ? '[скрытый шаблон]' : esc(detector.pattern)}</code>
    <button class="btn btn-sm btn-ghost btn-danger" data-detector-delete="${esc(detector.id)}">Удалить</button>
  </div>`).join('') || '<p class="dim">Пользовательских детекторов нет. Встроенные эвристики работают отдельно.</p>';
}

$('findings-query').addEventListener('input', renderFindings);
$('findings-score').addEventListener('change', renderFindings);
$('btn-findings-clear').addEventListener('click', async () => {
  if (!confirm('Очистить журнал подозрительного трафика? Закреплённые записи останутся.')) return;
  try { await api('/api/findings', { method: 'DELETE' }); await poll(); } catch (err) { toast(err.message, 'err'); }
});

$('findings-list').addEventListener('click', (event) => {
  const button = event.target.closest('[data-finding-traffic]');
  if (!button) return;
  document.querySelector('.tab[data-tab="traffic"]').click();
  $('traffic-rule').value = button.dataset.findingTraffic;
  expandedConns.clear();
  expandedConns.add(button.dataset.connection);
  resetTraffic();
});

$('btn-detector-settings').addEventListener('click', async () => {
  const config = Object.assign({}, (state.detection && state.detection.config) || {}, {
    enabled: $('detector-enabled').checked,
    builtins: $('detector-builtins').checked,
    threshold: parseInt($('detector-threshold').value, 10),
    auto_pin_score: parseInt($('detector-autopin').value, 10),
  });
  try { await api('/api/detectors', { method: 'PUT', body: JSON.stringify(config) }); toast('Настройки детекторов сохранены', 'ok'); poll(); }
  catch (err) { toast(err.message, 'err'); }
});

$('detector-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const detector = {
    name: $('detector-name').value.trim(), pattern: $('detector-pattern').value,
    enabled: true, mode: $('detector-mode').value, scope: $('detector-scope').value,
    direction: $('detector-direction').value, score: parseInt($('detector-score').value, 10),
    rule_ids: $('detector-rules').value.split(',').map((item) => item.trim()).filter(Boolean),
    case_insensitive: $('detector-case-insensitive').checked,
    sensitive: $('detector-sensitive').checked,
  };
  try {
    await api('/api/detectors', { method: 'POST', body: JSON.stringify(detector) });
    $('detector-form').reset(); $('detector-score').value = 60; toast('Детектор добавлен', 'ok'); poll();
  } catch (err) { toast(err.message, 'err'); }
});

$('detectors-list').addEventListener('change', async (event) => {
  const input = event.target.closest('[data-detector-toggle]');
  if (!input) return;
  const detector = ((state.detection && state.detection.config && state.detection.config.detectors) || []).find((item) => item.id === input.dataset.detectorToggle);
  if (!detector) return;
  try { await api(`/api/detectors/${encodeURIComponent(detector.id)}`, { method: 'PUT', body: JSON.stringify(Object.assign({}, detector, { enabled: input.checked })) }); poll(); }
  catch (err) { input.checked = !input.checked; toast(err.message, 'err'); }
});

$('detectors-list').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-detector-delete]');
  if (!button || !confirm('Удалить этот детектор?')) return;
  try { await api(`/api/detectors/${encodeURIComponent(button.dataset.detectorDelete)}`, { method: 'DELETE' }); poll(); }
  catch (err) { toast(err.message, 'err'); }
});

/* ── Нагрузка и события ──────────────────────────────────────── */
function renderMonitor() {
  const samples = state.metrics || [];
  const latest = samples[samples.length - 1] || {};
  const cards = [
    ['От клиента', fmtBytes(latest.bytes_in_per_sec || 0) + '/с'],
    ['От сервиса', fmtBytes(latest.bytes_out_per_sec || 0) + '/с'],
    ['Соединений', Number(latest.connections_per_sec || 0).toFixed(1) + '/с'],
    ['Активных', latest.active_conns || 0],
  ];
  $('metric-cards').innerHTML = cards.map(([label, value]) => `<div class="metric-card"><span>${label}</span><strong>${esc(value)}</strong></div>`).join('');
  renderChart('chart-traffic', 'Передача данных', samples, [
    { key: 'bytes_in_per_sec', label: 'От клиента', color: '#e3b341' },
    { key: 'bytes_out_per_sec', label: 'От сервиса', color: '#58a6ff' },
  ], (n) => fmtBytes(n) + '/с');
  renderChart('chart-connections', 'Новые соединения и ошибки', samples, [
    { key: 'connections_per_sec', label: 'Соединения', color: '#35d07f' },
    { key: 'failed_per_sec', label: 'Ошибки', color: '#f04f4f' },
  ], (n) => n.toFixed(1) + '/с');
  renderChart('chart-active', 'Активные соединения', samples, [
    { key: 'active_conns', label: 'Активные', color: '#a78bfa' },
  ], (n) => String(Math.round(n)));
  if (samples.length) {
    const first = samples[0].at;
    $('metrics-window').textContent = `Все пробросы · ${fmtTime(first)}–${fmtTime(latest.at)}`;
  }
  renderEvents();
}

function renderChart(id, title, samples, series, format) {
  const chart = chartSeries(samples, series.map((s) => s.key));
  const latest = samples[samples.length - 1] || {};
  const accessible = title + '. ' + series.map((s) => `${s.label}: ${format(Number(latest[s.key]) || 0)}`).join(', ');
  $(id).innerHTML = `<div class="chart-heading"><h3>${title}</h3><span class="dim">${esc(format(chart.max))}</span></div>
    <svg viewBox="0 0 560 146" role="img" aria-label="${esc(accessible)}" preserveAspectRatio="none">
      <path d="M0 4H560 M0 70H560 M0 136H560" class="chart-gridlines"/>
      ${chart.paths.map((points, i) => points ? `<polyline points="${points}" transform="translate(0 4)" fill="none" stroke="${series[i].color}" stroke-width="2" vector-effect="non-scaling-stroke"/>` : '').join('')}
      ${samples.length < 2 ? '<text x="280" y="76" text-anchor="middle" class="chart-placeholder">Собираем данные…</text>' : ''}
    </svg><div class="chart-times"><span>${chart.start ? fmtTime(chart.start) : '—'}</span><span>${chart.end ? fmtTime(chart.end) : '—'}</span></div>
    <div class="chart-legend">${series.map((s) => `<span><i style="background:${s.color}"></i>${s.label} <b>${esc(format(Number(latest[s.key]) || 0))}</b></span>`).join('')}</div>`;
}

function renderEvents() {
  const select = $('events-rule');
  const oldValue = select.value;
  const names = new Map();
  for (const rule of state.rules || []) names.set(rule.spec.id, rule.spec.name || rule.spec.listen_port);
  for (const event of state.events || []) if (event.rule_id && !names.has(event.rule_id)) names.set(event.rule_id, event.rule_name || event.rule_id);
  const options = '<option value="">Все правила</option>' + [...names].map(([id, name]) => `<option value="${esc(id)}">${esc(name)}</option>`).join('');
  if (select.innerHTML !== options && document.activeElement !== select) {
    select.innerHTML = options;
    if (names.has(oldValue)) select.value = oldValue;
  }
  const query = $('events-query').value.trim().toLocaleLowerCase('ru-RU');
  const events = (state.events || []).filter((event) => (!select.value || event.rule_id === select.value) &&
    (!query || `${event.rule_name || ''} ${event.kind || ''} ${event.message || ''}`.toLocaleLowerCase('ru-RU').includes(query)));
  const markup = events.map((event) => `<tr><td><time datetime="${esc(event.at)}" title="${esc(new Date(event.at).toLocaleString('ru-RU'))}">${fmtTime(event.at)}</time></td><td>${esc(event.rule_name || event.rule_id || 'Система')}</td><td><span class="event-kind">${esc(event.kind)}</span>${esc(event.message)}</td></tr>`).join('');
  if ($('events-list').innerHTML !== markup) $('events-list').innerHTML = markup;
  $('events-empty').classList.toggle('hidden', events.length > 0);
  $('events-count').textContent = `${events.length} событий`;
}

$('events-rule').addEventListener('change', renderEvents);
$('events-query').addEventListener('input', renderEvents);

/* ── Вкладки ─────────────────────────────────────────────────── */
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    openTab = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
    document.querySelectorAll('.tab-panel').forEach((p) => {
      p.classList.toggle('active', p.id === 'tab-' + openTab);
    });
    if (openTab === 'traffic') loadTraffic();
    else invalidateTraffic();
    if (openTab === 'findings') renderFindings();
    if (openTab === 'monitor') renderMonitor();
  });
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) invalidateTraffic();
  else if (!$('app').classList.contains('hidden')) {
    poll();
    if (openTab === 'traffic') loadTraffic();
  }
});

/* ── Старт ───────────────────────────────────────────────────── */
(async function init() {
  // Ссылка вида http://host:8420/#token=… избавляет от ручного ввода.
  const m = location.hash.match(/token=([^&]+)/);
  if (m) {
    token = decodeURIComponent(m[1]);
    localStorage.setItem('cpu_token', token);
    history.replaceState(null, '', location.pathname);
  }

  try {
    const ping = await fetch(API_BASE + '/ping').then((r) => r.json());
    if (!ping.auth) { showApp(); return; } // запущено с -no-auth
  } catch (e) { /* дальше разберёмся по /api/state */ }

  if (!token) { showLogin(); return; }
  try {
    state = await api('/api/state');
    showApp();
  } catch (err) {
    showLogin();
  }
})();
