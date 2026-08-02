/* CTF-ProxyUtils — фронтенд панели.
   Без внешних зависимостей: файл вшит в бинарник и должен открываться
   на голой виртуалке без интернета. */

'use strict';

const $ = (id) => document.getElementById(id);

let token = localStorage.getItem('cpu_token') || '';
let state = { rules: [], scan: {}, system: {} };
let pollTimer = null;
let expandedConns = new Set();
let openTab = 'rules';
let editingId = null;
let trafficView = 'hex';

/* ── Экранирование ────────────────────────────────────────────
   Баннеры сервисов, имена хостов и дампы трафика приходят с чужих
   машин. Всё, что попадает в разметку, обязано быть экранировано —
   иначе чужой баннер выполнит скрипт в нашей же панели. */
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* ── Обращения к API ─────────────────────────────────────────── */
async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (token) headers['X-Auth-Token'] = token;
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
    await fetch('/api/login', {
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
  if (document.hidden) return; // фоновая вкладка не нагружает виртуалку
  try {
    state = await api('/api/state');
    $('conn-dot').classList.remove('stale');
    render();
  } catch (err) {
    $('conn-dot').classList.add('stale');
  }
}

function render() {
  const sys = state.system || {};
  $('sys-host').textContent = sys.hostname || '';
  $('badge-rules').textContent = (state.rules || []).length;
  renderRules();
  renderScan();
  renderTrafficSelect();
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

  list.innerHTML = rules.map(ruleCard).join('');

  list.querySelectorAll('[data-act]').forEach((btn) => {
    btn.addEventListener('click', () => ruleAction(btn.dataset.id, btn.dataset.act));
  });
}

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
  if (r.using_backup) tags.push('<span class="tag warn">на резерве</span>');
  if (s.dump.enabled) tags.push(`<span class="tag">запись ${r.dump_count}</span>`);
  if (s.allow_cidr && s.allow_cidr.length) tags.push('<span class="tag">ACL</span>');

  const hasBackup = s.backup && s.backup.host;

  return `
  <div class="${cls}">
    <div class="rule-head">
      <span class="rule-name">${esc(s.name || 'без названия')}</span>
      <span class="rule-path">
        ${esc(s.listen_host)}:${s.listen_port}<span class="to">→</span>${esc(target.host)}:${target.port}
      </span>
      ${tags.join('')}
      <div class="rule-actions">
        ${hasBackup ? `<button class="btn btn-sm btn-ghost" data-act="switch" data-id="${esc(s.id)}">
            ${r.using_backup ? 'на основной' : 'на резерв'}</button>` : ''}
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
      <span>${fmtAgo(r.last_active_unix_ms)}</span>
    </div>
    ${r.last_error ? `<div class="rule-error">${esc(r.last_error)}</div>` : ''}
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
    } else if (act === 'switch') {
      await api(`/api/rules/${id}/switch`, {
        method: 'POST',
        body: JSON.stringify({ backup: !rule.using_backup }),
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
    health: { enabled: false, interval_sec: 3, timeout_ms: 1000, fail_after: 2, rise_after: 2, auto_failover: true, auto_failback: true },
    dump: { enabled: false, max_conns: 50, max_bytes_per: 65536 },
    allow_cidr: [], max_conns: 0, idle_timeout_sec: 0, dial_timeout_ms: 3000,
    enabled: true,
  };

  $('f-name').value = s.name || '';
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
  $('f-autofail').checked = s.health.auto_failover !== false;
  $('f-autoback').checked = s.health.auto_failback !== false;

  $('f-dump').checked = !!s.dump.enabled;
  $('f-dump-conns').value = s.dump.max_conns || 50;
  $('f-dump-kb').value = Math.round((s.dump.max_bytes_per || 65536) / 1024);

  $('f-acl').value = (s.allow_cidr || []).join(', ');
  $('f-maxconns').value = s.max_conns || 0;
  $('f-idle').value = s.idle_timeout_sec || 0;
  $('f-dial').value = s.dial_timeout_ms || 3000;
  $('f-enabled').checked = s.enabled !== false;

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

$('rule-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const backupHost = $('f-backup-host').value.trim();
  const backupPort = parseInt($('f-backup-port').value, 10);
  const acl = $('f-acl').value.split(',').map((s) => s.trim()).filter(Boolean);

  const spec = {
    name: $('f-name').value.trim(),
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
    },
    dump: {
      enabled: $('f-dump').checked,
      max_conns: parseInt($('f-dump-conns').value, 10),
      max_bytes_per: parseInt($('f-dump-kb').value, 10) * 1024,
    },
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
  $('scan-results').innerHTML = hosts.map(hostCard).join('');

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
  const rules = (state.rules || []).filter((r) => r.spec.dump.enabled);
  const cur = sel.value;
  const opts = rules.map((r) =>
    `<option value="${esc(r.spec.id)}">${esc(r.spec.name || r.spec.listen_port)} — ${r.dump_count} записей</option>`
  ).join('');
  if (sel.innerHTML !== opts) {
    sel.innerHTML = opts || '<option value="">нет правил с записью трафика</option>';
    if (cur && rules.some((r) => r.spec.id === cur)) sel.value = cur;
  }
}

async function loadTraffic() {
  const id = $('traffic-rule').value;
  if (!id) {
    $('traffic-list').innerHTML = '';
    $('traffic-empty').classList.remove('hidden');
    return;
  }
  try {
    const dumps = await api(`/api/rules/${id}/dumps`);
    $('traffic-empty').classList.toggle('hidden', dumps.length > 0);
    $('traffic-list').innerHTML = dumps.map(connCard).join('');
    $('traffic-list').querySelectorAll('.conn-head').forEach((el) => {
      el.addEventListener('click', () => {
        const cid = el.dataset.cid;
        if (expandedConns.has(cid)) expandedConns.delete(cid); else expandedConns.add(cid);
        loadTraffic();
      });
    });
  } catch (err) {
    toast(err.message, 'err');
  }
}

function connCard(c) {
  const open = expandedConns.has(String(c.id));
  const dur = c.ended_at && c.started_at
    ? ((new Date(c.ended_at) - new Date(c.started_at)) / 1000).toFixed(1) + ' с'
    : 'открыто';

  let body = '';
  if (open) {
    body = `<div class="conn-body">
      <div class="view-toggle">
        <button class="btn btn-sm ${trafficView === 'hex' ? 'btn-primary' : 'btn-ghost'}" data-view="hex">hex</button>
        <button class="btn btn-sm ${trafficView === 'text' ? 'btn-primary' : 'btn-ghost'}" data-view="text">текст</button>
      </div>
      ${(c.chunks || []).map(chunkBlock).join('') || '<p class="dim">пусто</p>'}
      ${c.truncated ? '<p class="hint">запись обрезана по лимиту</p>' : ''}
    </div>`;
  }

  return `
  <div class="conn">
    <div class="conn-head" data-cid="${c.id}">
      <span>${open ? '▾' : '▸'}</span>
      <span class="conn-remote">${esc(c.remote_addr)}</span>
      <span class="dim">→ ${esc(c.target)}</span>
      <span class="dim">${fmtTime(c.started_at)}</span>
      <span class="dim">↓${fmtBytes(c.bytes_in)} ↑${fmtBytes(c.bytes_out)}</span>
      <span class="dim">${dur}</span>
    </div>
    ${body}
  </div>`;
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
  if (!b64) return new Uint8Array(0);
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch (e) {
    return new Uint8Array(0);
  }
}

// bytesToText показывает полезную нагрузку как текст, заменяя непечатаемое.
function bytesToText(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += (b === 10 || b === 13 || b === 9 || (b >= 32 && b < 127))
      ? String.fromCharCode(b) : '.';
  }
  return s;
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

$('traffic-rule').addEventListener('change', loadTraffic);
$('btn-traffic-refresh').addEventListener('click', loadTraffic);
$('btn-traffic-clear').addEventListener('click', async () => {
  const id = $('traffic-rule').value;
  if (!id || !confirm('Стереть записанный трафик этого правила?')) return;
  try {
    await api(`/api/rules/${id}/dumps`, { method: 'DELETE' });
    expandedConns.clear();
    loadTraffic();
    toast('Записи стёрты', 'ok');
  } catch (err) { toast(err.message, 'err'); }
});

$('traffic-list').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-view]');
  if (!btn) return;
  trafficView = btn.dataset.view;
  loadTraffic();
});

let trafficTimer = null;
$('traffic-auto').addEventListener('change', (e) => {
  if (e.target.checked) {
    trafficTimer = setInterval(() => { if (openTab === 'traffic') loadTraffic(); }, 2000);
  } else if (trafficTimer) {
    clearInterval(trafficTimer);
    trafficTimer = null;
  }
});

/* ── Вкладки ─────────────────────────────────────────────────── */
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    openTab = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
    document.querySelectorAll('.tab-panel').forEach((p) => {
      p.classList.toggle('active', p.id === 'tab-' + openTab);
    });
    if (openTab === 'traffic') loadTraffic();
  });
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
    const ping = await fetch('/api/ping').then((r) => r.json());
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
