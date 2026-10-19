/* Shared by the offline panel and Node's built-in test runner. */
(function (root) {
  'use strict';

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[ch]);
  }

  function decodeBytes(base64) {
    if (!base64) return new Uint8Array(0);
    try { return Uint8Array.from(atob(base64), (ch) => ch.charCodeAt(0)); }
    catch (_) { return new Uint8Array(0); }
  }

  function joinStream(chunks, direction) {
    const parts = (chunks || []).filter((ch) => ch.dir === direction).map((ch) => decodeBytes(ch.data));
    const bytes = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
    let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    return bytes;
  }

  function buildSearch(filters, offset = 0) {
    const query = new URLSearchParams({ summary: '1', offset: String(offset), limit: '50' });
    query.set('q', filters.q || '');
    query.set('mode', filters.mode || 'text');
    query.set('dir', filters.dir || 'any');
    if (filters.remote) query.set('remote', filters.remote.trim());
    if (filters.pinned) query.set('pinned', '1');
    for (const key of ['from', 'to']) {
      if (!filters[key]) continue;
      const date = new Date(filters[key]);
      if (!Number.isFinite(date.getTime())) throw new Error('Некорректное время фильтра');
      query.set(key, date.toISOString());
    }
    if (filters.from && filters.to && new Date(filters.from) > new Date(filters.to)) {
      throw new Error('Время «с» должно быть раньше времени «до»');
    }
    return query.toString();
  }

  function parseHeaderLines(value) {
    const headers = {};
    for (const line of String(value || '').split(/\r?\n/)) {
      if (!line.trim()) continue;
      const separator = line.indexOf(':');
      if (separator < 1) throw new Error(`Некорректный HTTP-заголовок: ${line}`);
      const name = line.slice(0, separator).trim();
      const headerValue = line.slice(separator + 1).trim();
      if (!name || /[\s:]/.test(name) || /[\r\n]/.test(headerValue)) throw new Error(`Некорректный HTTP-заголовок: ${line}`);
      headers[name] = headerValue;
    }
    return headers;
  }

  // Use actual sample times so a pause in sampling does not compress the x-axis.
  function chartSeries(samples, keys, width = 560, height = 132) {
    const data = (samples || []).filter((s) => Number.isFinite(Date.parse(s.at)));
    const value = (s, key) => Number.isFinite(Number(s[key])) ? Math.max(0, Number(s[key])) : 0;
    const max = Math.max(1, ...data.flatMap((s) => keys.map((key) => value(s, key))));
    const start = data.length ? Date.parse(data[0].at) : 0;
    const end = data.length ? Date.parse(data[data.length - 1].at) : start;
    const paths = keys.map((key) => data.map((s) => {
      const x = end === start ? width : (Date.parse(s.at) - start) / (end - start) * width;
      const y = height - value(s, key) / max * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' '));
    return { paths, max, start, end };
  }

  function fmtBytes(n) {
    if (!n) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
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
        `<span class="off">${off.toString(16).padStart(8, '0')}</span>  ${hex} <span class="asc">${escapeHTML(asc)}</span>`
      );
    }
    return lines.join('\n');
  }

  const exported = { escapeHTML, decodeBytes, joinStream, buildSearch, parseHeaderLines, chartSeries, fmtBytes, bytesToText, hexdump };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  else root.TrafficUtils = exported;
})(typeof globalThis === 'undefined' ? this : globalThis);
