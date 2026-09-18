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

  const exported = { escapeHTML, decodeBytes, joinStream, buildSearch, chartSeries };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  else root.TrafficUtils = exported;
})(typeof globalThis === 'undefined' ? this : globalThis);
