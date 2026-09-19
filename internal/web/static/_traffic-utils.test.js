'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { escapeHTML, decodeBytes, joinStream, buildSearch, parseHeaderLines, chartSeries } = require('./traffic-utils.js');

test('untrusted service and traffic text cannot add HTML or attributes', () => {
  const input = '<img src=x onerror="alert(1)"> & \'test\'';
  assert.equal(escapeHTML(input), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &#39;test&#39;');
  assert.equal(escapeHTML(null), '');
  assert.equal(escapeHTML(0), '0');
});

test('whole streams preserve binary bytes, order and UTF-8 split across chunks', () => {
  const chunks = [
    { dir: 'in', data: Buffer.from([0, 0xd0]).toString('base64') },
    { dir: 'out', data: Buffer.from('response').toString('base64') },
    { dir: 'in', data: Buffer.from([0xbf, 0xff, 0x0a]).toString('base64') },
  ];
  assert.deepEqual([...joinStream(chunks, 'in')], [0, 0xd0, 0xbf, 0xff, 0x0a]);
  assert.equal(new TextDecoder().decode(joinStream(chunks, 'out')), 'response');
  assert.equal(new TextDecoder().decode(joinStream(chunks, 'in')).slice(1, 2), 'п');
  assert.equal(joinStream([], 'in').length, 0);
  assert.equal(decodeBytes('not-valid%%%').length, 0);
});

test('search encodes regex and address without introducing extra query parameters', () => {
  const regex = 'flag[0-9]+&offset=999#флаг';
  const query = new URLSearchParams(buildSearch({ q: regex, mode: 'regex', dir: 'out', remote: ' [::1]:8080 ', pinned: true }, 50));
  assert.equal(query.get('q'), regex);
  assert.equal(query.get('offset'), '50');
  assert.equal(query.get('limit'), '50');
  assert.equal(query.get('summary'), '1');
  assert.equal(query.get('remote'), '[::1]:8080');
  assert.equal(query.get('pinned'), '1');
  assert.equal(query.get('mode'), 'regex');
  assert.equal(query.get('dir'), 'out');
});

test('time filters preserve actual time and reject inverted intervals', () => {
  const query = new URLSearchParams(buildSearch({ from: '2026-09-16T12:00:00+07:00', to: '2026-09-16T06:00:00Z' }));
  assert.equal(query.get('from'), '2026-09-16T05:00:00.000Z');
  assert.equal(query.get('to'), '2026-09-16T06:00:00.000Z');
  assert.throws(() => buildSearch({ from: 'bad-date' }), /время/);
  assert.throws(() => buildSearch({ from: '2026-09-17', to: '2026-09-16' }), /раньше/);
});

test('empty search leaves optional filters absent', () => {
  const query = new URLSearchParams(buildSearch({}));
  assert.equal(query.get('mode'), 'text');
  assert.equal(query.get('dir'), 'any');
  for (const key of ['from', 'to', 'pinned', 'remote']) assert.equal(query.has(key), false);
});

test('health headers preserve colons in values and reject malformed names', () => {
  assert.deepEqual(parseHeaderLines('Authorization: Bearer a:b\r\nX-Probe: yes\n'), {
    Authorization: 'Bearer a:b',
    'X-Probe': 'yes',
  });
  assert.throws(() => parseHeaderLines('missing separator'), /Некорректный/);
  assert.throws(() => parseHeaderLines('Bad Name: value'), /Некорректный/);
});

test('chart x coordinates represent elapsed time and share a y scale', () => {
  const result = chartSeries([
    { at: '2026-09-16T00:00:00Z', incoming: 0, outgoing: 20 },
    { at: '2026-09-16T00:00:01Z', incoming: 10, outgoing: 0 },
    { at: '2026-09-16T00:00:10Z', incoming: 20, outgoing: 10 },
  ], ['incoming', 'outgoing'], 100, 40);
  assert.equal(result.max, 20);
  assert.equal(result.paths[0], '0.0,40.0 10.0,20.0 100.0,0.0');
  assert.equal(result.paths[1], '0.0,0.0 10.0,40.0 100.0,20.0');
});

test('charts remain finite for empty, single and malformed samples', () => {
  assert.deepEqual(chartSeries([], ['rate']).paths, ['']);
  const result = chartSeries([
    { at: 'bad-date', rate: 40 },
    { at: '2026-09-16T00:00:00Z', rate: Infinity },
    { at: '2026-09-16T00:00:00Z', rate: -1 },
  ], ['rate']);
  assert.equal(result.max, 1);
  assert.equal(result.paths[0], '560.0,132.0 560.0,132.0');
  assert.equal(/NaN|Infinity/.test(result.paths[0]), false);
});
