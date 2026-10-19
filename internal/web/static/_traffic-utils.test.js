'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  escapeHTML, decodeBytes, joinStream, buildSearch, parseHeaderLines, chartSeries, fmtBytes, bytesToText, hexdump,
} = require('./traffic-utils.js');

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

test('hexdump aligns partial rows and escapes the ASCII column', () => {
  const bytes = Uint8Array.from([0x48, 0x69, 0x3c, 0x62, 0x3e, 0x26, 0x00, 0x7f, 0xff, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x0a]);
  const lines = hexdump(bytes).split('\n');
  assert.deepEqual(lines, [
    '<span class="off">00000000</span>  48 69 3c 62 3e 26 00 7f  ff 41 42 43 44 45 46 47  <span class="asc">Hi&lt;b&gt;&amp;...ABCDEFG</span>',
    `<span class="off">00000010</span>  0a ${' '.repeat(21)} ${' '.repeat(24)} <span class="asc">.</span>`,
  ]);
  assert.equal(lines[0].indexOf('<span class="asc">'), lines[1].indexOf('<span class="asc">'));
  assert.equal(hexdump(new Uint8Array(0)), '');
});

test('hexdump never emits markup from captured payloads', () => {
  const html = hexdump(new TextEncoder().encode('<img src=x onerror=alert(1)>"\''));
  assert.equal(/<img|onerror=alert\(1\)>|"'/.test(html), false);
  assert.equal(html.match(/<span/g).length, 4);
});

test('text view replaces control bytes but keeps whitespace and UTF-8', () => {
  const bytes = new TextEncoder().encode('a\x00b\tc\r\n\x1b[31mфлаг\x7f');
  assert.equal(bytesToText(bytes), 'a.b\tc\r\n.[31mфлаг.');
  assert.equal(bytesToText(Uint8Array.from([0x66, 0xff, 0x67])), 'f\ufffdg');
  assert.equal(bytesToText(new Uint8Array(0)), '');
});

test('byte sizes use binary units and stop at terabytes', () => {
  const cases = [[0, '0 B'], [undefined, '0 B'], [1, '1 B'], [1023, '1023 B'], [1024, '1.0 KB'],
    [1536, '1.5 KB'], [5 * 1024 ** 2, '5.0 MB'], [3 * 1024 ** 3, '3.0 GB'], [1024 ** 5, '1024.0 TB']];
  for (const [input, expected] of cases) assert.equal(fmtBytes(input), expected, String(input));
});
