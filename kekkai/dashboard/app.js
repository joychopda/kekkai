'use strict';

// Polls a read-only endpoint every few seconds. Deliberately no websockets and no charting
// library: the page is a bounded view of the log's tail, and keeping it dependency-free means
// it works from a file server, offline, forever.
var POLL_MS = 5000;
var SCORE_NAMES = ['Safe', 'Low', 'High', 'Critical'];

function el(tag, cls, text) {
  var node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function tile(label, value, note, tone) {
  var t = el('div', 'tile' + (tone ? ' ' + tone : ''));
  t.appendChild(el('div', 'label', label));
  t.appendChild(el('div', 'value', value));
  if (note) t.appendChild(el('div', 'note', note));
  return t;
}

function renderTiles(s) {
  var root = document.getElementById('tiles');
  root.textContent = '';
  root.appendChild(tile('Screened', s.screened, 'tool calls in this log'));
  root.appendChild(tile('Blocked', s.blocked, (s.block_rate * 100).toFixed(1) + '% of calls',
    s.blocked > 0 ? 'bad' : null));
  root.appendChild(tile('Failed closed', s.failed_closed,
    s.failed_closed ? 'classifier unavailable' : 'no backend outages',
    s.failed_closed > 0 ? 'warn' : 'good'));
  // A rising count here is the in-production symptom of a classifier being injected: the
  // deterministic layer blocking something the model rated safe.
  root.appendChild(tile('Prefilter overrides', s.prefilter_overrides,
    'rules overruled the model', s.prefilter_overrides > 0 ? 'warn' : null));
  root.appendChild(tile('Latency p95', s.p95_ms.toFixed(1) + 'ms', 'p50 ' + s.p50_ms.toFixed(1) + 'ms'));
  var chainOk = s.chain.status === 'ok';
  root.appendChild(tile('Audit chain', chainOk ? 'intact' : s.chain.status.replace('_', ' '),
    s.chain.checked + ' records verified', chainOk ? 'good' : (s.chain.status === 'broken' ? 'bad' : 'warn')));
}

function renderHistogram(hist) {
  var root = document.getElementById('histogram');
  root.textContent = '';
  var counts = [0, 1, 2, 3].map(function (i) { return hist[String(i)] || 0; });
  var max = Math.max.apply(null, counts.concat([1]));
  counts.forEach(function (count, i) {
    var row = el('div', 'hrow');
    row.appendChild(el('div', null, SCORE_NAMES[i]));
    var track = el('div');
    var bar = el('div', 'hbar');
    bar.style.width = Math.round((count / max) * 100) + '%';
    bar.style.background = 'var(--s' + i + ')';
    track.appendChild(bar);
    row.appendChild(track);
    row.appendChild(el('div', 'hcount', count));
    root.appendChild(row);
  });
}

function renderEvents(events) {
  var body = document.querySelector('#events tbody');
  body.textContent = '';
  document.getElementById('empty').hidden = events.length > 0;
  events.forEach(function (e) {
    var tr = el('tr');
    var time = new Date(e.ts * 1000).toLocaleTimeString();
    tr.appendChild(el('td', 'mono', time));

    var cell = el('td');
    var pill = el('span', 'pill ' + (e.decision === 'block' ? 'block' : 'allow'), e.decision);
    cell.appendChild(pill);
    tr.appendChild(cell);

    tr.appendChild(el('td', null, SCORE_NAMES[e.score] || e.score));
    tr.appendChild(el('td', 'mono', e.tool));
    tr.appendChild(el('td', null, e.choice));
    tr.appendChild(el('td', 'mono', e.probability.toFixed(3)));
    tr.appendChild(el('td', 'mono', e.latency_ms.toFixed(1) + 'ms'));

    var reason = e.reason || '';
    if (e.fenced && e.fenced.length) reason += (reason ? '  ' : '') + '[fenced: ' + e.fenced.join(', ') + ']';
    tr.appendChild(el('td', 'reason', reason));
    body.appendChild(tr);
  });
}

function refresh() {
  fetch('/api/state', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      document.getElementById('logdir').textContent = data.log_dir;
      document.getElementById('updated').textContent = 'updated ' + new Date().toLocaleTimeString();
      renderTiles(data.summary);
      renderHistogram(data.summary.score_histogram);
      renderEvents(data.events);
    })
    .catch(function (err) {
      document.getElementById('updated').textContent = 'could not reach the server: ' + err.message;
    });
}

refresh();
setInterval(refresh, POLL_MS);
