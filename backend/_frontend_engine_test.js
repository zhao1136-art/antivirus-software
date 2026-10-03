/*
 * engine.html heuristic-card verification.
 *
 * VERIFICATION HARNESS (not part of the app; safe to delete). Added 2026-10-03
 * with the "heuristic" engine card. No backend needed:
 *     node _frontend_engine_test.js
 *
 * Runs the page's REAL inline script against a permissive DOM stub, then checks
 * that the new "heuristic" card exists, renders with the same structure as the
 * existing cards, and that the 13 deferred engines were NOT added.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'frontend', 'engine.html'), 'utf8');
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const mainScript = scripts.slice().sort((a, b) => b.length - a.length)[0];

function makeElement(id) {
    const el = {
        id: id, innerHTML: '', textContent: '', value: '',
        style: {}, dataset: {}, className: '', children: [],
        classList: { _s: new Set(), add() {}, remove() {}, toggle() {}, contains() { return false; } },
        addEventListener() {}, removeEventListener() {}, appendChild(c) { el.children.push(c); },
        replaceChildren(n) { el.children = [n]; },
        querySelector() { return makeElement('q'); },
        querySelectorAll() { return []; },
        setAttribute() {}, getAttribute() { return null; }, closest() { return null; }
    };
    return el;
}
const els = new Map();
const byId = id => { if (!els.has(id)) els.set(id, makeElement(id)); return els.get(id); };

const documentStub = {
    getElementById: byId,
    querySelector: () => makeElement('q'),
    querySelectorAll: () => [],
    createElement: () => makeElement('created'),
    createDocumentFragment: () => makeElement('frag'),
    addEventListener() {},
    documentElement: makeElement('html'),
    body: makeElement('body')
};

// run the real page script; expose its internals so we can confirm it rendered
const fetchStub = (url) => {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/v1/etw/status') >= 0) body = { running: true };
    else if (u.indexOf('/api/v1/amsi/status') >= 0) body = { registered: true };
    else if (u.indexOf('/api/v1/protection/status') >= 0) body = { modules: {}, realtime_enabled: true };
    return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
};
const exposed = new Function('document', 'window', 'localStorage', 'fetch', 'console',
    'setInterval', 'setTimeout', 'clearInterval', 'clearTimeout',
    mainScript + '\nreturn {engines: engines, engine: engine, app: app};')(
    documentStub,
    { addEventListener() {}, location: { origin: 'http://127.0.0.1:8899' } },
    { getItem: () => null, setItem() {} },
    fetchStub,
    { log() {}, warn() {}, error() {} },
    () => 0, () => 0, () => {}, () => {}
);

let pass = 0, fail = 0;
const failures = [];
function check(label, cond, extra) {
    if (cond) { pass++; console.log('  PASS  ' + label); }
    else { fail++; failures.push(label + (extra ? '  << ' + extra : '')); console.log('  FAIL  ' + label + (extra ? '  << ' + extra : '')); }
}

(async function main() {
    // app.start() schedules engines.refresh() via setTimeout, which this harness
    // stubs out; call the page's own render path directly instead of waiting.
    try {
        await exposed.engines.refresh();
    } catch (e) {
        console.log('  NOTE engines.refresh() threw: ' + e.message);
    }
    for (let i = 0; i < 20 && !(byId('engineGrid').children[0] && byId('engineGrid').children[0].children.length); i++) {
        await new Promise(r => setTimeout(r, 5));
    }

    console.log('\n=== engine.html: cards rendered ===');
    check('page script exposed its engines module', !!exposed.engines);
    check('registry has 4 entries', exposed.engines.registry.length === 4,
        'got ' + exposed.engines.registry.length);

    const grid = byId('engineGrid');
    const frag = grid.children[0];
    const cards = (frag && frag.children) || [];
    const ids = cards.map(c => c.dataset && c.dataset.id);
    const allHtml = cards.map(c => c.innerHTML).join('\n');
    console.log('  card ids: ' + JSON.stringify(ids));

    check('4 cards rendered', cards.length === 4, 'got ' + cards.length);
    check('existing ml_pe card still present', ids.indexOf('ml_pe') >= 0);
    check('existing etw card still present', ids.indexOf('etw') >= 0);
    check('existing amsi card still present', ids.indexOf('amsi') >= 0);
    check('new heuristic card present', ids.indexOf('heuristic') >= 0);
    check('new card appended last (order preserved)', ids[ids.length - 1] === 'heuristic');

    const hcard = (cards.find(c => c.dataset.id === 'heuristic') || { innerHTML: '' }).innerHTML;
    check('heuristic card has .ec-head structure', hcard.indexOf('ec-head') >= 0);
    check('heuristic card has icon slot with svg', hcard.indexOf('ec-icon') >= 0 && hcard.indexOf('<svg') >= 0);
    check('heuristic card shows its name', hcard.indexOf('\u542f\u53d1\u5f0f\u5f15\u64ce') >= 0);
    check('heuristic card shows status badge', hcard.indexOf('ec-status') >= 0);
    check('badge is ok / 就绪 (same form as ML PE card)', hcard.indexOf('ec-status ok') >= 0 && hcard.indexOf('\u5c31\u7eea') >= 0);
    check('heuristic card has a description', hcard.indexOf('ec-desc') >= 0);
    check('desc mentions script heuristic (generic script/OLE/PDF/driver)',
        hcard.indexOf('\u811a\u672c/OLE/PDF/\u9a71\u52a8\u901a\u7528\u542f\u53d1\u5f0f') >= 0);
    check('desc mentions OLE and PDF', hcard.indexOf('OLE') >= 0 && hcard.indexOf('PDF') >= 0);
    check('desc mentions PE heuristic', hcard.indexOf('PE') >= 0);
    check('desc mentions URL phishing', hcard.indexOf('URL') >= 0);
    check('desc mentions ransomware text', hcard.indexOf('\u52d2\u7d22') >= 0);
    check('static card has no action buttons', hcard.indexOf('ec-btn') < 0);
    check('ML PE card also has no buttons (style parity)', (cards.find(c => c.dataset.id === 'ml_pe') || { innerHTML: '' }).innerHTML.indexOf('ec-btn') < 0);
    check('etw card keeps its toggle button', (cards.find(c => c.dataset.id === 'etw') || { innerHTML: '' }).innerHTML.indexOf('ec-btn') >= 0);
    check('summary counts 4 engines',
        byId('engineSummary').textContent.indexOf('4 / 4') === 0,
        'got ' + byId('engineSummary').textContent);

    console.log('\n=== deferred engines must NOT be present ===');
    const existingIds = exposed.engines.registry.map(c => c.id);
    const registryJson = JSON.stringify(exposed.engines.registry);
    const deferred = [
        ['YARA 规则扫描', 'yara'],
        ['哈希特征库', 'hash'],
        ['云引擎 (3 家)', 'cloud'],
        ['原生模块 (6 个)', 'native'],
        ['C2 情报', 'c2_intel'],
        ['行为拦截', 'behavior'],
        ['广告拦截', 'adblock'],
        ['沙箱隔离', 'sandbox']
    ];
    for (const [label, key] of deferred) {
        const inRegistry = existingIds.some(id => String(id).toLowerCase().indexOf(key) >= 0);
        check('not added: ' + label, !inRegistry,
            'registry=' + JSON.stringify(existingIds));
    }
    check('registry is exactly the intended 4',
        JSON.stringify(existingIds) === JSON.stringify(['ml_pe', 'etw', 'amsi', 'heuristic']),
        'got ' + JSON.stringify(existingIds));

    console.log('\n---------------------------------------------');
    console.log('PASS ' + pass + '   FAIL ' + fail);
    if (fail) { console.log('failed:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
    console.log('engine page card assertions OK');
})();
