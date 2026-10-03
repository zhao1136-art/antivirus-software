/*
 * sandbox.html -- isolation capabilities + memory scan panel test
 *
 * VERIFICATION HARNESS (not part of the app; safe to delete). Added 2026-10-03
 * alongside the memory_scan / isolation.capabilities panels. No backend and no
 * network needed -- it runs the page's real inline script against a DOM stub:
 *     node _frontend_panel_test.js
 *
 * Runs the REAL inline script of frontend/sandbox.html (no re-implementation)
 * against a minimal DOM stub, then drives the two new pure renderers with fake
 * report objects and asserts every branch the task requires:
 *   - memory_scan.ok === false  -> reason visible, never rendered as "safe"
 *   - memory_scan.ok === true   -> module/byte/elapsed/hit stats + interpretation
 *   - capabilities.absolute_path_redirect === false -> shown as a LIMITATION
 *   - capabilities.limitation text shown verbatim
 *   - coverage / exec_path / copied_files / copied_bytes / truncated / engine_notes
 *   - verdict unknown never renders as "safe"; degraded_reason prominent
 */
'use strict';
const fs = require('fs');
const path = require('path');

const PAGE = path.join(__dirname, 'frontend', 'sandbox.html');
const html = fs.readFileSync(PAGE, 'utf8');

// ---------- pull the page's main inline script (the one defining the panels) ----
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)]
    .map(m => m[1]);
const mainScript = scripts.find(s => s.indexOf('function renderMemoryScan') >= 0);
if (!mainScript) throw new Error('could not locate the panel script in sandbox.html');

// ---------- minimal DOM stub (only what the page script touches) ----------
function makeElement(id) {
    const el = {
        id: id,
        innerHTML: '', textContent: '', value: '',
        style: {}, dataset: {},
        className: '',
        classList: {
            _s: new Set(),
            add(c) { this._s.add(c); },
            remove(c) { this._s.delete(c); },
            toggle(c, on) { if (on === undefined) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); } else if (on) { this._s.add(c); } else { this._s.delete(c); } },
            contains(c) { return this._s.has(c); }
        },
        addEventListener() {}, removeEventListener() {}, appendChild() {},
        querySelector() { return makeElement('q'); },
        setAttribute() {}, getAttribute() { return null; },
        closest() { return null; }
    };
    return el;
}
const els = new Map();
const byId = id => { if (!els.has(id)) els.set(id, makeElement(id)); return els.get(id); };
const documentStub = {
    getElementById: byId,
    querySelector: () => makeElement('q'),
    querySelectorAll: () => [],
    createElement: () => makeElement('new'),
    addEventListener: () => {},
    documentElement: makeElement('html'),
    body: makeElement('body')
};
const store = {};
const localStorageStub = {
    getItem: k => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; }
};

// ---------- run the real script and hand back its internals ----------
const R = new Function(
    'document', 'window', 'localStorage', 'fetch', 'console', 'setInterval', 'setTimeout', 'clearInterval', 'clearTimeout', 'alert',
    mainScript + '\nreturn {esc:esc, fmtBytes:fmtBytes, memHitModule:memHitModule,' +
    ' memHitCred:memHitCred, renderMemoryScan:renderMemoryScan,' +
    ' renderCapabilities:renderCapabilities, renderReport:renderReport};'
)(
    documentStub,
    { addEventListener() {}, scrollTo() {}, location: { origin: 'http://127.0.0.1:8899' } },
    localStorageStub,
    () => Promise.resolve({ ok: true, json: () => Promise.resolve(null) }),
    { log() {}, warn() {}, error() {} },
    () => 0, () => 0, () => {}, () => {}, () => {}
);

// ---------- assertion helpers ----------
let pass = 0, fail = 0;
const failures = [];
function check(label, cond, extra) {
    if (cond) { pass++; console.log('  PASS  ' + label); }
    else { fail++; failures.push(label + (extra ? '  << ' + extra : '')); console.log('  FAIL  ' + label + (extra ? '  << ' + extra : '')); }
}

const LIMITATION = '\u6837\u672c\u5f15\u7528\u7684\u7edd\u5bf9\u8def\u5f84\u4e0d\u4f1a\u88ab\u91cd\u5b9a\u5411\uff1b\u771f CoW \u9700\u8981\u5185\u6838\u9a71\u52a8\u6216 ProjFS';
const REASON = '\u8fdb\u7a0b\u5df2\u81ea\u884c\u9000\u51fa\uff0c\u65e0\u6cd5\u626b\u63cf\u5185\u5b58';
const INTERP_UNCOVERED = '\u672a\u8986\u76d6\u5185\u5b58';
const INTERP_HIT = '\u78c1\u76d8\u672a\u547d\u4e2d\u4f46\u5185\u5b58\u547d\u4e2d \u2014\u2014 \u9ad8\u5ea6\u6000\u7591\u52a0\u58f3\u6216\u6ce8\u5165';
const NOTE1 = '\u6837\u672c\u76ee\u5f55\u4f4d\u4e8e\u7cfb\u7edf\u76ee\u5f55\u6811\u4e0b\uff08C:\\Windows\uff09\uff0c\u8df3\u8fc7\u540c\u76ee\u5f55\u6279\u91cf\u590d\u5236';

// ---------- fake report 1: memory NOT covered (process exited by itself) ----------
const repUncovered = {
    verdict: 'unknown', score: 0,
    isolation: {
        job_object: true, network_blocked: true, integrity_level: 'low',
        degraded_reason: '\u5185\u5b58\u955c\u50cf\u626b\u63cf\u5931\u8d25: OpenProcess \u5931\u8d25 err=5',
        low_il_workdir: 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\yutian_sandbox\\sandbox_1791012408980',
        firewall_rule: 'caelire_sandbox_block_sandbox_1791012408980_5640',
        firewall_rule_removed: false,
        created_via: 'CreateProcessAsUserW(low_il)',
        engine: 'copy', engine_requested: 'copy',
        capabilities: {
            file_copy: true, absolute_path_redirect: false, registry_redirect: false,
            writable_sandbox: true, coverage: 'sample_and_its_directory',
            limitation: LIMITATION,
            copy_scope: 'sample + same_directory_files(dll/config/resource)',
            max_total_bytes: 268435456, max_files: 512,
            max_single_file_bytes: 67108864, truncated_capable: true
        },
        exec_path: 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\yutian_sandbox\\sandbox_1791012408980\\notepad.exe',
        copied_files: 1, copied_bytes: 200704, truncated: true,
        engine_notes: [NOTE1]
    },
    memory_scan: { ok: false, error: REASON, interpretation: INTERP_UNCOVERED }
};

// ---------- fake report 2: memory covered, disk clean but memory hit ----------
const repMemoryHit = {
    verdict: 'malicious', score: 80,
    isolation: {
        job_object: true, network_blocked: true, integrity_level: 'low',
        degraded_reason: '', low_il_workdir: 'C:\\Temp\\yutian_sandbox\\s2',
        firewall_rule: 'caelire_sandbox_block_s2_1', firewall_rule_removed: true,
        created_via: 'CreateProcessAsUserW(low_il)',
        engine: 'copy', engine_requested: 'none',
        capabilities: {
            file_copy: true, absolute_path_redirect: false, registry_redirect: false,
            writable_sandbox: true, coverage: 'sample_and_its_directory',
            limitation: LIMITATION,
            copy_scope: 'sample + same_directory_files(dll/config/resource)',
            max_total_bytes: 268435456, max_files: 512,
            max_single_file_bytes: 67108864, truncated_capable: true
        },
        exec_path: 'C:\\Temp\\yutian_sandbox\\s2\\notepad.exe',
        copied_files: 1, copied_bytes: 200704, truncated: false,
        engine_notes: ['NOTE-ONE', 'NOTE-TWO']
    },
    memory_scan: {
        ok: true, error: '', pid: 2284, modules_total: 35, modules_read: 35,
        scanned_bytes: 46399488, truncated: false,
        skipped: [['kernel32.dll', 'READ-FAIL']],
        elapsed_ms: 3548.4, interpretation: INTERP_HIT,
        hits: [
            { rule: 'RULE_HIGH', confidence: 'high', _module: 'notepad.exe', _source: 'memory' },
            { rule: 'RULE_MED', confidence: 'medium', _module: 'shell32.dll' },
            { rule: 'RULE_LOW', confidence: 'low', _module: 'ntdll.dll', quality_reason: 'effective-literal-4-bytes' }
        ]
    }
};

console.log('\n=== scenario 1: memory_scan.ok === false (degraded report) ===');
const h1mem = R.renderMemoryScan(repUncovered.memory_scan);
const h1cap = R.renderCapabilities(repUncovered.isolation);

check('ok:false panel rendered (non-empty)', h1mem.length > 0);
check('ok:false shows the real reason', h1mem.indexOf(REASON) >= 0);
check('ok:false marked "uncovered"', h1mem.indexOf('mem-panel uncovered') >= 0);
check('ok:false carries explicit warning (not safe)', h1mem.indexOf('\u4e0d\u80fd\u636e\u6b64\u8ba4\u5b9a\u5b89\u5168') >= 0);
check('ok:false shows interpretation', h1mem.indexOf(INTERP_UNCOVERED) >= 0);
check('ok:false does NOT claim "covered / no hit"', h1mem.indexOf('\u5df2\u8986\u76d6') < 0);
check('ok:false does NOT render a hit count', h1mem.indexOf('\u547d\u4e2d ') < 0);
check('ok:false stat says 未覆盖', h1mem.indexOf('\u672a\u8986\u76d6') >= 0);

check('capabilities block absent when no capabilities', R.renderCapabilities({ engine: 'none' }) === '');
check('capabilities rendered when present', h1cap.length > 0);
check('shows engine: copy', h1cap.indexOf('engine: copy') >= 0);
check('engine_requested == engine -> no downgrade note', h1cap.indexOf('\u5df2\u964d\u7ea7') < 0);
check('absolute_path_redirect false flagged as limitation',
    h1cap.indexOf('\u4e0d\u652f\u6301\uff08\u8fd9\u662f\u9650\u5236\uff0c\u4e0d\u662f\u7279\u6027\uff09') >= 0);
check('absolute_path_redirect row highlighted (cap-row-limit)', h1cap.indexOf('cap-row-limit') >= 0);
check('explains absolute paths still hit real system', h1cap.indexOf('\\Windows\\System32') >= 0);
check('limitation text shown verbatim', h1cap.indexOf(LIMITATION) >= 0);
check('limitation label present', h1cap.indexOf('\u80fd\u529b\u9650\u5236\uff08\u539f\u6587\uff09') >= 0);
check('coverage shown', h1cap.indexOf('sample_and_its_directory') >= 0);
check('copy_scope shown', h1cap.indexOf('same_directory_files(dll/config/resource)') >= 0);
// single backslashes here: this is the literal source text, which is what the
// page must emit (the report value is JS-escaped in this file, not HTML-escaped)
check('exec_path shown', h1cap.indexOf('sandbox_1791012408980\\notepad.exe') >= 0);
check('copied_files shown', h1cap.indexOf('1 \u4e2a') >= 0);
check('copied_bytes 200704 -> 196.0 KB', h1cap.indexOf('196.0 KB') >= 0);
check('truncated=true warned', h1cap.indexOf('\u88ab\u622a\u65ad') >= 0);
check('engine_notes section rendered', h1cap.indexOf('\u5f15\u64ce\u81ea\u8ff0') >= 0);
check('engine_note content rendered', h1cap.indexOf(NOTE1) >= 0);
check('capacity caps rendered', h1cap.indexOf('256.0 MB') >= 0 && h1cap.indexOf('512 \u4e2a\u6587\u4ef6') >= 0);
check('registry_redirect false -> not supported', h1cap.indexOf('\u6ce8\u518c\u8868\u91cd\u5b9a\u5411</span><span><span class="cap-bad">\u4e0d\u652f\u6301') >= 0);
check('file_copy true -> supported', h1cap.indexOf('\u6587\u4ef6\u590d\u5236\u9694\u79bb</span><span><span class="cap-ok">\u652f\u6301') >= 0);

console.log('\n=== scenario 2: memory_scan.ok === true (hits incl. low confidence) ===');
const h2mem = R.renderMemoryScan(repMemoryHit.memory_scan);
const h2cap = R.renderCapabilities(repMemoryHit.isolation);

check('ok:true panel rendered', h2mem.length > 0);
check('ok:true shows module counts 35/35', h2mem.indexOf('35/35') >= 0);
check('ok:true shows scanned bytes 44.3 MB', h2mem.indexOf('44.3 MB') >= 0);
check('ok:true shows elapsed 3548 ms', h2mem.indexOf('3548 ms') >= 0);
check('ok:true shows hit count 3', h2mem.indexOf('\u547d\u4e2d 3 \u6761') >= 0);
check('ok:true shows PID', h2mem.indexOf('PID 2284') >= 0);
check('ok:true shows interpretation', h2mem.indexOf(INTERP_HIT) >= 0);
check('hit rule names rendered', h2mem.indexOf('RULE_HIGH') >= 0 && h2mem.indexOf('RULE_MED') >= 0);
check('confidence tags rendered', h2mem.indexOf('cred-tag high') >= 0 && h2mem.indexOf('cred-tag medium') >= 0);
check('low confidence visually weakened', h2mem.indexOf('cred-low') >= 0);
check('hit source module rendered', h2mem.indexOf('notepad.exe') >= 0 && h2mem.indexOf('shell32.dll') >= 0);
check('quality_reason surfaced for low hit', h2mem.indexOf('effective-literal-4-bytes') >= 0);
check('skipped modules disclosed', h2mem.indexOf('kernel32.dll') >= 0);
check('not marked uncovered when ok:true', h2mem.indexOf('mem-panel uncovered') < 0);
check('truncated=false -> no truncation warning', h2mem.indexOf('\u672a\u626b\u5168') < 0);
check('downgrade (requested none -> copy) surfaced', h2cap.indexOf('\u5df2\u964d\u7ea7') >= 0);
check('engine: copy shown once', h2cap.indexOf('engine: copy') >= 0);
check('engine_notes list has 2 items', (h2cap.match(/<li>/g) || []).length === 2);
check('truncated=false -> no caps truncation warning', h2cap.indexOf('\u88ab\u622a\u65ad') < 0);

console.log('\n=== scenario 3: missing fields must not fabricate a verdict ===');
check('no capabilities -> panel hidden', R.renderCapabilities({ engine: 'none', capabilities: null }) === '');
check('no memory_scan -> panel hidden', R.renderMemoryScan(null) === '');
check('undefined memory_scan -> panel hidden', R.renderMemoryScan(undefined) === '');
check('empty object memory_scan -> treated as uncovered, not safe',
    R.renderMemoryScan({}).indexOf('mem-panel uncovered') >= 0);
check('memory_scan ok:false with no error still warns',
    R.renderMemoryScan({ ok: false }).indexOf('\u672a\u8bf4\u660e\u539f\u56e0') >= 0);

console.log('\n=== scenario 4: report-level verdict mapping ===');
// drive the real render path; the stub captures what would be written to the DOM
const box = byId('verdictBox');
R.renderReport({ verdict: 'unknown', score: 0, isolation: repUncovered.isolation, memory_scan: repUncovered.memory_scan });
check('verdict unknown -> NOT safe', box.innerHTML.indexOf('\u5b89\u5168') < 0, 'got: ' + box.innerHTML.slice(0, 120));
check('verdict unknown -> labelled 未知', box.innerHTML.indexOf('\u672a\u77e5\uff08\u672a\u80fd\u5206\u6790\uff09') >= 0);
check('renderReport writes isolation degraded reason', byId('isolationBox').innerHTML.indexOf('err=5') >= 0);
check('renderReport marks panel degraded class', byId('isolationBox').className.indexOf('degraded') >= 0);
check('renderReport writes capabilities panel', byId('capBox').innerHTML.indexOf(LIMITATION) >= 0);
check('renderReport shows firewall rule not cleaned', byId('isolationBox').innerHTML.indexOf('\u89c4\u5219\u672a\u6e05\u7406') >= 0);
check('renderReport writes memory panel', byId('memoryScanBox').innerHTML.indexOf(REASON) >= 0);

R.renderReport({ verdict: 'clean', score: 3, isolation: repMemoryHit.isolation, memory_scan: repMemoryHit.memory_scan });
check('verdict clean -> safe', byId('verdictBox').innerHTML.indexOf('\u5b89\u5168') >= 0);
check('clean report still shows capabilities limitation', byId('capBox').innerHTML.indexOf(LIMITATION) >= 0);
check('clean report still shows memory hits', byId('memoryScanBox').innerHTML.indexOf('RULE_HIGH') >= 0);
check('clean report no degraded class', byId('isolationBox').className.indexOf('degraded') < 0);

R.renderReport({ verdict: 'clean', score: 1 });
check('report without isolation -> capability panel hidden', byId('capBox').style.display === 'none');
check('report without memory_scan -> memory panel hidden', byId('memoryScanBox').style.display === 'none');

console.log('\n=== helpers ===');
check('fmtBytes(0)', R.fmtBytes(0) === '0 B');
check('fmtBytes(200704)', R.fmtBytes(200704) === '196.0 KB');
check('fmtBytes(46399488)', R.fmtBytes(46399488) === '44.3 MB');
check('memHitCred weak -> low', R.memHitCred({ confidence: 'weak' }) === 'low');
check('memHitCred missing -> medium', R.memHitCred({}) === 'medium');
check('memHitModule falls back to _source', R.memHitModule({ _source: 'memory' }) === 'memory');

console.log('\n=== XSS guard: report content is escaped on the way into innerHTML ===');
const x = R.renderCapabilities({
    engine: '<img src=x onerror=alert(1)>',
    capabilities: { file_copy: true, absolute_path_redirect: false, limitation: '<script>alert(1)</script>', coverage: 'x' },
    engine_notes: ['<b>bold</b>']
});
check('engine name escaped', x.indexOf('<img src=x') < 0 && x.indexOf('&lt;img') >= 0);
check('limitation escaped', x.indexOf('<script>') < 0);
check('engine_notes escaped', x.indexOf('<b>bold</b>') < 0);

console.log('\n---------------------------------------------');
console.log('PASS ' + pass + '   FAIL ' + fail);
if (fail) { console.log('failed:'); failures.forEach(f => console.log('  - ' + f)); process.exit(1); }
console.log('all branch assertions OK');
