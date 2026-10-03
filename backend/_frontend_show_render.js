/*
 * VERIFICATION HARNESS (not part of the app; safe to delete).
 * Prints the rendered HTML of the two new sandbox.html panels for both branches
 * so the markup can be eyeballed. No backend needed.
 * Usage: node _frontend_show_render.js
 */
'use strict';
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'frontend', 'sandbox.html'), 'utf8');
const mainScript = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)]
    .map(m => m[1]).find(s => s.indexOf('function renderMemoryScan') >= 0);

function el(id) {
    return { id, innerHTML: '', textContent: '', style: {}, dataset: {}, className: '',
        classList: { _s: new Set(), add() {}, remove() {}, toggle() {}, contains() { return false; } },
        addEventListener() {}, appendChild() {}, querySelector() { return el('q'); }, setAttribute() {}, closest() { return null; } };
}
const m = new Map();
const byId = id => { if (!m.has(id)) m.set(id, el(id)); return m.get(id); };
const R = new Function('document', 'window', 'localStorage', 'fetch', 'console', 'setInterval', 'setTimeout', 'clearInterval', 'clearTimeout', 'alert',
    mainScript + '\nreturn {renderMemoryScan:renderMemoryScan, renderCapabilities:renderCapabilities};')(
    { getElementById: byId, querySelector: () => el('q'), querySelectorAll: () => [], createElement: () => el('n'), addEventListener() {}, documentElement: el('h'), body: el('b') },
    { addEventListener() {}, scrollTo() {} }, { getItem: () => null, setItem() {} },
    () => Promise.resolve({ json: () => Promise.resolve(null) }),
    { log() {}, warn() {}, error() {} }, () => 0, () => 0, () => {}, () => {}, () => {});

// shapes taken from the task description (real backend output)
const UNCOVERED = { ok: false, error: '\u8fdb\u7a0b\u5df2\u81ea\u884c\u9000\u51fa\uff0c\u65e0\u6cd5\u626b\u63cf\u5185\u5b58', interpretation: '\u672a\u8986\u76d6\u5185\u5b58' };
const HIT = {
    ok: true, error: '', pid: 2284, modules_total: 35, modules_read: 35,
    scanned_bytes: 46399488, truncated: false, skipped: [], elapsed_ms: 3548.4,
    interpretation: '\u78c1\u76d8\u672a\u547d\u4e2d\u4f46\u5185\u5b58\u547d\u4e2d \u2014\u2014 \u9ad8\u5ea6\u6000\u7591\u52a0\u58f3\u6216\u6ce8\u5165',
    hits: [{ rule: 'Win32_Packed_Section', confidence: 'high', _module: 'notepad.exe', _source: 'memory' },
           { rule: 'Generic_Inject_Stub', confidence: 'low', _module: 'ntdll.dll' }]
};
const ISO = {
    engine: 'copy', engine_requested: 'copy',
    capabilities: {
        file_copy: true, absolute_path_redirect: false, registry_redirect: false,
        writable_sandbox: true, coverage: 'sample_and_its_directory',
        limitation: '\u6837\u672c\u5f15\u7528\u7684\u7edd\u5bf9\u8def\u5f84\u4e0d\u4f1a\u88ab\u91cd\u5b9a\u5411\uff1b\u771f CoW \u9700\u8981\u5185\u6838\u9a71\u52a8\u6216 ProjFS',
        copy_scope: 'sample + same_directory_files(dll/config/resource)',
        max_total_bytes: 268435456, max_files: 512, max_single_file_bytes: 67108864, truncated_capable: true
    },
    exec_path: 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\yutian_sandbox\\sandbox_1791012408980\\notepad.exe',
    copied_files: 1, copied_bytes: 200704, truncated: false,
    engine_notes: ['\u6837\u672c\u76ee\u5f55\u4f4d\u4e8e\u7cfb\u7edf\u76ee\u5f55\u6811\u4e0b\uff08C:\\Windows\uff09\uff0c\u8df3\u8fc7\u540c\u76ee\u5f55\u6279\u91cf\u590d\u5236']
};

function pretty(h) {
    // break into readable lines without changing semantics (display only)
    return h.replace(/></g, '>\n<');
}

console.log('=========== A) memory_scan ok:false (uncovered) ===========');
console.log(pretty(R.renderMemoryScan(UNCOVERED)));
console.log('\n=========== B) memory_scan ok:true (hits) ===========');
console.log(pretty(R.renderMemoryScan(HIT)));
console.log('\n=========== C) isolation.capabilities (engine: copy, apr=false) ===========');
console.log(pretty(R.renderCapabilities(ISO)));
