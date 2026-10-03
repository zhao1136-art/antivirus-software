/*
 * VERIFICATION HARNESS (not part of the app; safe to delete).
 * Syntax gate: extract every inline <script> block from the given HTML pages and
 * syntax-check each one with node's own parser (new Function).
 * Usage: node _frontend_syntax_check.js <page.html> [...]
 */
'use strict';
const fs = require('fs');
const path = require('path');

const files = process.argv.slice(2);
if (!files.length) { console.error('usage: node _frontend_syntax_check.js <page.html>...'); process.exit(2); }

let bad = 0;
for (const f of files) {
    const p = path.resolve(f);
    const html = fs.readFileSync(p, 'utf8');
    const blocks = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
    let ok = 0, broken = 0;
    blocks.forEach((code, idx) => {
        if (!code.trim()) return;
        try {
            new Function(code);            // throws SyntaxError on bad syntax
            ok++;
        } catch (e) {
            broken++;
            console.log('SYNTAX FAIL ' + path.basename(p) + ' block#' + (idx + 1) + ': ' + e.message);
        }
    });
    console.log(path.basename(p) + ': inline blocks ok=' + ok + ' broken=' + broken +
        ' (total blocks ' + blocks.length + ')');
    if (broken) bad++;
}
console.log(bad ? 'RESULT: FAIL' : 'RESULT: PASS');
process.exit(bad ? 1 : 0);
