// 临时 Mock 服务器：仅用于验证 engine.html 页面功能（验证后删除）
// 用法: node _mock_engine_test.js
const http = require('http');
const fs = require('fs');
const path = require('path');

const HTML = fs.readFileSync(path.join(__dirname, 'frontend', 'engine.html'), 'utf8');
const PORT = 8899;

const modules = {
    file_shield: true, network_shield: true, behavior_shield: true,
    ransomware_shield: true, process_guard: true, file_guard: true
};
let etwRunning = false;
let amsiRegistered = false;
let vigilRunning = false;
let tasks = {};
let taskSeq = 0;

function now(offsetMin = 0) {
    const d = new Date(Date.now() - offsetMin * 60000);
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function json(res, obj, code = 200) {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    console.log('[' + new Date().toISOString() + '] ' + req.method + ' ' + p);

    if (req.method === 'GET' && /\.html$/.test(p)) {
        // 动态读取前端页面，便于实时验证
        const file = path.join(FRONTEND, path.basename(p));
        if (fs.existsSync(file)) {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(fs.readFileSync(file, 'utf8'));
            return;
        }
    }
    if (req.method === 'GET' && p === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8'));
        return;
    }
    if (req.method === 'GET' && p === '/api/v1/protection/status') {
        return json(res, { modules, realtime_enabled: Object.values(modules).some(Boolean) });
    }
    if (req.method === 'POST' && p === '/api/v1/protection/toggle') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            try {
                const b = JSON.parse(body);
                modules[b.module] = !!b.enabled;
                return json(res, { module: b.module, enabled: modules[b.module] });
            } catch (e) { return json(res, { error: 'bad json' }, 400); }
        });
        return;
    }
    if (req.method === 'GET' && p === '/api/v1/stats/overview') {
        return json(res, {
            total_scanned: 128473, today_blocked: 3, total_threats: 57,
            protection_days: 42, guard_days: 42, signatures_count: 1863342,
            c2_ip_count: 12, c2_domain_count: 8
        });
    }
    if (req.method === 'GET' && p === '/api/v1/stats/activity') {
        return json(res, {
            threats: [
                { timestamp: now(2), name: 'Trojan.GenericKD.5948321', file: 'C:\\Users\\test\\AppData\\Local\\Temp\\svch0st.exe' },
                { timestamp: now(18), name: 'Adware.BrowserHelper', file: 'C:\\Program Files (x86)\\dhefwe\\uninst.exe' },
                { timestamp: now(41), name: 'HackTool.Mimikatz', file: 'C:\\Users\\test\\Downloads\\mimi.exe' }
            ],
            scans: [
                { timestamp: now(5), event: 'scan_complete', type: 'quick', stats: { files_scanned: 3421, threats_found: 1 } },
                { timestamp: now(75), event: 'scan_start', type: 'quick' },
                { timestamp: now(130), event: 'scan_complete', type: 'full', stats: { files_scanned: 98213, threats_found: 2 } }
            ]
        });
    }
    if (req.method === 'POST' && /^\/api\/v1\/scan\/(quick|full)$/.test(p)) {
        taskSeq++;
        const id = 'task_mock_' + taskSeq;
        const scope = p.split('/').pop();
        tasks[id] = { status: 'running', progress: 0, current_file: '正在初始化...', scope };
        return json(res, { task_id: id });
    }
    if (req.method === 'GET' && p === '/api/v1/ai/status') {
        return json(res, { available: true, engine: 'GuardianCNN v1.0', loaded: true, img_size: 128, params: '622,690' });
    }
    if (req.method === 'GET' && p === '/api/v1/vigil/status') {
        return json(res, { running: vigilRunning, port: 7331 });
    }
    if (req.method === 'POST' && p === '/api/v1/vigil/start') {
        vigilRunning = true;
        return json(res, { status: 'started', url: 'http://127.0.0.1:7331' });
    }
    if (req.method === 'GET' && p === '/api/v1/etw/status') {
        return json(res, { running: etwRunning });
    }
    if (req.method === 'POST' && (p === '/api/v1/etw/start' || p === '/api/v1/etw/stop')) {
        etwRunning = p.endsWith('/start');
        return json(res, { success: true, running: etwRunning });
    }
    if (req.method === 'GET' && p === '/api/v1/amsi/status') {
        return json(res, { registered: amsiRegistered, enabled: true });
    }
    if (req.method === 'POST' && (p === '/api/v1/amsi/register' || p === '/api/v1/amsi/unregister')) {
        amsiRegistered = p.endsWith('/register');
        return json(res, { success: true, registered: amsiRegistered });
    }
    if (req.method === 'GET' && p === '/api/v1/cloud/andun/status') {
        return json(res, { ok: true, available: true, url: 'http://47.93.118.106' });
    }
    if (req.method === 'GET' && p === '/api/v1/cloud/andun/verify') {
        return json(res, { ok: true, status: { available: true } });
    }
    const scanStatus = p.match(/^\/api\/v1\/scan\/(.+)\/status$/);
    if (req.method === 'GET' && scanStatus) {
        const t = tasks[scanStatus[1]];
        if (!t) return json(res, { status: 'failed', error: 'task not found' });
        if (t.status === 'running') {
            t.progress += 14;
            t.current_file = '扫描 ' + t.scope + ' · 文件 ' + (t.progress * 37) + '.exe';
            if (t.progress >= 100) {
                t.status = 'completed';
                return json(res, { status: 'completed', result: { files_scanned: t.scope === 'quick' ? 3421 : 98213, threats_found: t.scope === 'quick' ? 1 : 2 } });
            }
            return json(res, { status: 'running', progress: t.progress, current_file: t.current_file });
        }
        return json(res, { status: t.status, result: t.result || {} });
    }
    return json(res, { error: 'not found', path: p }, 404);
});

server.listen(PORT, '127.0.0.1', () => {
    console.log('Mock server listening on http://127.0.0.1:' + PORT);
});
