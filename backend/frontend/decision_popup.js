/*!
 * 威胁处置弹窗 —— 右下角倒计时
 *
 * 2026-10-03：原先"YARA 命中即自动隔离"把 42 个 Windows 系统文件搬走了。
 * 现在后端把命中挂起为待决项（/api/v1/threats/pending），由用户决定；
 * 15 秒内没有决定，后端会按默认动作自动处理。这个脚本负责把那 15 秒
 * 摆到用户眼前 —— 右下角弹窗 + 倒计时 + 「立即隔离 / 忽略」。
 *
 * 系统目录的文件已经在后端被二次复核拦下，不会出现在这里。
 *
 * 纯原生 JS，无依赖。通过 <script src="/static/decision_popup.js"> 引入。
 */
(function () {
  'use strict';

  var API = '/api/v1/threats';
  var POLL_MS = 1000;

  var box = null;
  var cards = {};      // id -> {el, deadline, timer, bar, num}

  function ensureBox() {
    if (box && document.body.contains(box)) return box;
    box = document.createElement('div');
    box.id = 'ytDecideBox';
    box.setAttribute('role', 'region');
    box.setAttribute('aria-label', '威胁处置');
    box.style.cssText = [
      'position:fixed', 'right:18px', 'bottom:18px', 'z-index:2147483000',
      'display:flex', 'flex-direction:column-reverse', 'gap:10px',
      'max-width:380px', 'pointer-events:none'
    ].join(';');
    document.body.appendChild(box);
    return box;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function decide(id, action) {
    var c = cards[id];
    if (c) { c.done = true; }
    fetch(API + '/' + encodeURIComponent(id) + '/decide', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action })
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res && res.ok) {
        flash(id, action === 'quarantine' ? '已隔离' : '已忽略', action === 'quarantine' ? '#f0a020' : '#5aa9e6');
      } else {
        // 超时后后端已自动处理，或该项已消失
        flash(id, '已自动处理', '#8b95a3');
      }
    }).catch(function () {
      flash(id, '请求失败', '#e5534b');
    });
  }

  function flash(id, text, color) {
    var c = cards[id];
    if (!c) return;
    if (c.timer) { clearInterval(c.timer); c.timer = null; }
    c.body.innerHTML = '<div style="color:' + color + ';font-size:13px;padding:4px 0">' + esc(text) + '</div>';
    setTimeout(function () { remove(id); }, 1200);
  }

  function remove(id) {
    var c = cards[id];
    if (!c) return;
    if (c.timer) clearInterval(c.timer);
    if (c.el && c.el.parentNode) c.el.parentNode.removeChild(c.el);
    delete cards[id];
  }

  function makeCard(item) {
    var el = document.createElement('div');
    el.style.cssText = [
      'pointer-events:auto', 'background:#1b2027', 'color:#e6e9ee',
      'border:1px solid #2c343f', 'border-left:4px solid #d29922',
      'border-radius:10px', 'padding:12px 14px', 'box-shadow:0 8px 28px rgba(0,0,0,.45)',
      'font:13px/1.5 "Segoe UI","Microsoft YaHei",sans-serif', 'position:relative'
    ].join(';');

    var head = document.createElement('div');
    head.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px';
    head.innerHTML =
      '<span style="font-size:15px">&#9888;</span>' +
      '<b style="flex:1;font-size:13.5px" title="' + esc(item.threat_name) + '">' +
      esc(item.threat_name) + '</b>' +
      '<span style="cursor:pointer;color:#8b95a3;font-size:16px;line-height:1" title="关闭（不决定，等超时自动处理）">&#215;</span>';
    head.lastChild.onclick = function () { remove(item.id); };

    var file = document.createElement('div');
    file.style.cssText = 'color:#8b95a3;font-size:11.5px;word-break:break-all;margin-bottom:4px';
    file.textContent = item.path;

    var meta = document.createElement('div');
    meta.style.cssText = 'color:#8b95a3;font-size:11.5px;margin-bottom:10px';
    meta.textContent = '规则 ' + (item.rule || '—') + ' · 等级 ' + (item.threat_level || '—');

    var bar = document.createElement('div');
    bar.style.cssText = 'height:4px;background:#222932;border-radius:3px;overflow:hidden;margin-bottom:8px';
    var fill = document.createElement('i');
    fill.style.cssText = 'display:block;height:100%;width:100%;background:#d29922';
    bar.appendChild(fill);

    var row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:8px';
    var num = document.createElement('span');
    num.style.cssText = 'color:#d29922;font-size:12px;flex:1';
    var bQ = document.createElement('button');
    bQ.textContent = '立即隔离';
    bQ.style.cssText = 'cursor:pointer;border:0;border-radius:7px;padding:6px 12px;background:#12325c;color:#9dc4ff;font:inherit;font-size:12.5px';
    var bI = document.createElement('button');
    bI.textContent = '忽略';
    bI.style.cssText = 'cursor:pointer;border:1px solid #2c343f;border-radius:7px;padding:6px 12px;background:transparent;color:#c9d1d9;font:inherit;font-size:12.5px';
    bQ.onclick = function () { decide(item.id, 'quarantine'); };
    bI.onclick = function () { decide(item.id, 'ignore'); };
    row.appendChild(num); row.appendChild(bQ); row.appendChild(bI);

    var body = document.createElement('div');
    body.appendChild(file);
    body.appendChild(meta);
    body.appendChild(bar);
    body.appendChild(row);

    el.appendChild(head);
    el.appendChild(body);

    // 倒计时：用后端给的 deadline（epoch 秒）本地推进，不依赖轮询频率
    var deadline = (item.deadline || 0) * 1000;
    var total = (item.timeout || 15) * 1000;
    function tickLocal() {
      var left = deadline - Date.now();
      if (left < 0) left = 0;
      var pct = total > 0 ? Math.max(0, Math.min(100, left / total * 100)) : 0;
      fill.style.width = pct + '%';
      fill.style.background = pct < 33 ? '#e5534b' : (pct < 66 ? '#d29922' : '#3fb950');
      num.textContent = Math.ceil(left / 1000) + ' 秒后自动隔离';
      if (left <= 0 && !cards[item.id].done) {
        num.textContent = '正在自动处理…';
      }
    }
    tickLocal();
    var timer = setInterval(tickLocal, 200);

    return { el: el, body: body, timer: timer, deadline: deadline, done: false };
  }

  function upsert(item) {
    var c = cards[item.id];
    if (c) {
      // 已存在：更新文件名/规则等可能变化的信息，不动倒计时
      c.deadline = (item.deadline || 0) * 1000;
      return;
    }
    var card = makeCard(item);
    cards[item.id] = card;
    ensureBox().appendChild(card.el);
  }

  var pollFails = 0;

  function poll() {
    // 注意：这里**不能**因为 document.hidden 就跳过轮询。
    // 早先加过 `if (document.hidden) return;`，结果是：标签页不在前台时
    // 弹窗根本不出现，而 15 秒一到后端照常自动隔离 —— 用户看到的就是
    // "没弹窗，文件却没了"。威胁处置比"别打扰"重要。
    fetch(API + '/pending', { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      })
      .then(function (d) {
        pollFails = 0;
        var list = (d && d.pending) || [];
        var alive = {};
        list.forEach(function (it) { alive[it.id] = 1; upsert(it); });
        // 后端已处理的（含超时自动处理）要把卡片收掉
        Object.keys(cards).forEach(function (id) {
          if (!alive[id] && !cards[id].done) flash(id, '已自动处理', '#8b95a3');
        });
      })
      .catch(function (e) {
        // 不再静默：连续失败要在控制台留痕，否则出问题无从查起
        pollFails++;
        if (pollFails === 1 || pollFails % 20 === 0) {
          try { console.warn('[威胁弹窗] 轮询失败 ' + pollFails + ' 次:', e && e.message); } catch (_) {}
        }
      });
  }

  function boot() {
    if (!document.body) { setTimeout(boot, 50); return; }
    poll();
    setInterval(poll, POLL_MS);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  window.YutianThreatPopup = { poll: poll, decide: decide };
})();
