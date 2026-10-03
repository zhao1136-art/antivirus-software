/*!
 * 威胁处置弹窗 —— 右下角倒计时卡片（视觉风格参考火绒：近黑卡片 + 红色主导 + 大号粗体标题）
 *
 * 2026-10-03：原先"YARA 命中即自动隔离"把 42 个 Windows 系统文件搬走了。
 * 现在后端把命中挂起为待决项（/api/v1/threats/pending），由用户决定；
 * 15 秒内没有决定，后端按默认动作自动处理。这个脚本负责把那 15 秒
 * 摆到用户眼前：右下角卡片 + 倒计时 + 「立即隔离 / 忽略」。
 *
 * 系统目录的文件已在后端被二次复核拦下，不会出现在这里。
 *
 * 两条实现纪律（都栽过跟头，别再改回去）：
 *   1) 绝不用 document.hidden 跳过轮询 —— 加过，结果标签页不在前台时弹窗
 *      根本不出现，而 15 秒后后端照常隔离，用户只看到"文件没了"。
 *   2) 请求失败不静默 —— 连续失败在控制台留痕，否则无从查起。
 *
 * 纯原生 JS，无依赖。通过 <script src="/static/decision_popup.js"> 引入。
 */
(function () {
  'use strict';

  var API = '/api/v1/threats';
  var POLL_MS = 1000;
  var NS = 'ytdp';

  var box = null;
  var styleDone = false;
  var cards = {};
  var pollFails = 0;

  // 火绒式配色：近黑底 + 警示红 + 克制的灰阶
  var C = {
    bg1: '#1b1b1d', bg2: '#131315',
    line: 'rgba(255,255,255,.08)',
    text: '#f2f3f5', dim: '#8d9199',
    red: '#e0483c', redDark: '#b8352b',
    blue: '#2f81f7'
  };

  function injectStyle() {
    if (styleDone || document.getElementById(NS + '-style')) return;
    var css = [
      '.' + NS + '-box{position:fixed;right:18px;bottom:18px;z-index:2147483000;',
      'display:flex;flex-direction:column-reverse;gap:12px;width:368px;max-width:calc(100vw - 36px);',
      'pointer-events:none;font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif;',
      '-webkit-font-smoothing:antialiased}',

      /* 卡片：近黑渐变 + 顶部红色警示条 */
      '.' + NS + '-card{pointer-events:auto;position:relative;overflow:hidden;',
      'background:linear-gradient(180deg,' + C.bg1 + ' 0%,' + C.bg2 + ' 100%);color:' + C.text + ';',
      'border:1px solid ' + C.line + ';border-radius:12px;padding:16px 18px 15px;',
      'box-shadow:0 14px 40px rgba(0,0,0,.62),0 2px 8px rgba(0,0,0,.4);',
      'animation:' + NS + '-in .3s cubic-bezier(.22,1,.36,1)}',
      '.' + NS + '-card::before{content:"";position:absolute;left:0;right:0;top:0;height:3px;',
      'background:linear-gradient(90deg,' + C.red + ',' + C.redDark + ')}',
      '@keyframes ' + NS + '-in{from{opacity:0;transform:translateY(14px) scale(.98)}to{opacity:1;transform:none}}',
      '.' + NS + '-card.' + NS + '-out{animation:' + NS + '-out .22s ease forwards}',
      '@keyframes ' + NS + '-out{to{opacity:0;transform:translateY(10px) scale(.98)}}',

      /* 头部：大号粗体「发现威胁」+ 威胁名 */
      '.' + NS + '-head{display:flex;align-items:center;gap:11px;margin-bottom:13px}',
      '.' + NS + '-badge{flex:0 0 auto;width:34px;height:34px;border-radius:9px;',
      'display:flex;align-items:center;justify-content:center;',
      'background:linear-gradient(180deg,' + C.red + ',' + C.redDark + ');',
      'box-shadow:0 4px 12px rgba(224,72,60,.34)}',
      '.' + NS + '-badge svg{width:19px;height:19px;display:block}',
      '.' + NS + '-htext{flex:1;min-width:0}',
      '.' + NS + '-big{font-size:15px;font-weight:700;letter-spacing:.2px;line-height:1.25}',
      '.' + NS + '-name{font-size:12.5px;color:' + C.dim + ';margin-top:2px;',
      'white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.' + NS + '-close{flex:0 0 auto;width:24px;height:24px;border:0;background:transparent;',
      'color:#63666d;font-size:18px;line-height:1;cursor:pointer;border-radius:6px;padding:0}',
      '.' + NS + '-close:hover{background:rgba(255,255,255,.08);color:' + C.text + '}',

      /* 文件路径：等宽、深底 */
      '.' + NS + '-path{font:11px/1.5 Consolas,"Cascadia Mono",monospace;color:#9aa0aa;',
      'background:rgba(0,0,0,.34);border:1px solid rgba(255,255,255,.05);border-radius:8px;',
      'padding:8px 10px;word-break:break-all;max-height:47px;overflow:hidden;margin-bottom:11px}',

      '.' + NS + '-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}',
      '.' + NS + '-chip{font-size:11px;padding:2px 9px;border-radius:4px;',
      'background:rgba(255,255,255,.07);color:#a9aeb6}',
      '.' + NS + '-chip.' + NS + '-hi{background:rgba(224,72,60,.18);color:#ff8d84}',
      '.' + NS + '-chip.' + NS + '-md{background:rgba(214,152,44,.18);color:#e5b455}',

      /* 倒计时条：红->橙->绿 反过来用（剩余越多越红，越少越亮） */
      '.' + NS + '-bar{height:4px;border-radius:3px;background:rgba(255,255,255,.07);',
      'overflow:hidden;margin-bottom:12px}',
      '.' + NS + '-bar>i{display:block;height:100%;width:100%;background:' + C.red + ';',
      'transition:width .2s linear,background .3s}',

      '.' + NS + '-foot{display:flex;align-items:center;gap:9px}',
      '.' + NS + '-left{flex:1;font-size:12px;color:' + C.dim + ';font-variant-numeric:tabular-nums}',
      '.' + NS + '-left b{color:' + C.red + ';font-weight:700;font-size:13px}',
      '.' + NS + '-btn{border:0;border-radius:8px;padding:8px 16px;font:inherit;font-size:12.5px;',
      'cursor:pointer;transition:background .15s,filter .15s;white-space:nowrap}',
      '.' + NS + '-btn-q{background:' + C.red + ';color:#fff;font-weight:600}',
      '.' + NS + '-btn-q:hover{background:#ef5a4e}',
      '.' + NS + '-btn-i{background:rgba(255,255,255,.09);color:#c9ccd2}',
      '.' + NS + '-btn-i:hover{background:rgba(255,255,255,.15)}',
      '.' + NS + '-done{font-size:12.5px;padding:5px 0;font-weight:600}'
    ].join('');
    var el = document.createElement('style');
    el.id = NS + '-style';
    el.textContent = css;
    (document.head || document.documentElement).appendChild(el);
    styleDone = true;
  }

  function ensureBox() {
    if (box && document.body.contains(box)) return box;
    injectStyle();
    box = document.createElement('div');
    box.id = NS + 'Box';
    box.className = NS + '-box';
    box.setAttribute('role', 'region');
    box.setAttribute('aria-label', '威胁处置');
    document.body.appendChild(box);
    return box;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function levelClass(lv) {
    lv = String(lv || '').toLowerCase();
    if (lv === 'high' || lv === 'malicious') return NS + '-hi';
    if (lv === 'medium' || lv === 'suspicious') return NS + '-md';
    return '';
  }

  function levelText(lv) {
    var m = { high: '高危', medium: '中危', low: '低危', malicious: '恶意', suspicious: '可疑' };
    return m[String(lv || '').toLowerCase()] || (lv || '未知');
  }

  function decide(id, action) {
    var c = cards[id];
    if (!c || c.done) return;
    c.done = true;
    fetch(API + '/' + encodeURIComponent(id) + '/decide', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action })
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res && res.ok) {
        flash(id, action === 'quarantine' ? '已隔离' : '已忽略',
              action === 'quarantine' ? C.red : C.blue);
      } else {
        flash(id, '已自动处理', C.dim);   // 超时后后端已处理
      }
    }).catch(function () {
      flash(id, '提交失败，请重试', C.red);
      var c2 = cards[id]; if (c2) c2.done = false;
    });
  }

  function flash(id, text, color) {
    var c = cards[id];
    if (!c) return;
    if (c.timer) { clearInterval(c.timer); c.timer = null; }
    c.body.innerHTML = '<div class="' + NS + '-done" style="color:' + color + '">' + esc(text) + '</div>';
    setTimeout(function () { remove(id); }, 1100);
  }

  function remove(id) {
    var c = cards[id];
    if (!c) return;
    if (c.timer) clearInterval(c.timer);
    if (c.el && c.el.parentNode) {
      c.el.className += ' ' + NS + '-out';
      var el = c.el;
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 220);
    }
    delete cards[id];
  }

  var SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" ' +
    'stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5l7.5 3.5v5.5c0 4.6-3.2 7.9-7.5 9.5' +
    '-4.3-1.6-7.5-4.9-7.5-9.5V6z"/><path d="M12 8.6v4.2"/><circle cx="12" cy="16.2" r="1.05" fill="#fff" stroke="none"/></svg>';

  function makeCard(item) {
    var el = document.createElement('div');
    el.className = NS + '-card';

    var head = document.createElement('div');
    head.className = NS + '-head';
    head.innerHTML =
      '<div class="' + NS + '-badge">' + SHIELD + '</div>' +
      '<div class="' + NS + '-htext">' +
        '<div class="' + NS + '-big">发现威胁</div>' +
        '<div class="' + NS + '-name" title="' + esc(item.threat_name) + '">' + esc(item.threat_name) + '</div>' +
      '</div>' +
      '<button class="' + NS + '-close" title="关闭（不做决定，等超时自动处理）">&#215;</button>';
    head.querySelector('.' + NS + '-close').onclick = function () { remove(item.id); };

    var body = document.createElement('div');
    body.innerHTML =
      '<div class="' + NS + '-path" title="' + esc(item.path) + '">' + esc(item.path) + '</div>' +
      '<div class="' + NS + '-chips">' +
        '<span class="' + NS + '-chip ' + levelClass(item.threat_level) + '">' + esc(levelText(item.threat_level)) + '</span>' +
        (item.rule ? '<span class="' + NS + '-chip">规则 ' + esc(item.rule) + '</span>' : '') +
        '<span class="' + NS + '-chip">YARA</span>' +
      '</div>' +
      '<div class="' + NS + '-bar"><i></i></div>' +
      '<div class="' + NS + '-foot">' +
        '<span class="' + NS + '-left"></span>' +
        '<button class="' + NS + '-btn ' + NS + '-btn-i">忽略</button>' +
        '<button class="' + NS + '-btn ' + NS + '-btn-q">立即隔离</button>' +
      '</div>';

    var fill = body.querySelector('.' + NS + '-bar>i');
    var left = body.querySelector('.' + NS + '-left');
    var btns = body.querySelectorAll('.' + NS + '-btn');
    btns[0].onclick = function () { decide(item.id, 'ignore'); };
    btns[1].onclick = function () { decide(item.id, 'quarantine'); };

    el.appendChild(head);
    el.appendChild(body);

    // 倒计时用后端给的 deadline 本地推进，不依赖轮询频率
    var deadline = (item.deadline || 0) * 1000;
    var total = (item.timeout || 15) * 1000;

    function tickLocal() {
      var ms = deadline - Date.now();
      if (ms < 0) ms = 0;
      var pct = total > 0 ? Math.max(0, Math.min(100, ms / total * 100)) : 0;
      var accent = pct < 34 ? '#ff6b5e' : (pct < 67 ? '#e0483c' : '#c0392f');
      fill.style.width = pct + '%';
      fill.style.background = accent;
      var secs = Math.ceil(ms / 1000);
      left.innerHTML = secs > 0
        ? '<b>' + secs + '</b> 秒后自动隔离'
        : '正在自动处理…';
    }
    tickLocal();
    var timer = setInterval(tickLocal, 200);

    return { el: el, body: body, timer: timer, deadline: deadline, done: false };
  }

  function upsert(item) {
    var c = cards[item.id];
    if (c) { c.deadline = (item.deadline || 0) * 1000; return; }
    var card = makeCard(item);
    cards[item.id] = card;
    ensureBox().appendChild(card.el);
  }

  function poll() {
    // 纪律 1：不能因为 document.hidden 跳过轮询。
    fetch(API + '/pending', { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (d) {
        pollFails = 0;
        var list = (d && d.pending) || [];
        var alive = {};
        list.forEach(function (it) { alive[it.id] = 1; upsert(it); });
        Object.keys(cards).forEach(function (id) {
          if (!alive[id] && !cards[id].done) flash(id, '已自动处理', C.dim);
        });
      })
      .catch(function (e) {
        // 纪律 2：失败不静默
        pollFails++;
        if (pollFails === 1 || pollFails % 20 === 0) {
          try { console.warn('[威胁弹窗] 轮询失败 ' + pollFails + ' 次:', e && e.message); } catch (_) {}
        }
      });
  }

  function boot() {
    if (!document.body) { setTimeout(boot, 50); return; }
    injectStyle();
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
