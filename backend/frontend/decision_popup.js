/*!
 * 威胁处置弹窗 —— 右下角倒计时卡片
 *
 * 2026-10-03：原先"YARA 命中即自动隔离"把 42 个 Windows 系统文件搬走了。
 * 现在后端把命中挂起为待决项（/api/v1/threats/pending），由用户决定；
 * 15 秒内没有决定，后端按默认动作自动处理。这个脚本负责把那 15 秒
 * 摆到用户眼前：右下角卡片 + 倒计时 + 「立即隔离 / 忽略」。
 *
 * 系统目录的文件已在后端被二次复核拦下，不会出现在这里。
 *
 * 两条实现纪律（都栽过跟头）：
 *   1) 绝不用 document.hidden 跳过轮询 —— 早先加过，结果标签页不在前台
 *      时弹窗根本不出现，而 15 秒后后端照常隔离，用户只看到"文件没了"。
 *   2) 请求失败不再静默 —— 连续失败要在控制台留痕，否则无从查起。
 *
 * 纯原生 JS，无依赖。通过 <script src="/static/decision_popup.js"> 引入。
 */
(function () {
  'use strict';

  var API = '/api/v1/threats';
  var POLL_MS = 1000;
  var NS = 'ytdp';          // 类名前缀，避免和页面样式打架

  var box = null;
  var styleDone = false;
  var cards = {};           // id -> card 状态对象
  var pollFails = 0;

  /* ── 样式：一次性注入，避免和 16 个页面各自的 CSS 变量纠缠 ── */
  function injectStyle() {
    if (styleDone || document.getElementById(NS + '-style')) return;
    var css = [
      '.' + NS + '-box{position:fixed;right:18px;bottom:18px;z-index:2147483000;',
      'display:flex;flex-direction:column-reverse;gap:12px;max-width:392px;pointer-events:none;',
      "font-family:'Segoe UI','Microsoft YaHei',system-ui,-apple-system,sans-serif}",

      '.' + NS + '-card{pointer-events:auto;position:relative;overflow:hidden;',
      'background:linear-gradient(160deg,#1e2530 0%,#171c24 100%);color:#e6e9ee;',
      'border:1px solid rgba(255,255,255,.09);border-radius:14px;padding:15px 16px 14px;',
      'box-shadow:0 12px 34px rgba(0,0,0,.5),0 2px 6px rgba(0,0,0,.35);',
      'animation:' + NS + '-in .28s cubic-bezier(.22,1,.36,1)}',
      '@keyframes ' + NS + '-in{from{opacity:0;transform:translateX(24px) scale(.97)}',
      'to{opacity:1;transform:none}}',
      '.' + NS + '-card.' + NS + '-out{animation:' + NS + '-out .22s ease forwards}',
      '@keyframes ' + NS + '-out{to{opacity:0;transform:translateX(24px) scale(.97)}}',
      /* 左侧色带随剩余时间变色 */
      '.' + NS + '-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;',
      'background:var(--ytdp-accent,#e5534b);transition:background .3s}',

      '.' + NS + '-head{display:flex;align-items:flex-start;gap:10px}',
      '.' + NS + '-badge{flex:0 0 auto;width:30px;height:30px;border-radius:9px;display:flex;',
      'align-items:center;justify-content:center;font-size:16px;line-height:1;',
      'background:var(--ytdp-badge,rgba(229,83,75,.16));color:var(--ytdp-accent,#e5534b)}',
      '.' + NS + '-title{flex:1;min-width:0}',
      '.' + NS + '-name{font-size:13.5px;font-weight:600;letter-spacing:.1px;',
      'white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.' + NS + '-sub{font-size:11.5px;color:#8b95a3;margin-top:2px;',
      'white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.' + NS + '-close{flex:0 0 auto;width:22px;height:22px;border:0;background:transparent;',
      'color:#6b7684;font-size:17px;line-height:1;cursor:pointer;border-radius:6px;padding:0}',
      '.' + NS + '-close:hover{background:rgba(255,255,255,.08);color:#c9d1d9}',

      '.' + NS + '-path{margin:11px 0 9px;font:11px/1.5 Consolas,"Cascadia Mono",monospace;',
      'color:#9aa5b1;background:rgba(0,0,0,.26);border-radius:8px;padding:7px 9px;',
      'word-break:break-all;max-height:46px;overflow:hidden}',

      '.' + NS + '-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:11px}',
      '.' + NS + '-chip{font-size:11px;padding:2px 8px;border-radius:20px;',
      'background:rgba(255,255,255,.07);color:#a9b4c0}',
      '.' + NS + '-chip.' + NS + '-hi{background:rgba(229,83,75,.16);color:#ff8b83}',
      '.' + NS + '-chip.' + NS + '-md{background:rgba(210,153,34,.16);color:#e2b04a}',

      '.' + NS + '-bar{height:5px;border-radius:4px;background:rgba(255,255,255,.08);',
      'overflow:hidden;margin-bottom:11px}',
      '.' + NS + '-bar>i{display:block;height:100%;width:100%;border-radius:4px;',
      'background:var(--ytdp-accent,#e5534b);transition:width .2s linear,background .3s}',

      '.' + NS + '-foot{display:flex;align-items:center;gap:9px}',
      '.' + NS + '-left{flex:1;font-size:11.5px;color:#8b95a3;font-variant-numeric:tabular-nums}',
      '.' + NS + '-left b{color:var(--ytdp-accent,#e5534b);font-weight:600}',
      '.' + NS + '-btn{border:0;border-radius:9px;padding:7px 14px;font:inherit;font-size:12.5px;',
      'cursor:pointer;transition:filter .15s,background .15s;white-space:nowrap}',
      '.' + NS + '-btn:hover{filter:brightness(1.18)}',
      '.' + NS + '-btn-q{background:linear-gradient(180deg,#c8453c,#a8342d);color:#fff;font-weight:600}',
      '.' + NS + '-btn-i{background:rgba(255,255,255,.08);color:#c9d1d9}',
      '.' + NS + '-done{font-size:12.5px;padding:6px 0;font-weight:600}'
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
              action === 'quarantine' ? '#e5534b' : '#5aa9e6');
      } else {
        flash(id, '已自动处理', '#8b95a3');   // 超时后后端已处理
      }
    }).catch(function () {
      flash(id, '提交失败，请重试', '#e5534b');
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

  function makeCard(item) {
    var el = document.createElement('div');
    el.className = NS + '-card';

    var head = document.createElement('div');
    head.className = NS + '-head';
    head.innerHTML =
      '<div class="' + NS + '-badge">&#9888;</div>' +
      '<div class="' + NS + '-title">' +
        '<div class="' + NS + '-name" title="' + esc(item.threat_name) + '">' + esc(item.threat_name) + '</div>' +
        '<div class="' + NS + '-sub">需要你决定</div>' +
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
      var accent = pct < 34 ? '#e5534b' : (pct < 67 ? '#d29922' : '#3fb950');
      el.style.setProperty('--ytdp-accent', accent);
      el.style.setProperty('--ytdp-badge', 'rgba(255,255,255,.07)');
      fill.style.width = pct + '%';
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
    // 纪律 1：这里绝不能因为 document.hidden 就跳过轮询。
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
          if (!alive[id] && !cards[id].done) flash(id, '已自动处理', '#8b95a3');
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
