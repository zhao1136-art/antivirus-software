/*!
 * 安盾 前端公共模块（组件化复用）
 * 通过 /static/common.js 引入。所有页面共用的 API 封装与格式化工具。
 * 约定：
 *   - 动态适配当前 origin：API_BASE 一律为 ''，禁止硬编码 127.0.0.1/端口。
 *   - 若页面已自行定义同名函数，则以页面为准（以 window 守卫避免覆盖）。
 */
(function () {
  'use strict';

  var BASE = '';

  function apiGet(path) {
    return fetch(BASE + path).then(function (r) { return r.json(); })
      .catch(function (e) { console.warn('API 不可用:', e && e.message); return null; });
  }

  function apiPost(path, body, method) {
    return fetch(BASE + path, {
      method: method || 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) { return r.json(); })
      .catch(function (e) { console.warn('API 不可用:', e && e.message); return null; });
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    var div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  function formatTime(dateStr) {
    if (!dateStr) return '-';
    try {
      var d = new Date(dateStr);
      return d.toLocaleString('zh-CN', {
        month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
      });
    } catch (e) { return String(dateStr); }
  }

  function truncateHash(hash, keep) {
    if (!hash) return '-';
    var n = keep || 20;
    return hash.length > n ? hash.substring(0, n - 4) + '...' : hash;
  }

  // 浅合并：仅在页面未定义时挂到全局，避免覆盖页面已有实现
  var exports = { apiGet: apiGet, apiPost: apiPost, escapeHtml: escapeHtml, formatTime: formatTime, truncateHash: truncateHash };
  var target = window.YutianCS || (window.YutianCS = {});
  Object.keys(exports).forEach(function (k) {
    if (target[k] === undefined) target[k] = exports[k];
  });
})();