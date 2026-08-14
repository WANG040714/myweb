// Cloudflare Pages _worker.js —— WQQ 网站访问 IP 记录器 + 留言板 API
// 功能：
// 1. 每次访问记录真实 IP + 时间 + 页面 + 浏览器 + 城市/运营商到 KV
// 2. 统计页 /__stats?key=xxx
// 3. 留言板 API：GET/POST /api/guestbook（KV 存储，带 IP 限流）
// 4. 访问统计 API：GET /api/stats
// 城市定位使用 ip-api.com 免费接口（45 次/分钟限速），结果按 IP 缓存 30 天。
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const STATS_KEY = env.STATS_KEY || 'wqq2026';

    // 统计页：/__stats?key=xxx
    if (url.pathname === '/__stats') {
      if (url.searchParams.get('key') !== STATS_KEY) {
        return new Response('403 Forbidden', { status: 403 });
      }
      return handleStats(env);
    }

    // 留言板 API
    if (url.pathname === '/api/guestbook') {
      if (request.method === 'POST') return handleGuestbookPost(request, env);
      if (request.method === 'GET') return handleGuestbookGet(env);
      return new Response('Method Not Allowed', { status: 405 });
    }

    // 访问统计 API（页面页脚展示用）
    if (url.pathname === '/api/stats') {
      return handleStatsApi(env);
    }

    // 记录访问（waitUntil 保证写入在响应后完成；只记录文档请求，跳过静态资源和 API）
    const isAsset = /\.(css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|map|txt)$/i.test(url.pathname);
    if (!isAsset && !url.pathname.startsWith('/api/') && request.method === 'GET') {
      ctx.waitUntil(recordVisit(request, env, url).catch(() => {}));
    }

    // 正常返回静态页面
    return env.ASSETS.fetch(request);
  },
};

// ---------- 访问记录 ----------

// 查询 IP 城市信息（带 KV 缓存，避免每次访问都打第三方接口）
async function getGeo(env, ip) {
  if (!ip || ip === '-') return null;
  try {
    const cached = await env.VISITS.get('geo:' + ip);
    if (cached) return JSON.parse(cached);
  } catch (e) {}
  try {
    const resp = await fetch(
      'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,country,regionName,city,isp,query&lang=zh-CN',
      { headers: { 'User-Agent': 'wqq-site' } }
    );
    const data = await resp.json();
    if (data && data.status === 'success') {
      const geo = { city: data.city || null, region: data.regionName || null, isp: data.isp || null };
      // 缓存 30 天
      await env.VISITS.put('geo:' + ip, JSON.stringify(geo), { expirationTtl: 2592000 }).catch(() => {});
      return geo;
    }
  } catch (e) {}
  return null;
}

async function recordVisit(request, env, url) {
  const ip = request.headers.get('CF-Connecting-IP') || '-';
  const country = request.headers.get('CF-IPCountry') || '-';
  const ua = (request.headers.get('User-Agent') || '-').slice(0, 200);
  const path = url.pathname;
  const t = Date.now();
  const geo = await getGeo(env, ip);
  // key 唯一：时间戳 + IP + 随机串
  const key = `v:${t}:${ip}:${Math.random().toString(36).slice(2, 8)}`;
  await env.VISITS.put(
    key,
    JSON.stringify({
      ip,
      country,
      city: geo ? geo.city : null,
      region: geo ? geo.region : null,
      isp: geo ? geo.isp : null,
      path,
      ua,
      t,
    })
  );
}

// ---------- 留言板 ----------

// 读取最近 100 条留言（倒序）
async function handleGuestbookGet(env) {
  const msgs = [];
  try {
    const list = await env.VISITS.list({ prefix: 'g:', limit: 200 });
    for (const k of list.keys) {
      const v = await env.VISITS.get(k.name);
      if (v) msgs.push(JSON.parse(v));
    }
  } catch (e) {
    return json({ ok: false, error: '读取留言失败' }, 500);
  }
  msgs.sort((a, b) => b.t - a.t);
  return json({ ok: true, messages: msgs.slice(0, 100) });
}

// 提交留言（带简单限流：每 IP 每 60 秒最多 1 条）
async function handleGuestbookPost(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, error: '请求格式错误' }, 400);
  }

  const name = String(body.name || '').trim().slice(0, 20);
  const text = String(body.text || '').trim().slice(0, 300);

  if (!name) return json({ ok: false, error: '请填写昵称' }, 400);
  if (!text) return json({ ok: false, error: '请填写留言内容' }, 400);

  // IP 限流：60 秒内同 IP 最多 1 条
  const rateKey = 'rl:' + ip;
  const last = await env.VISITS.get(rateKey);
  const now = Date.now();
  if (last && now - parseInt(last, 10) < 60000) {
    const waitSec = Math.ceil((60000 - (now - parseInt(last, 10))) / 1000);
    return json({ ok: false, error: `操作太频繁，请 ${waitSec} 秒后再试` }, 429);
  }
  await env.VISITS.put(rateKey, String(now), { expirationTtl: 120 });

  const key = `g:${now}:${ip}:${Math.random().toString(36).slice(2, 8)}`;
  await env.VISITS.put(key, JSON.stringify({ name, text, t: now, ip }));
  return json({ ok: true, message: '留言成功' });
}

// ---------- 访问统计 API ----------

async function handleStatsApi(env) {
  try {
    const list = await env.VISITS.list({ prefix: 'v:', limit: 1000 });
    const ips = new Set();
    let total = 0;
    for (const k of list.keys) {
      const v = await env.VISITS.get(k.name);
      if (v) {
        total++;
        try { ips.add(JSON.parse(v).ip); } catch (e) {}
      }
    }
    return json({ ok: true, total, uniqIps: ips.size });
  } catch (e) {
    return json({ ok: false, error: '统计失败' }, 500);
  }
}

// ---------- 统计页 ----------

async function handleStats(env) {
  const rows = [];
  try {
    const list = await env.VISITS.list({ limit: 1000 });
    for (const k of list.keys) {
      if (!k.name.startsWith('v:')) continue; // 跳过 geo 缓存键
      const v = await env.VISITS.get(k.name);
      if (v) rows.push(JSON.parse(v));
    }
  } catch (e) {
    return new Response('统计读取失败：' + e.message, { status: 500 });
  }
  rows.sort((a, b) => b.t - a.t);

  // 汇总统计
  const uniqIps = new Set(rows.map((r) => r.ip));
  const byDay = {};
  const byPath = {};
  const byCountry = {};
  const byCity = {};
  for (const r of rows) {
    const d = new Date(r.t).toISOString().slice(0, 10);
    byDay[d] = (byDay[d] || 0) + 1;
    byPath[r.path] = (byPath[r.path] || 0) + 1;
    byCountry[r.country] = (byCountry[r.country] || 0) + 1;
    const city = r.city || (r.country === 'CN' ? '中国(未知城市)' : r.country);
    byCity[city] = (byCity[city] || 0) + 1;
  }

  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const fmtLoc = (r) => {
    const parts = [];
    if (r.city) parts.push(r.city);
    if (r.region && r.region !== r.city) parts.push(r.region);
    if (r.country && r.country !== '-') parts.push(r.country);
    const main = parts.length ? esc(parts.join('，')) : esc(r.country || '-');
    const sub = r.isp ? `<div class="isp">${esc(r.isp)}</div>` : '';
    return main + sub;
  };

  // 把 {key: count} 转成标签块
  const kvItems = (obj, limit) =>
    Object.entries(obj)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([k, c]) => `<span class="item">${esc(k)}<b>${c}</b></span>`)
      .join('');
  const dayItems = (o) => kvItems(o, 10);
  const pathItems = (o) => kvItems(o, 8);
  const countryItems = (o) => kvItems(o, 8);
  const cityItems = (o) => kvItems(o, 10);

  const trs = rows
    .slice(0, 300)
    .map(
      (r) =>
        `<tr><td class="ip">${esc(r.ip)}</td><td class="time">${new Date(r.t).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</td><td class="path">${esc(r.path)}</td><td class="loc">${fmtLoc(r)}</td><td class="ua" title="${esc(r.ua)}">${esc(r.ua)}</td></tr>`
    )
    .join('');

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WQQ 网站访问统计</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "PingFang SC", "Microsoft YaHei", "Helvetica Neue", sans-serif;
    margin: 0; padding: 0;
    background: linear-gradient(165deg, #eaf2fb 0%, #dcebf8 45%, #cfe3f4 100%);
    min-height: 100vh;
    color: #1d2d3d;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 32px 18px 60px; }
  header { text-align: center; margin-bottom: 26px; }
  h1 {
    font-size: 28px; font-weight: 800; margin: 0 0 6px; letter-spacing: -0.5px;
    background: linear-gradient(120deg, #2f6fa8, #4a90d9 55%, #7ab8ec);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }
  .sub { font-size: 13px; color: #5a7a99; }

  .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 22px 0; }
  .card {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px; padding: 20px 22px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
  }
  .card .num { font-size: 34px; font-weight: 800; color: #2f6fa8; letter-spacing: -1px; }
  .card .lbl { font-size: 13px; color: #5a7a99; margin-top: 6px; }

  .cols { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin: 16px 0 26px; }
  .panel {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px; padding: 18px 20px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
  }
  .panel h2 { font-size: 15px; font-weight: 700; margin: 0 0 12px; color: #1d2d3d; }
  .kv { display: flex; flex-wrap: wrap; gap: 6px; }
  .kv .item {
    font-size: 12px; line-height: 1;
    background: #e8f1fa; color: #3a5a78;
    border-radius: 8px; padding: 8px 10px;
  }
  .kv .item b { color: #2f6fa8; font-weight: 700; margin-left: 4px; }

  .table-title { font-size: 17px; font-weight: 700; margin: 0 0 12px; color: #1d2d3d; }
  .table-wrap {
    background: rgba(255,255,255,0.72);
    border: 1px solid rgba(255,255,255,0.9);
    border-radius: 16px;
    box-shadow: 0 4px 20px rgba(47,111,168,0.10);
    overflow: hidden;
  }
  .table-scroll { overflow-x: auto; max-height: 62vh; overflow-y: auto; }
  table {
    width: 100%; border-collapse: collapse; table-layout: fixed;
    font-size: 12px; min-width: 820px;
  }
  col.ip { width: 15%; }
  col.time { width: 17%; }
  col.path { width: 11%; }
  col.loc { width: 17%; }
  col.ua { width: 40%; }
  thead th {
    position: sticky; top: 0; z-index: 2;
    background: #f2f7fc;
    color: #33506e; font-weight: 700;
    text-align: left; padding: 11px 12px;
    border-bottom: 1px solid #dce8f3;
    font-size: 12px; white-space: nowrap;
  }
  tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid #eef3f8;
    vertical-align: middle;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  td.ip { font-family: "SF Mono", Consolas, Menlo, monospace; font-size: 11.5px; color: #3a5a78; }
  td.time { color: #5a7a99; font-variant-numeric: tabular-nums; }
  td.path { color: #2f6fa8; font-weight: 600; }
  td.loc { color: #33475b; }
  td.loc .isp { color: #8aa3ba; font-size: 11px; margin-top: 2px; }
  td.ua { color: #6b8299; cursor: help; }
  tbody tr:hover td { background: #eaf3fc; }
  tbody tr:last-child td { border-bottom: none; }
  .empty { text-align: center; color: #8aa3ba; padding: 40px 0 !important; white-space: normal !important; }

  @media (max-width: 820px) {
    .cards { grid-template-columns: 1fr; }
    .cols { grid-template-columns: 1fr; }
    h1 { font-size: 23px; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>📊 WQQ 网站访问统计</h1>
    <div class="sub">数据实时记录 · 每小时自动更新</div>
  </header>
  <div class="cards">
    <div class="card"><div class="num">${rows.length}</div><div class="lbl">记录总数（近 1000 条）</div></div>
    <div class="card"><div class="num">${uniqIps.size}</div><div class="lbl">独立 IP</div></div>
    <div class="card"><div class="num">${Object.keys(byDay).length > 0 ? Object.values(byDay).reduce((a, b) => a + b, 0) : 0}</div><div class="lbl">总访问次数</div></div>
  </div>
  <div class="cols">
    <div class="panel"><h2>📅 按天</h2><div class="kv">${dayItems(byDay) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
    <div class="panel"><h2>🧭 访问页面</h2><div class="kv">${pathItems(byPath) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
    <div class="panel"><h2>🌍 国家/地区</h2><div class="kv">${countryItems(byCountry) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
    <div class="panel"><h2>📍 城市 TOP</h2><div class="kv">${cityItems(byCity) || '<span style="color:#8aa3ba;font-size:12px">暂无</span>'}</div></div>
  </div>
  <div class="table-title">🕒 最近访问明细（最新 300 条）</div>
  <div class="table-wrap">
    <div class="table-scroll">
      <table>
        <colgroup>
          <col class="ip"><col class="time"><col class="path"><col class="loc"><col class="ua">
        </colgroup>
        <thead><tr><th>IP</th><th>时间（北京时间）</th><th>页面</th><th>位置 / 运营商</th><th>User-Agent（悬停查看完整）</th></tr></thead>
        <tbody>${trs || '<tr><td class="empty" colspan="5">还没有记录</td></tr>'}</tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>`;

  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ---------- 工具 ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
